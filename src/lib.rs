//! Fernet provides symmetric-authenticated-encryption with an API that makes
//! misusing it difficult. It is based on a public specification and there are
//! interoperable implementations in Rust, Python, Ruby, Go, and Clojure.

//! # Example
//! ```rust
//! // Store `key` somewhere safe!
//! let key = fernet::Fernet::generate_key();
//! let fernet = fernet::Fernet::new(&key).unwrap();
//! let plaintext = b"my top secret message!";
//! let ciphertext = fernet.encrypt(plaintext);
//! let decrypted_plaintext = fernet.decrypt(&ciphertext);
//! assert_eq!(decrypted_plaintext.unwrap(), plaintext);
// ```

#[cfg(test)]
#[macro_use]
extern crate serde_derive;

extern crate base64;
extern crate byteorder;
extern crate openssl;
extern crate rand;

use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};
use std::time;
use rand::RngCore;

const MAX_CLOCK_SKEW: u64 = 60;

pub struct Fernet {
    encryption_key: [u8; 16],
    signing_key: [u8; 16],
}

/// This error is returned when fernet cannot decrypt the ciphertext for any
/// reason.
#[derive(Debug, PartialEq, Eq)]
pub struct DecryptionError;

pub struct MultiFernet {
    fernets: Vec<Fernet>,
}

/// `MultiFernet` encapsulates the encrypt operation with the first `Fernet`
/// instance and decryption with  the `Fernet` instances provided in order
/// until successful decryption or a `DecryptionError`.
impl MultiFernet {
    pub fn new(keys: Vec<Fernet>) -> MultiFernet {
        assert!(keys.len() > 0);
        MultiFernet { fernets: keys }
    }

    /// Encrypts data with the first `Fernet` instance. Returns a value
    /// (which is base64-encoded) that can be passed to `MultiFernet::decrypt`.
    pub fn encrypt(&self, data: &[u8]) -> String {
        self.fernets[0].encrypt(data)
    }

    /// Decrypts a ciphertext, using the `Fernet` instances provided. Returns
    /// either `Ok(plaintext)` if decryption is successful or
    /// `Err(DecryptionError)` if there are any errors.
    pub fn decrypt(&self, token: &str) -> Result<Vec<u8>, DecryptionError> {
        for fernet in self.fernets.iter() {
            let res = fernet.decrypt(token);
            if res.is_ok() {
                return res;
            }
        }

        return Err(DecryptionError);
    }
}

/// `Fernet` encapsulates encrypt and decrypt operations for a particular key.
impl Fernet {
    /// Returns a new fernet instance with the provided key. The key should be
    /// 32-bytes, base64-encoded. Generating keys with `Fernet::generate_key`
    /// is recommended. DO NOT USE A HUMAN READABLE PASSWORD AS A KEY. Returns
    /// `None` if the key is not 32-bytes base64 encoded.
    pub fn new(key: &str) -> Option<Fernet> {
        let key = base64::decode_config(key, base64::URL_SAFE).ok()?;
        if key.len() != 32 {
            return None;
        }

        let mut signing_key: [u8; 16] = Default::default();
        signing_key.copy_from_slice(&key[..16]);
        let mut encryption_key: [u8; 16] = Default::default();
        encryption_key.copy_from_slice(&key[16..]);

        Some(Fernet {
            signing_key,
            encryption_key,
        })
    }

    /// Generates a new, random, key. Can be safely passed to `Fernet::new()`.
    /// Store this somewhere safe!
    pub fn generate_key() -> String {
        let mut key: [u8; 32] = Default::default();
        rand::OsRng::new().unwrap().fill(&mut key);
        return base64::encode_config(&key, base64::URL_SAFE);
    }

    /// Encrypts data. Returns a value (which is base64-encoded) that can be
    /// passed to `Fernet::decrypt`.
    pub fn encrypt(&self, data: &[u8]) -> String {
        let current_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut iv: [u8; 16] = Default::default();
        rand::OsRng::new().unwrap().fill(&mut iv);
        return self._encrypt_from_parts(data, current_time, &iv);
    }

    fn _encrypt_from_parts(&self, data: &[u8], current_time: u64, iv: &[u8]) -> String {
        let ciphertext = openssl::symm::encrypt(
            openssl::symm::Cipher::aes_128_cbc(),
            &self.encryption_key,
            Some(iv),
            data,
        ).unwrap();

        let mut result = Vec::new();
        result.push(0x80);
        result
            .write_u64::<byteorder::BigEndian>(current_time)
            .unwrap();
        result.extend_from_slice(iv);
        result.extend_from_slice(&ciphertext);

        let hmac_pkey = openssl::pkey::PKey::hmac(&self.signing_key).unwrap();
        let mut hmac_signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &hmac_pkey).unwrap();
        hmac_signer.update(&result).unwrap();

        result.extend_from_slice(&hmac_signer.sign_to_vec().unwrap());

        return base64::encode_config(&result, base64::URL_SAFE);
    }

    /// Decrypts a ciphertext. Returns either `Ok(plaintext)` if decryption is
    /// successful or `Err(DecryptionError)` if there are any errors.
    pub fn decrypt(&self, token: &str) -> Result<Vec<u8>, DecryptionError> {
        let current_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        return self._decrypt_at_time(token, None, current_time);
    }

    // TODO: add decrypt_with_ttl()

    fn _decrypt_at_time(
        &self,
        token: &str,
        ttl: Option<u64>,
        current_time: u64,
    ) -> Result<Vec<u8>, DecryptionError> {
        let data = match base64::decode_config(token, base64::URL_SAFE) {
            Ok(data) => data,
            Err(_) => return Err(DecryptionError),
        };

        let mut input = Cursor::new(data);

        match input.read_u8() {
            Ok(0x80) => {}
            _ => return Err(DecryptionError),
        }

        let timestamp = input
            .read_u64::<byteorder::BigEndian>()
            .map_err(|_| DecryptionError)?;

        if let Some(ttl) = ttl {
            if timestamp + ttl < current_time {
                return Err(DecryptionError);
            }
        }

        if current_time + MAX_CLOCK_SKEW < timestamp {
            return Err(DecryptionError);
        }

        let mut iv = vec![0; 16];
        input.read_exact(&mut iv).map_err(|_| DecryptionError)?;

        let mut rest = vec![];
        input.read_to_end(&mut rest).unwrap();
        if rest.len() < 32 {
            return Err(DecryptionError);
        }
        let ciphertext = &rest[..rest.len() - 32];
        let hmac = &rest[rest.len() - 32..];

        let hmac_pkey = openssl::pkey::PKey::hmac(&self.signing_key).unwrap();
        let mut hmac_signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &hmac_pkey).unwrap();
        hmac_signer
            .update(&input.get_ref()[..input.get_ref().len() - 32])
            .unwrap();
        let expected_hmac = hmac_signer.sign_to_vec().unwrap();
        if !openssl::memcmp::eq(&expected_hmac, hmac) {
            return Err(DecryptionError);
        }

        let plaintext = openssl::symm::decrypt(
            openssl::symm::Cipher::aes_128_cbc(),
            &self.encryption_key,
            Some(&iv),
            ciphertext,
        ).map_err(|_| DecryptionError)?;

        return Ok(plaintext);
    }
}

#[cfg(test)]
mod tests {
    extern crate base64;
    extern crate chrono;
    extern crate serde_json;

    use std::collections::HashSet;
    use super::{DecryptionError, Fernet, MultiFernet};

    #[derive(Deserialize)]
    struct GenerateVector<'a> {
        token: &'a str,
        now: &'a str,
        iv: Vec<u8>,
        src: &'a str,
        secret: &'a str,
    }

    #[derive(Deserialize)]
    struct VerifyVector<'a> {
        token: &'a str,
        now: &'a str,
        ttl_sec: u64,
        src: &'a str,
        secret: &'a str,
    }

    #[derive(Deserialize, Debug)]
    struct InvalidVector<'a> {
        token: &'a str,
        now: &'a str,
        ttl_sec: u64,
        secret: &'a str,
    }

    #[test]
    fn test_generate_vectors() {
        let vectors: Vec<GenerateVector> =
            serde_json::from_str(include_str!("../tests/generate.json")).unwrap();

        for v in vectors {
            let f = Fernet::new(v.secret).unwrap();
            let token = f._encrypt_from_parts(
                v.src.as_bytes(),
                chrono::DateTime::parse_from_rfc3339(v.now)
                    .unwrap()
                    .timestamp() as u64,
                &v.iv,
            );
            assert_eq!(token, v.token);
        }
    }

    #[test]
    fn test_verify_vectors() {
        let vectors: Vec<VerifyVector> =
            serde_json::from_str(include_str!("../tests/verify.json")).unwrap();

        for v in vectors {
            let f = Fernet::new(v.secret).unwrap();
            let decrypted = f._decrypt_at_time(
                v.token,
                Some(v.ttl_sec),
                chrono::DateTime::parse_from_rfc3339(v.now)
                    .unwrap()
                    .timestamp() as u64,
            );
            assert_eq!(decrypted, Ok(v.src.as_bytes().to_vec()));
        }
    }

    #[test]
    fn test_invalid_vectors() {
        let vectors: Vec<InvalidVector> =
            serde_json::from_str(include_str!("../tests/invalid.json")).unwrap();

        for v in vectors {
            let f = Fernet::new(v.secret).unwrap();
            let decrypted = f._decrypt_at_time(
                v.token,
                Some(v.ttl_sec),
                chrono::DateTime::parse_from_rfc3339(v.now)
                    .unwrap()
                    .timestamp() as u64,
            );
            assert_eq!(decrypted, Err(DecryptionError));
        }
    }

    #[test]
    fn test_invalid() {
        let f = Fernet::new(&base64::encode_config(&vec![0; 32], base64::URL_SAFE)).unwrap();

        // Invalid version byte
        assert_eq!(
            f.decrypt(&base64::encode_config(b"\x81", base64::URL_SAFE)),
            Err(DecryptionError)
        );
        // Timestamp too short
        assert_eq!(
            f.decrypt(&base64::encode_config(
                b"\x80\x00\x00\x00",
                base64::URL_SAFE
            )),
            Err(DecryptionError)
        );
        // Invalid base64
        assert_eq!(f.decrypt("\x00"), Err(DecryptionError));
    }

    #[test]
    fn test_roundtrips() {
        let f = Fernet::new(&base64::encode_config(&vec![0; 32], base64::URL_SAFE)).unwrap();

        for val in [b"".to_vec(), b"Abc".to_vec(), b"\x00\xFF\x00\x00".to_vec()].into_iter() {
            assert_eq!(f.decrypt(&f.encrypt(&val)), Ok(val.clone()));
        }
    }

    #[test]
    fn test_new_errors() {
        assert!(Fernet::new("axxx").is_none());
        assert!(Fernet::new(&base64::encode_config(&vec![0, 33], base64::URL_SAFE)).is_none());
        assert!(Fernet::new(&base64::encode_config(&vec![0, 31], base64::URL_SAFE)).is_none());
    }

    #[test]
    fn test_generate_key() {
        let mut keys = HashSet::new();
        for _ in 0..1024 {
            keys.insert(Fernet::generate_key());
        }
        assert_eq!(keys.len(), 1024);
    }

    #[test]
    fn test_generate_key_roundtrips() {
        let k = Fernet::generate_key();
        let f1 = Fernet::new(&k).unwrap();
        let f2 = Fernet::new(&k).unwrap();

        for val in [b"".to_vec(), b"Abc".to_vec(), b"\x00\xFF\x00\x00".to_vec()].into_iter() {
            assert_eq!(f1.decrypt(&f2.encrypt(&val)), Ok(val.clone()));
            assert_eq!(f2.decrypt(&f1.encrypt(&val)), Ok(val.clone()));
        }
    }

    #[test]
    fn test_multi_encrypt() {
        let key1 = Fernet::generate_key();
        let key2 = Fernet::generate_key();
        let f1 = Fernet::new(&key1).unwrap();
        let f2 = Fernet::new(&key2).unwrap();
        let f = MultiFernet::new(vec![
            Fernet::new(&key1).unwrap(),
            Fernet::new(&key2).unwrap(),
        ]);
        assert_eq!(f1.decrypt(&f.encrypt(b"abc")).unwrap(), b"abc".to_vec());
        assert_eq!(f2.decrypt(&f.encrypt(b"abc")), Err(DecryptionError));
    }

    #[test]
    fn test_multi_decrypt() {
        let key1 = Fernet::generate_key();
        let key2 = Fernet::generate_key();
        let f1 = Fernet::new(&key1).unwrap();
        let f2 = Fernet::new(&key2).unwrap();
        let f = MultiFernet::new(vec![
            Fernet::new(&key1).unwrap(),
            Fernet::new(&key2).unwrap(),
        ]);
        assert_eq!(f.decrypt(&f1.encrypt(b"abc")).unwrap(), b"abc".to_vec());
        assert_eq!(f.decrypt(&f2.encrypt(b"abc")).unwrap(), b"abc".to_vec());
        assert_eq!(f.decrypt("\x00"), Err(DecryptionError));
    }

    #[test]
    #[should_panic]
    fn test_multi_no_fernets() {
        MultiFernet::new(vec![]);
    }

    #[test]
    fn test_multi_roundtrips() {
        let f = MultiFernet::new(vec![Fernet::new(&Fernet::generate_key()).unwrap()]);

        for val in [b"".to_vec(), b"Abc".to_vec(), b"\x00\xFF\x00\x00".to_vec()].into_iter() {
            assert_eq!(f.decrypt(&f.encrypt(&val)), Ok(val.clone()));
        }
    }
}
