#![deny(warnings)]

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

use byteorder::ReadBytesExt;
use std::error::Error;
use std::fmt::{self, Display};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::time;
use zeroize::Zeroize;
use base64::Engine;

#[cfg(feature = "rustcrypto")]
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
#[cfg(feature = "rustcrypto")]
use hmac::Mac;
#[cfg(feature = "rustcrypto")]
use sha2::Sha256;

#[cfg(not(any(feature = "rustcrypto", feature = "openssl",)))]
compile_error!(
    "no crypto cargo feature enabled! \
     please enable one of: default, openssl"
);

const MAX_CLOCK_SKEW: u64 = 60;

// Automatically zero out the contents of the memory when the struct is drop'd.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Fernet {
    encryption_key: [u8; 16],
    signing_key: [u8; 16],
}

/// This error is returned when fernet cannot decrypt the ciphertext for any
/// reason. It could be an expired token, incorrect key or other failure. If
/// you recieve this error, you should consider the fernet token provided as
/// invalid.
#[derive(Debug, PartialEq, Eq)]
pub struct DecryptionError;

impl Error for DecryptionError {}

impl Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fernet decryption error")
    }
}

#[derive(Clone)]
pub struct MultiFernet {
    fernets: Vec<Fernet>,
}

/// `MultiFernet` encapsulates the encrypt operation with the first `Fernet`
/// instance and decryption with  the `Fernet` instances provided in order
/// until successful decryption or a `DecryptionError`.
impl MultiFernet {
    pub fn new(keys: Vec<Fernet>) -> MultiFernet {
        assert!(!keys.is_empty(), "keys must not be empty");
        MultiFernet { fernets: keys }
    }

    /// Encrypts data with the first `Fernet` instance. Returns a value
    /// (which is base64-encoded) that can be passed to `MultiFernet::decrypt`.
    pub fn encrypt(&self, data: &[u8]) -> String {
        self.fernets[0].encrypt(data)
    }

    /// Decrypts a ciphertext, using the `Fernet` instances provided. Returns
    /// either `Ok(plaintext)` if decryption is successful or
    /// `Err(DecryptionError)` if no decryption was possible across the set of
    /// fernet keys.
    pub fn decrypt(&self, token: &str) -> Result<Vec<u8>, DecryptionError> {
        for fernet in self.fernets.iter() {
            let res = fernet.decrypt(token);
            if res.is_ok() {
                return res;
            }
        }

        Err(DecryptionError)
    }
}

/// Token split into parts before decryption.
struct ParsedToken {
    /// message is the whole token except for the HMAC
    message: Vec<u8>,
    /// 128 bit IV
    iv: [u8; 16],
    /// Ciphertext (part of message)
    ciphertext: Vec<u8>,
    /// 256 bit HMAC
    hmac: [u8; 32],
}

/// `Fernet` encapsulates encrypt and decrypt operations for a particular symmetric key.
impl Fernet {
    /// Returns a new fernet instance with the provided key. The key should be
    /// 32-bytes, url-safe base64-encoded. Generating keys with `Fernet::generate_key`
    /// is recommended. DO NOT USE A HUMAN READABLE PASSWORD AS A KEY. Returns
    /// `None` if the key is not 32-bytes base64 encoded.
    pub fn new(key: &str) -> Option<Fernet> {
        let key = b64_decode_url(key).ok()?;
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
        getrandom::getrandom(&mut key).expect("Error in getrandom");
        crate::b64_encode_url(&key.to_vec())
    }

    /// Encrypts data into a token. Returns a value (which is base64-encoded) that can be
    /// passed to `Fernet::decrypt` for decryption and verification..
    pub fn encrypt(&self, data: &[u8]) -> String {
        let current_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self._encrypt_at_time(data, current_time)
    }

    /// Encrypts data with the current_time. Returns a value (which is base64-encoded) that can be
    /// passed to `Fernet::decrypt`.
    ///
    /// This function has the capacity to be used incorrectly or insecurely due to
    /// to the "current_time" parameter. current_time must be the systems `time::SystemTime::now()`
    /// with `duraction_since(time::UNIX_EPOCH)` as seconds.
    ///
    /// The motivation for a function like this is for your application to be able to test
    /// ttl expiry of tokens in your API. This allows you to pass in mock time data to assert
    /// correct behaviour of your application. Care should be taken to ensure you always pass in
    /// correct current_time values for deployments.
    #[inline]
    #[cfg(feature = "fernet_danger_timestamps")]
    pub fn encrypt_at_time(&self, data: &[u8], current_time: u64) -> String {
        self._encrypt_at_time(data, current_time)
    }

    fn _encrypt_at_time(&self, data: &[u8], current_time: u64) -> String {
        let mut iv: [u8; 16] = Default::default();
        getrandom::getrandom(&mut iv).expect("Error in getrandom");
        self._encrypt_from_parts(data, current_time, &iv)
    }

    #[cfg(not(feature = "rustcrypto"))]
    fn _encrypt_from_parts(&self, data: &[u8], current_time: u64, iv: &[u8]) -> String {
        let ciphertext = openssl::symm::encrypt(
            openssl::symm::Cipher::aes_128_cbc(),
            &self.encryption_key,
            Some(iv),
            data,
        )
        .unwrap();

        let mut result = vec![0x80];
        result.extend_from_slice(&current_time.to_be_bytes());
        result.extend_from_slice(iv);
        result.extend_from_slice(&ciphertext);

        let hmac_pkey = openssl::pkey::PKey::hmac(&self.signing_key).unwrap();
        let mut hmac_signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &hmac_pkey).unwrap();
        hmac_signer.update(&result).unwrap();

        result.extend_from_slice(&hmac_signer.sign_to_vec().unwrap());

        crate::b64_encode_url(&result)
    }

    #[cfg(feature = "rustcrypto")]
    fn _encrypt_from_parts(&self, data: &[u8], current_time: u64, iv: &[u8]) -> String {
        let ciphertext = cbc::Encryptor::<aes::Aes128>::new_from_slices(&self.encryption_key, iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(data);

        let mut result = vec![0x80];
        result.extend_from_slice(&current_time.to_be_bytes());
        result.extend_from_slice(iv);
        result.extend_from_slice(&ciphertext);

        let mut hmac_signer = hmac::Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .expect("Signing key has unexpected size");
        hmac_signer.update(&result);

        result.extend_from_slice(&hmac_signer.finalize().into_bytes());
        crate::b64_encode_url(&result)
    }

    /// Decrypts a ciphertext. Returns either `Ok(plaintext)` if decryption is
    /// successful or `Err(DecryptionError)` if there are any errors. Errors could
    /// include incorrect key or tampering with the data.
    pub fn decrypt(&self, token: &str) -> Result<Vec<u8>, DecryptionError> {
        let current_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self._decrypt_at_time(token, None, current_time)
    }

    /// Decrypts a ciphertext with a time-to-live. Returns either `Ok(plaintext)`
    /// if decryption is successful or `Err(DecryptionError)` if there are any errors.
    /// Note if the token timestamp + ttl > current time, then this will also yield a
    /// DecryptionError. The ttl is measured in seconds. This is a relative time, not
    /// the absolute time of expiry. IE you would use 60 as a ttl_secs if you wanted
    /// tokens to be considered invalid after that time.
    pub fn decrypt_with_ttl(&self, token: &str, ttl_secs: u64) -> Result<Vec<u8>, DecryptionError> {
        let current_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self._decrypt_at_time(token, Some(ttl_secs), current_time)
    }

    /// Decrypt a ciphertext with a time-to-live, and the current time.
    /// Returns either `Ok(plaintext)` if decryption is
    /// successful or `Err(DecryptionError)` if there are any errors.
    ///
    /// This function has the capacity to be used incorrectly or insecurely due to
    /// to the "current_time" parameter. current_time must be the systems time::SystemTime::now()
    /// with duraction_since(time::UNIX_EPOCH) as seconds.
    ///
    /// The motivation for a function like this is for your application to be able to test
    /// ttl expiry of tokens in your API. This allows you to pass in mock time data to assert
    /// correct behaviour of your application. Care should be taken to ensure you always pass in
    /// correct current_time values for deployments.
    #[inline]
    #[cfg(feature = "fernet_danger_timestamps")]
    pub fn decrypt_at_time(
        &self,
        token: &str,
        ttl: Option<u64>,
        current_time: u64,
    ) -> Result<Vec<u8>, DecryptionError> {
        self._decrypt_at_time(token, ttl, current_time)
    }

    #[cfg(not(feature = "rustcrypto"))]
    fn _decrypt_at_time(
        &self,
        token: &str,
        ttl: Option<u64>,
        current_time: u64,
    ) -> Result<Vec<u8>, DecryptionError> {
        let parsed = Self::_decrypt_parse(token, ttl, current_time)?;

        let hmac_pkey = openssl::pkey::PKey::hmac(&self.signing_key).unwrap();
        let mut hmac_signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &hmac_pkey).unwrap();
        hmac_signer.update(&parsed.message).unwrap();
        let expected_hmac = hmac_signer.sign_to_vec().unwrap();
        if !openssl::memcmp::eq(&expected_hmac, &parsed.hmac) {
            return Err(DecryptionError);
        }

        let plaintext = openssl::symm::decrypt(
            openssl::symm::Cipher::aes_128_cbc(),
            &self.encryption_key,
            Some(&parsed.iv),
            &parsed.ciphertext,
        )
        .map_err(|_| DecryptionError)?;

        Ok(plaintext)
    }

    #[cfg(feature = "rustcrypto")]
    fn _decrypt_at_time(
        &self,
        token: &str,
        ttl: Option<u64>,
        current_time: u64,
    ) -> Result<Vec<u8>, DecryptionError> {
        let parsed = Self::_decrypt_parse(token, ttl, current_time)?;

        let mut hmac_signer = hmac::Hmac::<Sha256>::new_from_slice(&self.signing_key)
            .expect("Signing key has unexpected size");
        hmac_signer.update(&parsed.message);

        let expected_hmac = hmac_signer.finalize().into_bytes();

        use subtle::ConstantTimeEq;
        let hmac_matches: bool = parsed.hmac.ct_eq(&expected_hmac).into();
        if !hmac_matches {
            return Err(DecryptionError);
        }

        let plaintext =
            cbc::Decryptor::<aes::Aes128>::new_from_slices(&self.encryption_key, &parsed.iv)
                .unwrap()
                .decrypt_padded_vec_mut::<Pkcs7>(&parsed.ciphertext)
                .map_err(|_| DecryptionError)?;

        Ok(plaintext)
    }

    /// Parse the base64-encoded token into parts, verify timestamp TTL if given
    fn _decrypt_parse(
        token: &str,
        ttl: Option<u64>,
        current_time: u64,
    ) -> Result<ParsedToken, DecryptionError> {
        let data = match b64_decode_url(token) {
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

        let mut iv = [0; 16];
        input.read_exact(&mut iv).map_err(|_| DecryptionError)?;

        let mut rest = vec![];
        input.read_to_end(&mut rest).unwrap();
        if rest.len() < 32 {
            return Err(DecryptionError);
        }
        let ciphertext = rest[..rest.len() - 32].to_owned();

        input
            .seek(SeekFrom::Current(-32))
            .map_err(|_| DecryptionError)?;
        let mut hmac = [0u8; 32];
        input.read_exact(&mut hmac).map_err(|_| DecryptionError)?;

        let message = input.get_ref()[..input.get_ref().len() - 32].to_vec();
        Ok(ParsedToken {
            message,
            iv,
            ciphertext,
            hmac,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{DecryptionError, Fernet, MultiFernet};
    use serde_derive::Deserialize;
    use std::collections::HashSet;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

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
                OffsetDateTime::parse(v.now, &Rfc3339)
                    .unwrap()
                    .unix_timestamp() as u64,
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
                OffsetDateTime::parse(v.now, &Rfc3339)
                    .unwrap()
                    .unix_timestamp() as u64,
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
                OffsetDateTime::parse(v.now, &Rfc3339)
                    .unwrap()
                    .unix_timestamp() as u64,
            );
            assert_eq!(decrypted, Err(DecryptionError));
        }
    }

    #[test]
    fn test_invalid() {
        let f = Fernet::new(&super::b64_encode_url(&vec![0; 32])).unwrap();

        // Invalid version byte
        assert_eq!(
            f.decrypt(&crate::b64_encode_url(&b"\x81".to_vec())),
            Err(DecryptionError)
        );
        // Timestamp too short
        assert_eq!(
            f.decrypt(&super::b64_encode_url(
                &b"\x80\x00\x00\x00".to_vec())),
            Err(DecryptionError)
        );
        // Invalid base64
        assert_eq!(f.decrypt("\x00"), Err(DecryptionError));
    }

    #[test]
    fn test_roundtrips() {
        let f = Fernet::new(&super::b64_encode_url(&vec![0; 32])).unwrap();

        for val in [b"".to_vec(), b"Abc".to_vec(), b"\x00\xFF\x00\x00".to_vec()].iter() {
            assert_eq!(f.decrypt(&f.encrypt(val)), Ok(val.clone()));
        }
    }

    #[test]
    fn test_new_errors() {
        assert!(Fernet::new("axxx").is_none());
        assert!(Fernet::new(&super::b64_encode_url(&vec![0, 33])).is_none());
        assert!(Fernet::new(&super::b64_encode_url(&vec![0, 31])).is_none());
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

        for val in [b"".to_vec(), b"Abc".to_vec(), b"\x00\xFF\x00\x00".to_vec()].iter() {
            assert_eq!(f1.decrypt(&f2.encrypt(val)), Ok(val.clone()));
            assert_eq!(f2.decrypt(&f1.encrypt(val)), Ok(val.clone()));
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

        for val in [b"".to_vec(), b"Abc".to_vec(), b"\x00\xFF\x00\x00".to_vec()].iter() {
            assert_eq!(f.decrypt(&f.encrypt(val)), Ok(val.clone()));
        }
    }

    #[test]
    fn test_danger_timestamps() {
        use std::time;
        let key = Fernet::generate_key();
        let f = Fernet::new(&key).unwrap();
        let current_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let good_time = current_time + 1;
        let exp_time = current_time + 60;
        assert_eq!(
            f._decrypt_at_time(
                &f._encrypt_at_time(b"abc", current_time),
                Some(30),
                good_time,
            )
            .unwrap(),
            b"abc".to_vec()
        );
        assert_eq!(
            f._decrypt_at_time(
                &f._encrypt_at_time(b"abc", current_time),
                Some(30),
                exp_time,
            )
            .unwrap_err(),
            DecryptionError
        );
    }
}

/// base64 had a habit of changing this a fair bit, so isolating these functions
/// to reduce future code changes.
///
pub(crate) fn b64_decode_url(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input.trim_end_matches('='))
}

pub(crate) fn b64_encode_url(input: &Vec<u8>) -> String {
    base64::engine::general_purpose::URL_SAFE.encode(input)
}
