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
use rand::Rng;

const MAX_CLOCK_SKEW: u64 = 60;

pub struct Fernet {
    encryption_key: Vec<u8>,
    signing_key: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecryptionError;

impl Fernet {
    pub fn new(key: &str) -> Fernet {
        let key = base64::decode_config(key, base64::URL_SAFE).unwrap();
        assert_eq!(key.len(), 32);
        Fernet {
            signing_key: key[..16].to_vec(),
            encryption_key: key[16..].to_vec(),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> String {
        let current_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut iv: [u8; 16] = Default::default();
        rand::OsRng::new().unwrap().fill_bytes(&mut iv);
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

        let timestamp = match input.read_u64::<byteorder::BigEndian>() {
            Ok(value) => value,
            Err(_) => return Err(DecryptionError),
        };

        if let Some(ttl) = ttl {
            if timestamp + ttl < current_time {
                return Err(DecryptionError);
            }
        }

        if current_time + MAX_CLOCK_SKEW < timestamp {
            return Err(DecryptionError);
        }

        let mut iv = vec![0; 16];
        if input.read_exact(&mut iv).is_err() {
            return Err(DecryptionError);
        }

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

        let plaintext = match openssl::symm::decrypt(
            openssl::symm::Cipher::aes_128_cbc(),
            &self.encryption_key,
            Some(&iv),
            ciphertext,
        ) {
            Ok(value) => value,
            Err(_) => return Err(DecryptionError),
        };

        return Ok(plaintext);
    }
}

#[cfg(test)]
mod tests {
    extern crate base64;
    extern crate chrono;
    extern crate serde_json;

    use super::{DecryptionError, Fernet};

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
        // TODO: the vector file shouldn't be in this directory
        let vectors: Vec<GenerateVector> =
            serde_json::from_str(include_str!("generate.json")).unwrap();

        for v in vectors {
            let f = Fernet::new(v.secret);
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
        // TODO: the vector file shouldn't be in this directory
        let vectors: Vec<VerifyVector> = serde_json::from_str(include_str!("verify.json")).unwrap();

        for v in vectors {
            let f = Fernet::new(v.secret);
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
        // TODO: the vector file shouldn't be in this directory
        let vectors: Vec<InvalidVector> =
            serde_json::from_str(include_str!("invalid.json")).unwrap();

        for v in vectors {
            let f = Fernet::new(v.secret);
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
        let f = Fernet::new(&base64::encode_config(&vec![0; 32], base64::URL_SAFE));

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
        let f = Fernet::new(&base64::encode_config(&vec![0; 32], base64::URL_SAFE));

        for val in [b"".to_vec(), b"Abc".to_vec(), b"\x00\xFF\x00\x00".to_vec()].into_iter() {
            assert_eq!(f.decrypt(&f.encrypt(&val)), Ok(val.clone()));
        }
    }

}
