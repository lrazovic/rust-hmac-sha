#![no_std]
#![allow(dead_code)]

use digest::Digest;
use heapless::Vec;
use hmac::{Hmac, Mac, NewMac};
pub struct HmacSha<'a, T: Digest> {
    key: &'a [u8],
    message: &'a [u8],
    sha_type: T,
}

impl<'a, T> HmacSha<'a, T>
where
    T: digest::Digest + digest::Update + digest::FixedOutput + digest::Reset + Clone + Default + digest::BlockInput,
{
    #[must_use]
    pub fn new(key: &'a [u8], message: &'a [u8], sha_type: T) -> Self {
        Self {
            key,
            message,
            sha_type,
        }
    }

    #[must_use]
    pub fn from(key: &'a str, message: &'a str, sha_type: T) -> Self {
        Self {
            key: key.as_bytes(),
            message: message.as_bytes(),
            sha_type,
        }
    }

    pub fn compute_digest(&mut self) -> Vec<u8, 64> {
        let mut mac = Hmac::<T>::new_from_slice(self.key).expect("HMAC can take key of any size");
        mac.update(self.message);
        let bytes = mac.finalize().into_bytes();
        let bytes = bytes.as_slice();
        Vec::from_slice(bytes).expect("Failed to compute the digest")
    }
}

#[cfg(test)]
mod tests {

    use super::HmacSha;
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};
    use sha3::Sha3_256;

    #[test]
    fn test_vector1() {
        // tuples of (data, key, expected hex string)
        let data = b"Hi There";
        let key = &[0x0b; 20];
        let expected = "b617318655057264e28bc0b6fb378c8ef146be00";
        let mut hash = HmacSha::new(key, data, Sha1::default());
        let buf = hash.compute_digest();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_vector2() {
        // tuples of (data, key, expected hex string)
        let data = b"what do ya want for nothing?";
        let key = b"Jefe";
        let expected = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";
        let mut hash = HmacSha::new(key, data, Sha1::default());
        let buf = hash.compute_digest();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_vector3() {
        // tuples of (data, key, expected hex string)
        let data = &[0xdd; 50];
        let key = &[0xaa; 20];
        let expected = "125d7342b9ac11cd91a39af48aa17b4f63f175d3";
        let mut hash = HmacSha::new(key, data, Sha1::default());
        let buf = hash.compute_digest();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_vector4() {
        // tuples of (data, key, expected hex string)
        let data = &[0xcd; 50];
        let key = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25,
        ];
        let expected = "4c9007f4026250c6bc8414f9bf50c86c2d7235da";
        let mut hasher = HmacSha::new(key, data, Sha1::default());
        let result = hasher.compute_digest();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_readme() {
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "bc192ba8d968e0c705eecd406c74299ca83d05e6";
        let mut hasher = HmacSha::from(secret_key, message, Sha1::default());
        let result = hasher.compute_digest();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_readme_sha2() {
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "4134aad013bd12a6d7b0a5b5e78e3b1a76cb095cf5b7ceb6ac0717e433f56133";
        let mut hasher = HmacSha::from(secret_key, message, Sha256::default());
        let result = hasher.compute_digest();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_readme_sha3() {
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "92b41d5b7e665a81faa9c18e25657107ad8f174cdc7558a15b6990c2c47c7bfe";
        let mut hasher = HmacSha::from(secret_key, message, Sha3_256::default());
        let result = hasher.compute_digest();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_readme_sha2_512() {
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "e9a33f07f9d14e95efda67889e015c73b8c71c1372976c1d247c0e1d1aad7822427f113d8d8f0a5fbb33c7a547491867346d19e2a02bf02349118ff6c6eba51a";
        let mut hasher = HmacSha::from(secret_key, message, Sha512::default());
        let result = hasher.compute_digest();
        assert_eq!(hex::encode(result), expected);
    }
}
