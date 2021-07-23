#![no_std]

use hmac::{
    digest::{BlockInput, Digest, FixedOutputDirty, Reset, Update},
    Hmac, Mac, NewMac,
};

pub struct HmacSha<'a> {
    key: &'a [u8],
    message: &'a [u8],
    output: &'a mut [u8],
}

impl<'a> HmacSha<'a> {
    pub fn new(key: &'a [u8], message: &'a [u8], output: &'a mut [u8]) -> Self {
        Self {
            key,
            message,
            output,
        }
    }

    pub fn from(key: &'a str, message: &'a str, output: &'a mut [u8]) -> Self {
        Self {
            key: key.as_bytes(),
            message: message.as_bytes(),
            output,
        }
    }

    pub fn digest<D: Digest + Update + BlockInput + Reset + Default + Clone + FixedOutputDirty>(
        &mut self,
    ) {
        let mut mac = Hmac::<D>::new_from_slice(self.key).expect("HMAC can take key of any size");
        mac.update(self.message);
        self.output.copy_from_slice(&mac.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {

    use super::HmacSha;
    use crate::constants::*;
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};
    use sha3::Sha3_256;

    #[test]
    fn test_vector1() {
        // tuples of (data, key, expected hex string)
        let data = "Hi There".as_bytes();
        let key = &[0x0b; 20];
        let expected = "b617318655057264e28bc0b6fb378c8ef146be00";
        let mut buf = [0_u8; 20];
        let mut hasher = HmacSha::new(key, data, &mut buf);
        hasher.digest::<Sha1>();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_vector2() {
        // tuples of (data, key, expected hex string)
        let data = "what do ya want for nothing?".as_bytes();
        let key = "Jefe".as_bytes();
        let expected = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";
        let mut buf = [0_u8; 20];
        let mut hasher = HmacSha::new(key, data, &mut buf);
        hasher.digest::<Sha1>();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_vector3() {
        // tuples of (data, key, expected hex string)
        let data = &[0xdd; 50];
        let key = &[0xaa; 20];
        let expected = "125d7342b9ac11cd91a39af48aa17b4f63f175d3";
        let mut buf = [0_u8; 20];
        let mut hasher = HmacSha::new(key, data, &mut buf);
        hasher.digest::<Sha1>();
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
        let mut buf = [0_u8; 20];
        let mut hasher = HmacSha::new(key, data, &mut buf);
        hasher.digest::<Sha1>();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_readme() {
        let mut digest = [0_u8; SHA1_OUTPUT_SIZE];
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "bc192ba8d968e0c705eecd406c74299ca83d05e6";
        let mut hasher = HmacSha::from(secret_key, message, &mut digest);
        hasher.digest::<Sha1>();
        assert_eq!(hex::encode(digest), expected);
    }

    #[test]
    fn test_readme_sha2() {
        let mut digest = [0_u8; SHA_256_OUTPUT_SIZE];
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "4134aad013bd12a6d7b0a5b5e78e3b1a76cb095cf5b7ceb6ac0717e433f56133";
        let mut hasher = HmacSha::from(secret_key, message, &mut digest);
        hasher.digest::<Sha256>();
        assert_eq!(hex::encode(digest), expected);
    }

    #[test]
    fn test_readme_sha3() {
        let mut digest = [0_u8; SHA_256_OUTPUT_SIZE];
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "92b41d5b7e665a81faa9c18e25657107ad8f174cdc7558a15b6990c2c47c7bfe";
        let mut hasher = HmacSha::from(secret_key, message, &mut digest);
        hasher.digest::<Sha3_256>();
        assert_eq!(hex::encode(digest), expected);
    }

    #[test]
    fn test_readme_sha2_512() {
        let mut digest = [0_u8; SHA_512_OUTPUT_SIZE];
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "e9a33f07f9d14e95efda67889e015c73b8c71c1372976c1d247c0e1d1aad7822427f113d8d8f0a5fbb33c7a547491867346d19e2a02bf02349118ff6c6eba51a";
        let mut hasher = HmacSha::from(secret_key, message, &mut digest);
        hasher.digest::<Sha512>();
        assert_eq!(hex::encode(digest), expected);
    }
}

pub mod constants {
    pub const SHA1_OUTPUT_SIZE: usize = 20;
    pub const SHA_256_OUTPUT_SIZE: usize = 32;
    pub const SHA_512_OUTPUT_SIZE: usize = 64;
}
