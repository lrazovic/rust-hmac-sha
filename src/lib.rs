#![no_std]

// define hash constants
pub const SHA1_DIGEST_BYTES: usize = 20;
const SHA1_KEY_BYTES: usize = 64;

// set constants for HMAC
const INNER_PAD_BYTES: u8 = 0x36;
const OUTER_PAD_BYTE: u8 = 0x5c;
const KEY_PAD_BYTE: u8 = 0x00;

use sha1::{Digest, Sha1};

pub struct HmacSha1<'a> {
    key: &'a [u8],
    message: &'a [u8],
    output: &'a mut [u8],
}

impl<'a> HmacSha1<'a> {
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

    #[inline(always)]
    pub fn digest(&mut self) {
        // instantiate internal structures
        let mut hasher = Sha1::new();
        let auth_key: &mut [u8; SHA1_KEY_BYTES] = &mut [KEY_PAD_BYTE; SHA1_KEY_BYTES];

        // if the key is longer than the hasher's block length, it should be truncated using the hasher
        if self.key.len() > SHA1_KEY_BYTES {
            // derive new authentication from provided key
            hasher.update(self.key);

            // assign derived authentication key
            let digest = hasher.finalize_reset();
            auth_key[..SHA1_DIGEST_BYTES].copy_from_slice(&(digest));
        } else {
            auth_key[..self.key.len()].copy_from_slice(self.key);
        }

        // generate padding arrays
        let mut inner_padding: [u8; SHA1_KEY_BYTES] = [INNER_PAD_BYTES; SHA1_KEY_BYTES];
        let mut outer_padding: [u8; SHA1_KEY_BYTES] = [OUTER_PAD_BYTE; SHA1_KEY_BYTES];

        for (offset, elem) in auth_key.iter().enumerate() {
            inner_padding[offset] ^= elem;
            outer_padding[offset] ^= elem;
        }

        // perform inner hash
        hasher.update(&inner_padding);
        hasher.update(self.message);
        let inner_hash = hasher.finalize_reset();

        // perform outer hash
        hasher.update(&outer_padding);
        hasher.update(&inner_hash);
        self.output.copy_from_slice(&hasher.finalize())
    }
}

#[cfg(test)]
mod tests {

    use super::HmacSha1;

    #[test]
    fn test_vector1() {
        // tuples of (data, key, expected hex string)
        let data = "Hi There".as_bytes();
        let key = &[0x0b; 20];
        let expected = "b617318655057264e28bc0b6fb378c8ef146be00";
        let mut buf = [0_u8; 20];
        HmacSha1::new(key, data, &mut buf).digest();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_vector2() {
        // tuples of (data, key, expected hex string)
        let data = "what do ya want for nothing?".as_bytes();
        let key = "Jefe".as_bytes();
        let expected = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";
        let mut buf = [0_u8; 20];
        HmacSha1::new(key, data, &mut buf).digest();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_vector3() {
        // tuples of (data, key, expected hex string)
        let data = &[0xdd; 50];
        let key = &[0xaa; 20];
        let expected = "125d7342b9ac11cd91a39af48aa17b4f63f175d3";
        let mut buf = [0_u8; 20];
        HmacSha1::new(key, data, &mut buf).digest();
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
        HmacSha1::new(key, data, &mut buf).digest();
        assert_eq!(hex::encode(buf), expected);
    }

    #[test]
    fn test_readme() {
        let mut digest = [0u8; 20];
        let secret_key = "A very strong secret";
        let message = "My secret message";
        let expected = "bc192ba8d968e0c705eecd406c74299ca83d05e6";
        HmacSha1::from(secret_key, &message, &mut digest).digest();
        assert_eq!(hex::encode(digest), expected);
    }
}
