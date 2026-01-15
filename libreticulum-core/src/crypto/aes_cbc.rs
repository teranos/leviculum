//! AES-256-CBC encryption/decryption with PKCS7 padding

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};

type Aes256CbcEnc = Encryptor<aes::Aes256>;
type Aes256CbcDec = Decryptor<aes::Aes256>;

use crate::constants::{AES256_KEY_SIZE, AES_BLOCK_SIZE};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// AES-256-CBC encryption error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesError {
    /// Invalid key length (must be 32 bytes)
    InvalidKeyLength,
    /// Invalid IV length (must be 16 bytes)
    InvalidIvLength,
    /// Buffer too small for encrypted output
    BufferTooSmall,
    /// Decryption failed (invalid padding or ciphertext)
    DecryptionFailed,
}

/// Apply PKCS7 padding to a buffer
fn pkcs7_pad(data: &[u8], output: &mut [u8]) -> usize {
    let padding_len = AES_BLOCK_SIZE - (data.len() % AES_BLOCK_SIZE);
    let total_len = data.len() + padding_len;
    output[..data.len()].copy_from_slice(data);
    for i in data.len()..total_len {
        output[i] = padding_len as u8;
    }
    total_len
}

/// Remove PKCS7 padding and return valid length
fn pkcs7_unpad(data: &[u8]) -> Result<usize, AesError> {
    if data.is_empty() {
        return Err(AesError::DecryptionFailed);
    }
    let padding_len = data[data.len() - 1] as usize;
    if padding_len == 0 || padding_len > AES_BLOCK_SIZE || padding_len > data.len() {
        return Err(AesError::DecryptionFailed);
    }
    // Verify all padding bytes are correct
    for &byte in &data[data.len() - padding_len..] {
        if byte as usize != padding_len {
            return Err(AesError::DecryptionFailed);
        }
    }
    Ok(data.len() - padding_len)
}

/// Encrypt data using AES-256-CBC with PKCS7 padding
///
/// Returns ciphertext length written to the output buffer.
/// The output buffer must be large enough to hold plaintext + padding (up to 16 extra bytes).
pub fn aes256_cbc_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, AesError> {
    if key.len() != AES256_KEY_SIZE {
        return Err(AesError::InvalidKeyLength);
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(AesError::InvalidIvLength);
    }

    // Calculate padded length
    let padded_len = ((plaintext.len() / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    if output.len() < padded_len {
        return Err(AesError::BufferTooSmall);
    }

    // Apply PKCS7 padding
    let total_len = pkcs7_pad(plaintext, output);

    // Create cipher and encrypt in place
    let mut cipher = Aes256CbcEnc::new_from_slices(key, iv).expect("valid key/iv lengths");

    // Encrypt block by block
    for chunk in output[..total_len].chunks_exact_mut(AES_BLOCK_SIZE) {
        cipher.encrypt_block_mut(chunk.into());
    }

    Ok(total_len)
}

/// Encrypt data using AES-256-CBC, returning a new Vec
#[cfg(feature = "alloc")]
pub fn aes256_cbc_encrypt_vec(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AesError> {
    let padded_len = ((plaintext.len() / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    let mut output = alloc::vec![0u8; padded_len];
    let len = aes256_cbc_encrypt(key, iv, plaintext, &mut output)?;
    output.truncate(len);
    Ok(output)
}

/// Decrypt data using AES-256-CBC with PKCS7 padding
///
/// Returns plaintext length written to the output buffer.
pub fn aes256_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, AesError> {
    if key.len() != AES256_KEY_SIZE {
        return Err(AesError::InvalidKeyLength);
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(AesError::InvalidIvLength);
    }
    if ciphertext.len() % AES_BLOCK_SIZE != 0 || ciphertext.is_empty() {
        return Err(AesError::DecryptionFailed);
    }
    if output.len() < ciphertext.len() {
        return Err(AesError::BufferTooSmall);
    }

    // Copy ciphertext to output buffer
    output[..ciphertext.len()].copy_from_slice(ciphertext);

    // Create cipher and decrypt in place
    let mut cipher = Aes256CbcDec::new_from_slices(key, iv).expect("valid key/iv lengths");

    // Decrypt block by block
    for chunk in output[..ciphertext.len()].chunks_exact_mut(AES_BLOCK_SIZE) {
        cipher.decrypt_block_mut(chunk.into());
    }

    // Remove PKCS7 padding
    pkcs7_unpad(&output[..ciphertext.len()])
}

/// Decrypt data using AES-256-CBC, returning a new Vec
#[cfg(feature = "alloc")]
pub fn aes256_cbc_decrypt_vec(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AesError> {
    let mut output = alloc::vec![0u8; ciphertext.len()];
    let len = aes256_cbc_decrypt(key, iv, ciphertext, &mut output)?;
    output.truncate(len);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_padding() {
        let data = b"hello";
        let mut output = [0u8; 16];
        let len = pkcs7_pad(data, &mut output);
        assert_eq!(len, 16);
        // "hello" is 5 bytes, padding should be 11 bytes of 0x0b
        assert_eq!(&output[5..16], &[11u8; 11]);
    }

    #[test]
    fn test_pkcs7_unpad() {
        let mut data = [0u8; 16];
        data[..5].copy_from_slice(b"hello");
        for i in 5..16 {
            data[i] = 11;
        }
        let len = pkcs7_unpad(&data).unwrap();
        assert_eq!(len, 5);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 16];
        let plaintext = b"Hello, Reticulum!";

        let mut encrypted = [0u8; 32]; // 17 bytes + padding = 32 bytes
        let enc_len = aes256_cbc_encrypt(&key, &iv, plaintext, &mut encrypted).unwrap();
        assert_eq!(enc_len, 32);

        let mut decrypted = [0u8; 32];
        let dec_len = aes256_cbc_decrypt(&key, &iv, &encrypted[..enc_len], &mut decrypted).unwrap();
        assert_eq!(dec_len, plaintext.len());
        assert_eq!(&decrypted[..dec_len], plaintext);
    }

    #[test]
    fn test_encrypt_block_aligned() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 16];
        let plaintext = [0xab; 16]; // Exactly one block

        let mut encrypted = [0u8; 32]; // Will need extra block for padding
        let enc_len = aes256_cbc_encrypt(&key, &iv, &plaintext, &mut encrypted).unwrap();
        assert_eq!(enc_len, 32); // 16 bytes data + 16 bytes padding block
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0x42u8; 16]; // Wrong size
        let iv = [0x13u8; 16];
        let plaintext = b"test";
        let mut output = [0u8; 32];

        let result = aes256_cbc_encrypt(&key, &iv, plaintext, &mut output);
        assert_eq!(result, Err(AesError::InvalidKeyLength));
    }

    #[test]
    fn test_invalid_iv_length() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 8]; // Wrong size
        let plaintext = b"test";
        let mut output = [0u8; 32];

        let result = aes256_cbc_encrypt(&key, &iv, plaintext, &mut output);
        assert_eq!(result, Err(AesError::InvalidIvLength));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_vec_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 16];
        let plaintext = b"Test message for vec functions";

        let encrypted = aes256_cbc_encrypt_vec(&key, &iv, plaintext).unwrap();
        let decrypted = aes256_cbc_decrypt_vec(&key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
