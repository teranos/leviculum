//! HKDF (HMAC-based Key Derivation Function) implementation

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a key using HKDF-SHA256
///
/// # Arguments
/// * `ikm` - Input key material
/// * `salt` - Optional salt (use None for zero-length salt)
/// * `info` - Optional context/application-specific info
/// * `output` - Buffer to write derived key material
///
/// # Panics
/// Panics if output length exceeds 255 * 32 bytes
pub fn derive_key(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, output: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info.unwrap_or(&[]), output)
        .expect("output length should not exceed 255 * hash length");
}

/// Derive a fixed-size key using HKDF-SHA256
pub fn derive_key_fixed<const N: usize>(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> [u8; N] {
    let mut output = [0u8; N];
    derive_key(ikm, salt, info, &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";
        let mut output = [0u8; 32];

        derive_key(ikm, Some(salt), Some(info), &mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"input key material";
        let mut output = [0u8; 32];

        derive_key(ikm, None, None, &mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_fixed() {
        let ikm = b"input key material";
        let output: [u8; 64] = derive_key_fixed(ikm, None, None);
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"input key material";
        let salt = b"salt";

        let out1: [u8; 32] = derive_key_fixed(ikm, Some(salt), None);
        let out2: [u8; 32] = derive_key_fixed(ikm, Some(salt), None);
        assert_eq!(out1, out2);
    }
}
