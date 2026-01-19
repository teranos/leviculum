//! Cryptographic primitives for Reticulum
//!
//! This module provides the cryptographic building blocks used throughout
//! the Reticulum protocol:
//!
//! - X25519 for ECDH key exchange
//! - Ed25519 for digital signatures
//! - AES-256-CBC for symmetric encryption
//! - HMAC-SHA256 for message authentication
//! - HKDF for key derivation
//! - SHA-256/SHA-512 for hashing

mod aes_cbc;
mod hashes;
mod hkdf_impl;
mod hmac_impl;
mod token;

pub use aes_cbc::{aes256_cbc_decrypt, aes256_cbc_encrypt};
pub use hashes::{full_hash, sha256, sha512, truncated_hash};
pub use hkdf_impl::derive_key;
pub use hmac_impl::{hmac_sha256, verify_hmac};
pub use token::{decrypt_token, encrypt_token, TokenError};

// Re-export key types from dalek crates
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
pub use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

/// Generate random bytes using the provided RNG
#[cfg(feature = "std")]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::OsRng;
    let mut bytes = [0u8; N];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    bytes
}

/// Generate random bytes using a provided RNG (for no_std)
pub fn random_bytes_with_rng<R: rand_core::RngCore, const N: usize>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}
