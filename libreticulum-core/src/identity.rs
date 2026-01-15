//! Cryptographic identity management
//!
//! An Identity represents a cryptographic key pair used for:
//! - Encryption (X25519 ECDH)
//! - Digital signatures (Ed25519)
//!
//! The identity hash is derived from the public keys and serves as a unique
//! identifier in the network.

use crate::constants::{
    ED25519_KEY_SIZE, ED25519_SIGNATURE_SIZE, IDENTITY_HASHBYTES, IDENTITY_KEY_SIZE,
    RATCHET_SIZE, X25519_KEY_SIZE,
};
use crate::crypto::{sha256, truncated_hash};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Error types for identity operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// Invalid key length
    InvalidKeyLength,
    /// Invalid signature
    InvalidSignature,
    /// Decryption failed
    DecryptionFailed,
    /// No private key available (public-only identity)
    NoPrivateKey,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IdentityError::InvalidKeyLength => write!(f, "Invalid key length"),
            IdentityError::InvalidSignature => write!(f, "Invalid signature"),
            IdentityError::DecryptionFailed => write!(f, "Decryption failed"),
            IdentityError::NoPrivateKey => write!(f, "No private key available"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IdentityError {}

/// A cryptographic identity with X25519 and Ed25519 key pairs
pub struct Identity {
    /// X25519 private key for ECDH (None for public-only identities)
    x25519_private: Option<x25519_dalek::StaticSecret>,
    /// X25519 public key
    x25519_public: x25519_dalek::PublicKey,
    /// Ed25519 signing key (None for public-only identities)
    ed25519_signing: Option<ed25519_dalek::SigningKey>,
    /// Ed25519 verifying key
    ed25519_verifying: ed25519_dalek::VerifyingKey,
    /// Cached identity hash
    hash: [u8; IDENTITY_HASHBYTES],
}

impl Identity {
    /// Create a new identity with random keys
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        use rand_core::OsRng;
        Self::new_with_rng(&mut OsRng)
    }

    /// Create a new identity with a provided RNG
    pub fn new_with_rng<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        use rand_core::RngCore;

        let x25519_private = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_private);

        // Generate Ed25519 key from random bytes
        let mut ed25519_seed = [0u8; 32];
        rng.fill_bytes(&mut ed25519_seed);
        let ed25519_signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        let ed25519_verifying = ed25519_signing.verifying_key();

        let hash = Self::compute_hash(&x25519_public, &ed25519_verifying);

        Self {
            x25519_private: Some(x25519_private),
            x25519_public,
            ed25519_signing: Some(ed25519_signing),
            ed25519_verifying,
            hash,
        }
    }

    /// Create a public-only identity from public keys
    pub fn from_public_keys(
        x25519_pub: &[u8; X25519_KEY_SIZE],
        ed25519_pub: &[u8; ED25519_KEY_SIZE],
    ) -> Result<Self, IdentityError> {
        let x25519_public = x25519_dalek::PublicKey::from(*x25519_pub);
        let ed25519_verifying = ed25519_dalek::VerifyingKey::from_bytes(ed25519_pub)
            .map_err(|_| IdentityError::InvalidKeyLength)?;

        let hash = Self::compute_hash(&x25519_public, &ed25519_verifying);

        Ok(Self {
            x25519_private: None,
            x25519_public,
            ed25519_signing: None,
            ed25519_verifying,
            hash,
        })
    }

    /// Create an identity from combined public key bytes (64 bytes)
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != IDENTITY_KEY_SIZE {
            return Err(IdentityError::InvalidKeyLength);
        }

        let mut x25519_pub = [0u8; X25519_KEY_SIZE];
        let mut ed25519_pub = [0u8; ED25519_KEY_SIZE];
        x25519_pub.copy_from_slice(&bytes[..X25519_KEY_SIZE]);
        ed25519_pub.copy_from_slice(&bytes[X25519_KEY_SIZE..]);

        Self::from_public_keys(&x25519_pub, &ed25519_pub)
    }

    /// Load identity from private key bytes (64 bytes: 32 X25519 + 32 Ed25519)
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != IDENTITY_KEY_SIZE {
            return Err(IdentityError::InvalidKeyLength);
        }

        let mut x25519_prv = [0u8; X25519_KEY_SIZE];
        let mut ed25519_prv = [0u8; ED25519_KEY_SIZE];
        x25519_prv.copy_from_slice(&bytes[..X25519_KEY_SIZE]);
        ed25519_prv.copy_from_slice(&bytes[X25519_KEY_SIZE..]);

        let x25519_private = x25519_dalek::StaticSecret::from(x25519_prv);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_private);

        let ed25519_signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_prv);
        let ed25519_verifying = ed25519_signing.verifying_key();

        let hash = Self::compute_hash(&x25519_public, &ed25519_verifying);

        Ok(Self {
            x25519_private: Some(x25519_private),
            x25519_public,
            ed25519_signing: Some(ed25519_signing),
            ed25519_verifying,
            hash,
        })
    }

    /// Get the identity hash (truncated hash of public keys)
    pub fn hash(&self) -> &[u8; IDENTITY_HASHBYTES] {
        &self.hash
    }

    /// Get the combined public key bytes (64 bytes)
    pub fn public_key_bytes(&self) -> [u8; IDENTITY_KEY_SIZE] {
        let mut bytes = [0u8; IDENTITY_KEY_SIZE];
        bytes[..X25519_KEY_SIZE].copy_from_slice(self.x25519_public.as_bytes());
        bytes[X25519_KEY_SIZE..].copy_from_slice(self.ed25519_verifying.as_bytes());
        bytes
    }

    /// Get the private key bytes (64 bytes) if available
    pub fn private_key_bytes(&self) -> Result<[u8; IDENTITY_KEY_SIZE], IdentityError> {
        let x25519_prv = self.x25519_private.as_ref().ok_or(IdentityError::NoPrivateKey)?;
        let ed25519_prv = self.ed25519_signing.as_ref().ok_or(IdentityError::NoPrivateKey)?;

        let mut bytes = [0u8; IDENTITY_KEY_SIZE];
        bytes[..X25519_KEY_SIZE].copy_from_slice(x25519_prv.as_bytes());
        bytes[X25519_KEY_SIZE..].copy_from_slice(ed25519_prv.as_bytes());
        Ok(bytes)
    }

    /// Check if this identity has private keys
    pub fn has_private_keys(&self) -> bool {
        self.x25519_private.is_some() && self.ed25519_signing.is_some()
    }

    /// Sign a message with the Ed25519 key
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ED25519_SIGNATURE_SIZE], IdentityError> {
        use ed25519_dalek::Signer;

        let signing_key = self.ed25519_signing.as_ref().ok_or(IdentityError::NoPrivateKey)?;
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, IdentityError> {
        use ed25519_dalek::Verifier;

        if signature.len() != ED25519_SIGNATURE_SIZE {
            return Ok(false);
        }

        let sig_bytes: [u8; ED25519_SIGNATURE_SIZE] = signature
            .try_into()
            .map_err(|_| IdentityError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        Ok(self.ed25519_verifying.verify(message, &sig).is_ok())
    }

    /// Compute identity hash from public keys
    fn compute_hash(
        x25519_pub: &x25519_dalek::PublicKey,
        ed25519_pub: &ed25519_dalek::VerifyingKey,
    ) -> [u8; IDENTITY_HASHBYTES] {
        let mut combined = [0u8; IDENTITY_KEY_SIZE];
        combined[..X25519_KEY_SIZE].copy_from_slice(x25519_pub.as_bytes());
        combined[X25519_KEY_SIZE..].copy_from_slice(ed25519_pub.as_bytes());
        truncated_hash(&combined)
    }

    /// Get the X25519 public key
    pub fn x25519_public(&self) -> &x25519_dalek::PublicKey {
        &self.x25519_public
    }

    /// Get the Ed25519 verifying key
    pub fn ed25519_verifying(&self) -> &ed25519_dalek::VerifyingKey {
        &self.ed25519_verifying
    }

    // TODO: Implement encryption/decryption methods
    // TODO: Implement ratcheting support
}

#[cfg(feature = "std")]
impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn test_identity_creation() {
        let identity = Identity::new();
        assert!(identity.has_private_keys());
        assert_eq!(identity.hash().len(), IDENTITY_HASHBYTES);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_sign_verify() {
        let identity = Identity::new();
        let message = b"Test message for signing";

        let signature = identity.sign(message).unwrap();
        assert_eq!(signature.len(), ED25519_SIGNATURE_SIZE);

        assert!(identity.verify(message, &signature).unwrap());
        assert!(!identity.verify(b"Wrong message", &signature).unwrap());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_serialization() {
        let identity = Identity::new();

        // Test public key roundtrip
        let pub_bytes = identity.public_key_bytes();
        let pub_only = Identity::from_public_key_bytes(&pub_bytes).unwrap();
        assert_eq!(pub_only.hash(), identity.hash());
        assert!(!pub_only.has_private_keys());

        // Test private key roundtrip
        let prv_bytes = identity.private_key_bytes().unwrap();
        let restored = Identity::from_private_key_bytes(&prv_bytes).unwrap();
        assert_eq!(restored.hash(), identity.hash());
        assert!(restored.has_private_keys());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_public_only_cannot_sign() {
        let identity = Identity::new();
        let pub_bytes = identity.public_key_bytes();
        let pub_only = Identity::from_public_key_bytes(&pub_bytes).unwrap();

        let result = pub_only.sign(b"test");
        assert_eq!(result, Err(IdentityError::NoPrivateKey));
    }
}
