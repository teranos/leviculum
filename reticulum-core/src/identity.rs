//! Cryptographic identity management
//!
//! An Identity represents a cryptographic key pair used for:
//! - Encryption (X25519 ECDH)
//! - Digital signatures (Ed25519)
//!
//! The identity hash is derived from the public keys and serves as a unique
//! identifier in the network.

use crate::constants::{
    AES_BLOCK_SIZE, ED25519_KEY_SIZE, ED25519_SIGNATURE_SIZE, IDENTITY_HASHBYTES,
    IDENTITY_KEY_SIZE, X25519_KEY_SIZE,
};
use crate::crypto::{decrypt_token, derive_key, encrypt_token, truncated_hash};

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
extern crate std;

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
    /// Create a new identity with random keys from a Context
    ///
    /// # Example
    /// ```
    /// use reticulum_core::identity::Identity;
    /// use reticulum_core::traits::{PlatformContext, NoStorage};
    /// use rand_core::OsRng;
    ///
    /// // Simple clock implementation for the example
    /// struct SimpleClock;
    /// impl reticulum_core::traits::Clock for SimpleClock {
    ///     fn now_ms(&self) -> u64 { 0 }
    /// }
    ///
    /// let mut ctx = PlatformContext { rng: OsRng, clock: SimpleClock, storage: NoStorage };
    /// let identity = Identity::generate(&mut ctx);
    /// assert_eq!(identity.hash().len(), 16);
    /// ```
    pub fn generate(ctx: &mut impl crate::traits::Context) -> Self {
        Self::generate_with_rng(ctx.rng())
    }

    /// Create a new identity with a provided RNG
    pub fn generate_with_rng<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
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
        let x25519_prv = self
            .x25519_private
            .as_ref()
            .ok_or(IdentityError::NoPrivateKey)?;
        let ed25519_prv = self
            .ed25519_signing
            .as_ref()
            .ok_or(IdentityError::NoPrivateKey)?;

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

        let signing_key = self
            .ed25519_signing
            .as_ref()
            .ok_or(IdentityError::NoPrivateKey)?;
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

    /// Derived key length for encryption (64 bytes: 32 signing + 32 encryption)
    const DERIVED_KEY_LENGTH: usize = 64;

    /// Encrypt data for this identity using a Context
    ///
    /// Uses ephemeral ECDH key exchange followed by token encryption.
    /// Format: [ephemeral_pub (32)] [token (variable)]
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `ctx` - Platform context providing RNG
    ///
    /// # Returns
    /// Ciphertext that can be decrypted by the holder of this identity's private key
    pub fn encrypt(&self, plaintext: &[u8], ctx: &mut impl crate::traits::Context) -> Vec<u8> {
        self.encrypt_with_rng(plaintext, ctx.rng())
    }

    /// Encrypt data for this identity with a provided RNG
    pub fn encrypt_with_rng<R: rand_core::CryptoRngCore>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        // Generate ephemeral X25519 key pair
        let ephemeral_private = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);

        // Generate random IV
        let mut iv = [0u8; AES_BLOCK_SIZE];
        rng.fill_bytes(&mut iv);

        self.encrypt_impl(&ephemeral_private, plaintext, &iv)
    }

    /// Encrypt data for this identity with a specific ephemeral key and IV (for testing)
    pub fn encrypt_with_keys(
        &self,
        plaintext: &[u8],
        ephemeral_private_bytes: &[u8; X25519_KEY_SIZE],
        iv: &[u8; AES_BLOCK_SIZE],
    ) -> Vec<u8> {
        let ephemeral_private = x25519_dalek::StaticSecret::from(*ephemeral_private_bytes);
        self.encrypt_impl(&ephemeral_private, plaintext, iv)
    }

    /// Internal encryption implementation used by both encrypt_with_rng and encrypt_with_keys
    fn encrypt_impl(
        &self,
        ephemeral_private: &x25519_dalek::StaticSecret,
        plaintext: &[u8],
        iv: &[u8; AES_BLOCK_SIZE],
    ) -> Vec<u8> {
        let ephemeral_public = x25519_dalek::PublicKey::from(ephemeral_private);

        // Perform ECDH
        let shared_key = ephemeral_private.diffie_hellman(&self.x25519_public);

        // Derive encryption key using HKDF (salt = identity hash, context = None)
        let mut derived_key = [0u8; Self::DERIVED_KEY_LENGTH];
        derive_key(
            shared_key.as_bytes(),
            Some(&self.hash),
            None,
            &mut derived_key,
        );

        // Calculate token size: IV + padded ciphertext + HMAC
        let padded_len = ((plaintext.len() / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        let token_len = AES_BLOCK_SIZE + padded_len + 32; // IV + ciphertext + HMAC

        // Allocate output: ephemeral_pub + token
        let mut output = alloc::vec![0u8; X25519_KEY_SIZE + token_len];

        // Write ephemeral public key
        output[..X25519_KEY_SIZE].copy_from_slice(ephemeral_public.as_bytes());

        // Encrypt with token
        let token_size = encrypt_token(&derived_key, iv, plaintext, &mut output[X25519_KEY_SIZE..])
            .expect("token encryption should succeed with valid parameters");

        output.truncate(X25519_KEY_SIZE + token_size);
        output
    }

    /// Decrypt data encrypted for this identity
    ///
    /// # Arguments
    /// * `ciphertext` - Data encrypted with `encrypt()`
    ///
    /// # Returns
    /// Decrypted plaintext, or error if decryption fails
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let x25519_prv = self
            .x25519_private
            .as_ref()
            .ok_or(IdentityError::NoPrivateKey)?;

        // Minimum size: ephemeral_pub (32) + IV (16) + one block (16) + HMAC (32) = 96
        if ciphertext.len() < X25519_KEY_SIZE + AES_BLOCK_SIZE + AES_BLOCK_SIZE + 32 {
            return Err(IdentityError::DecryptionFailed);
        }

        // Extract ephemeral public key
        let mut peer_pub_bytes = [0u8; X25519_KEY_SIZE];
        peer_pub_bytes.copy_from_slice(&ciphertext[..X25519_KEY_SIZE]);
        let peer_public = x25519_dalek::PublicKey::from(peer_pub_bytes);

        // Perform ECDH
        let shared_key = x25519_prv.diffie_hellman(&peer_public);

        // Derive decryption key
        let mut derived_key = [0u8; Self::DERIVED_KEY_LENGTH];
        derive_key(
            shared_key.as_bytes(),
            Some(&self.hash),
            None,
            &mut derived_key,
        );

        // Decrypt token
        let token = &ciphertext[X25519_KEY_SIZE..];
        let mut plaintext = alloc::vec![0u8; token.len()];

        let plaintext_len = decrypt_token(&derived_key, token, &mut plaintext)
            .map_err(|_| IdentityError::DecryptionFailed)?;

        plaintext.truncate(plaintext_len);
        Ok(plaintext)
    }

    // TODO: Implement ratcheting support
}

// Note: No Default impl - use Identity::generate(ctx) instead

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // Helper to create identity in tests (uses OsRng directly)
    fn new_identity() -> Identity {
        Identity::generate_with_rng(&mut OsRng)
    }

    #[test]
    fn test_identity_creation() {
        let identity = new_identity();
        assert!(identity.has_private_keys());
        assert_eq!(identity.hash().len(), IDENTITY_HASHBYTES);
    }

    #[test]
    fn test_sign_verify() {
        let identity = new_identity();
        let message = b"Test message for signing";

        let signature = identity.sign(message).unwrap();
        assert_eq!(signature.len(), ED25519_SIGNATURE_SIZE);

        assert!(identity.verify(message, &signature).unwrap());
        assert!(!identity.verify(b"Wrong message", &signature).unwrap());
    }

    #[test]
    fn test_key_serialization() {
        let identity = new_identity();

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

    #[test]
    fn test_public_only_cannot_sign() {
        let identity = new_identity();
        let pub_bytes = identity.public_key_bytes();
        let pub_only = Identity::from_public_key_bytes(&pub_bytes).unwrap();

        let result = pub_only.sign(b"test");
        assert_eq!(result, Err(IdentityError::NoPrivateKey));
    }

    // ==================== EDGE CASE TESTS ====================

    #[test]
    fn test_public_only_cannot_decrypt() {
        let identity = new_identity();
        let pub_bytes = identity.public_key_bytes();
        let pub_only = Identity::from_public_key_bytes(&pub_bytes).unwrap();

        // Encrypt something for this identity
        let plaintext = b"Secret message";
        let ciphertext = identity.encrypt_with_rng(plaintext, &mut OsRng);

        // Public-only identity should not be able to decrypt
        let result = pub_only.decrypt(&ciphertext);
        assert_eq!(result, Err(IdentityError::NoPrivateKey));
    }

    #[test]
    fn test_public_only_cannot_get_private_key() {
        let identity = new_identity();
        let pub_bytes = identity.public_key_bytes();
        let pub_only = Identity::from_public_key_bytes(&pub_bytes).unwrap();

        let result = pub_only.private_key_bytes();
        assert_eq!(result, Err(IdentityError::NoPrivateKey));
    }

    #[test]
    fn test_decrypt_with_wrong_identity() {
        let alice = new_identity();
        let bob = new_identity();

        // Encrypt for Alice
        let plaintext = b"Secret for Alice";
        let ciphertext = alice.encrypt_with_rng(plaintext, &mut OsRng);

        // Bob should not be able to decrypt
        let result = bob.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_wrong_identity() {
        let alice = new_identity();
        let bob = new_identity();

        let message = b"Signed by Alice";
        let signature = alice.sign(message).unwrap();

        // Bob should not verify Alice's signature
        assert!(!bob.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_sign_empty_message() {
        let identity = new_identity();
        let message: &[u8] = b"";

        let signature = identity.sign(message).unwrap();
        assert_eq!(signature.len(), ED25519_SIGNATURE_SIZE);
        assert!(identity.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let identity = new_identity();
        let plaintext: &[u8] = b"";

        let ciphertext = identity.encrypt_with_rng(plaintext, &mut OsRng);
        let decrypted = identity.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn test_sign_large_message() {
        let identity = new_identity();
        let message = [0xab; 100000]; // 100KB

        let signature = identity.sign(&message).unwrap();
        assert!(identity.verify(&message, &signature).unwrap());
    }

    #[test]
    fn test_encrypt_large_plaintext() {
        let identity = new_identity();
        let plaintext = [0xab; 100000]; // 100KB

        let ciphertext = identity.encrypt_with_rng(&plaintext, &mut OsRng);
        let decrypted = identity.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_invalid_public_key_length() {
        let short_bytes = [0u8; 32]; // Should be 64
        let result = Identity::from_public_key_bytes(&short_bytes);
        assert!(matches!(result, Err(IdentityError::InvalidKeyLength)));
    }

    #[test]
    fn test_invalid_private_key_length() {
        let short_bytes = [0u8; 32]; // Should be 64
        let result = Identity::from_private_key_bytes(&short_bytes);
        assert!(matches!(result, Err(IdentityError::InvalidKeyLength)));
    }

    #[test]
    fn test_invalid_signature_length() {
        let identity = new_identity();
        let short_sig = [0u8; 32]; // Should be 64

        // Short signature should return false, not error
        let result = identity.verify(b"message", &short_sig);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_corrupted_signature() {
        let identity = new_identity();
        let message = b"Test message";

        let mut signature = identity.sign(message).unwrap();
        // Corrupt the signature
        signature[0] ^= 0x01;

        assert!(!identity.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_decrypt_corrupted_ephemeral_key() {
        let identity = new_identity();
        let plaintext = b"Secret message";

        let mut ciphertext = identity.encrypt_with_rng(plaintext, &mut OsRng);
        // Corrupt the ephemeral public key (first 32 bytes)
        ciphertext[0] ^= 0x01;

        // Should fail (HMAC will fail because derived key is different)
        let result = identity.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_corrupted_token() {
        let identity = new_identity();
        let plaintext = b"Secret message";

        let mut ciphertext = identity.encrypt_with_rng(plaintext, &mut OsRng);
        // Corrupt the token part (after ephemeral key)
        ciphertext[40] ^= 0x01;

        let result = identity.decrypt(&ciphertext);
        assert_eq!(result, Err(IdentityError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_truncated_ciphertext() {
        let identity = new_identity();
        let plaintext = b"Secret message";

        let ciphertext = identity.encrypt_with_rng(plaintext, &mut OsRng);
        // Truncate to less than minimum size
        let truncated = &ciphertext[..32];

        let result = identity.decrypt(truncated);
        assert_eq!(result, Err(IdentityError::DecryptionFailed));
    }

    #[test]
    fn test_each_identity_unique_hash() {
        let id1 = new_identity();
        let id2 = new_identity();

        assert_ne!(id1.hash(), id2.hash());
    }

    #[test]
    fn test_identity_hash_deterministic() {
        let identity = new_identity();
        let prv_bytes = identity.private_key_bytes().unwrap();

        let restored = Identity::from_private_key_bytes(&prv_bytes).unwrap();

        assert_eq!(identity.hash(), restored.hash());
    }

    #[test]
    fn test_signature_deterministic() {
        // Ed25519 signatures are deterministic
        let identity = new_identity();
        let message = b"Test message";

        let sig1 = identity.sign(message).unwrap();
        let sig2 = identity.sign(message).unwrap();

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_encryption_not_deterministic() {
        // Each encryption should produce different ciphertext (random ephemeral key + IV)
        let identity = new_identity();
        let plaintext = b"Same message";

        let ct1 = identity.encrypt_with_rng(plaintext, &mut OsRng);
        let ct2 = identity.encrypt_with_rng(plaintext, &mut OsRng);

        // Ciphertexts should be different
        assert_ne!(ct1, ct2);

        // But both should decrypt to the same plaintext
        assert_eq!(identity.decrypt(&ct1).unwrap(), plaintext);
        assert_eq!(identity.decrypt(&ct2).unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_for_public_only_identity() {
        // Should be able to encrypt for a public-only identity
        let identity = new_identity();
        let pub_bytes = identity.public_key_bytes();
        let pub_only = Identity::from_public_key_bytes(&pub_bytes).unwrap();

        let plaintext = b"Secret message";
        let ciphertext = pub_only.encrypt_with_rng(plaintext, &mut OsRng);

        // Original identity (with private key) should be able to decrypt
        let decrypted = identity.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_multiple_encrypt_decrypt_cycles() {
        let identity = new_identity();

        for i in 0..10 {
            let plaintext = alloc::format!("Message number {}", i);
            let ciphertext = identity.encrypt_with_rng(plaintext.as_bytes(), &mut OsRng);
            let decrypted = identity.decrypt(&ciphertext).unwrap();
            assert_eq!(&decrypted[..], plaintext.as_bytes());
        }
    }

    #[test]
    fn test_different_identities_different_public_keys() {
        let id1 = new_identity();
        let id2 = new_identity();

        assert_ne!(id1.public_key_bytes(), id2.public_key_bytes());
    }

    #[test]
    fn test_sign_then_verify_roundtrip() {
        let signer = new_identity();
        let pub_bytes = signer.public_key_bytes();
        let verifier = Identity::from_public_key_bytes(&pub_bytes).unwrap();

        let message = b"Important document";
        let signature = signer.sign(message).unwrap();

        // Verifier (public-only) should be able to verify
        assert!(verifier.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_encrypt_single_byte() {
        let identity = new_identity();
        let plaintext = [0xaa];

        let ciphertext = identity.encrypt_with_rng(&plaintext, &mut OsRng);
        let decrypted = identity.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0], 0xaa);
    }

    #[test]
    fn test_verify_tampered_message() {
        let identity = new_identity();
        let message = b"Original message";
        let signature = identity.sign(message).unwrap();

        // Tampered message should not verify
        let tampered = b"Tampered message";
        assert!(!identity.verify(tampered, &signature).unwrap());
    }

    #[test]
    fn test_decrypt_minimum_ciphertext_size() {
        let identity = new_identity();
        // Minimum: ephemeral_pub (32) + IV (16) + one block (16) + HMAC (32) = 96
        let too_short = [0u8; 95];

        let result = identity.decrypt(&too_short);
        assert_eq!(result, Err(IdentityError::DecryptionFailed));
    }
}
