//! Packet receipt tracking for delivery confirmation
//!
//! A PacketReceipt tracks a sent packet awaiting proof of delivery.
//! When the receiver processes a packet, it can generate a cryptographic
//! proof (signature of the packet hash) and send it back.
//!
//! # Usage
//!
//! 1. After sending a packet, create a `PacketReceipt` for it
//! 2. Store receipts in a map keyed by truncated hash
//! 3. When a proof packet arrives, look up the receipt and validate
//! 4. Periodically check for expired receipts
//!
//! # Example
//!
//! ```
//! use reticulum_core::receipt::{PacketReceipt, ReceiptStatus};
//! use reticulum_core::destination::DestinationHash;
//!
//! // After sending a packet
//! let packet_hash = [0x42u8; 32];
//! let dest_hash = DestinationHash::new([0x01u8; 16]);
//! let receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);
//!
//! assert_eq!(receipt.status, ReceiptStatus::Sent);
//! assert!(!receipt.is_expired(1500)); // Not expired yet
//! assert!(receipt.is_expired(32000)); // Expired after timeout
//! ```

use crate::constants::{PROOF_DATA_SIZE, RECEIPT_TIMEOUT_DEFAULT_MS, TRUNCATED_HASHBYTES};
use crate::crypto::truncated_hash;
use crate::destination::DestinationHash;
use crate::identity::Identity;

/// Status of a packet receipt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// Packet was sent, awaiting proof
    Sent,
    /// Proof received and validated - packet was delivered
    Delivered,
    /// Receipt timed out or proof validation failed
    Failed,
}

/// Tracks a sent packet awaiting proof of delivery
///
/// When a packet is sent that requests proof of delivery, a PacketReceipt
/// is created to track it. The receipt stores the packet hash and allows
/// validation of incoming proofs.
#[derive(Debug, Clone)]
pub struct PacketReceipt {
    /// Full SHA256 hash of the sent packet
    pub packet_hash: [u8; 32],
    /// Truncated hash (used as receipt ID for lookups)
    pub truncated_hash: [u8; TRUNCATED_HASHBYTES],
    /// Destination the packet was sent to
    pub destination_hash: DestinationHash,
    /// When the packet was sent (ms since epoch)
    pub sent_at_ms: u64,
    /// Current receipt status
    pub status: ReceiptStatus,
    /// Timeout duration in milliseconds
    pub timeout_ms: u64,
}

impl PacketReceipt {
    /// Create a new receipt for a sent packet
    ///
    /// # Arguments
    /// * `packet_hash` - Full SHA256 hash of the sent packet
    /// * `destination_hash` - Hash of the destination the packet was sent to
    /// * `sent_at_ms` - Timestamp when the packet was sent
    ///
    /// # Example
    /// ```
    /// use reticulum_core::receipt::PacketReceipt;
    /// use reticulum_core::destination::DestinationHash;
    ///
    /// let packet_hash = [0x42u8; 32];
    /// let dest_hash = DestinationHash::new([0x01u8; 16]);
    /// let receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);
    /// ```
    pub fn new(
        packet_hash: [u8; 32],
        destination_hash: DestinationHash,
        sent_at_ms: u64,
    ) -> Self {
        let truncated = truncated_hash(&packet_hash);
        Self {
            packet_hash,
            truncated_hash: truncated,
            destination_hash,
            sent_at_ms,
            status: ReceiptStatus::Sent,
            timeout_ms: RECEIPT_TIMEOUT_DEFAULT_MS,
        }
    }

    /// Create a receipt with a custom timeout
    ///
    /// # Arguments
    /// * `packet_hash` - Full SHA256 hash of the sent packet
    /// * `destination_hash` - Hash of the destination
    /// * `sent_at_ms` - Timestamp when sent
    /// * `timeout_ms` - Custom timeout duration in milliseconds
    pub fn with_timeout(
        packet_hash: [u8; 32],
        destination_hash: DestinationHash,
        sent_at_ms: u64,
        timeout_ms: u64,
    ) -> Self {
        let truncated = truncated_hash(&packet_hash);
        Self {
            packet_hash,
            truncated_hash: truncated,
            destination_hash,
            sent_at_ms,
            status: ReceiptStatus::Sent,
            timeout_ms,
        }
    }

    /// Check if the receipt has timed out
    ///
    /// # Arguments
    /// * `current_time_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    /// `true` if the timeout has elapsed since the packet was sent
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.sent_at_ms) > self.timeout_ms
    }

    /// Validate an incoming proof against this receipt
    ///
    /// Checks that:
    /// 1. The proof data is the correct size (96 bytes)
    /// 2. The packet hash in the proof matches our stored hash
    /// 3. The signature is valid for the sender's public key
    ///
    /// # Arguments
    /// * `proof_data` - The proof data (96 bytes: hash + signature)
    /// * `sender_identity` - The identity of the sender (for signature verification)
    ///
    /// # Returns
    /// `true` if the proof is valid
    pub fn validate_proof(&self, proof_data: &[u8], sender_identity: &Identity) -> bool {
        if proof_data.len() != PROOF_DATA_SIZE {
            return false;
        }

        sender_identity.verify_proof(proof_data, &self.packet_hash)
    }

    /// Mark this receipt as delivered
    pub fn set_delivered(&mut self) {
        self.status = ReceiptStatus::Delivered;
    }

    /// Mark this receipt as failed
    pub fn set_failed(&mut self) {
        self.status = ReceiptStatus::Failed;
    }

    /// Get the time elapsed since the packet was sent
    ///
    /// # Arguments
    /// * `current_time_ms` - Current timestamp
    ///
    /// # Returns
    /// Milliseconds elapsed since the packet was sent
    pub fn elapsed_ms(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.sent_at_ms)
    }

    /// Get the remaining time before timeout
    ///
    /// # Arguments
    /// * `current_time_ms` - Current timestamp
    ///
    /// # Returns
    /// Milliseconds remaining, or 0 if already expired
    pub fn remaining_ms(&self, current_time_ms: u64) -> u64 {
        let elapsed = self.elapsed_ms(current_time_ms);
        self.timeout_ms.saturating_sub(elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn new_identity() -> Identity {
        Identity::generate(&mut OsRng)
    }

    #[test]
    fn test_receipt_creation() {
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);

        assert_eq!(receipt.packet_hash, packet_hash);
        assert_eq!(receipt.destination_hash, dest_hash);
        assert_eq!(receipt.sent_at_ms, 1000);
        assert_eq!(receipt.status, ReceiptStatus::Sent);
        assert_eq!(receipt.timeout_ms, RECEIPT_TIMEOUT_DEFAULT_MS);

        // Truncated hash should be computed
        assert_eq!(receipt.truncated_hash, truncated_hash(&packet_hash));
    }

    #[test]
    fn test_receipt_with_custom_timeout() {
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::with_timeout(packet_hash, dest_hash, 1000, 5000);

        assert_eq!(receipt.timeout_ms, 5000);
    }

    #[test]
    fn test_receipt_expiry() {
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::with_timeout(packet_hash, dest_hash, 1000, 5000);

        // Not expired at sent time
        assert!(!receipt.is_expired(1000));

        // Not expired just before timeout
        assert!(!receipt.is_expired(5999));

        // Expired at timeout
        assert!(receipt.is_expired(6001));

        // Definitely expired way after
        assert!(receipt.is_expired(100000));
    }

    #[test]
    fn test_receipt_elapsed_remaining() {
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::with_timeout(packet_hash, dest_hash, 1000, 5000);

        // At start
        assert_eq!(receipt.elapsed_ms(1000), 0);
        assert_eq!(receipt.remaining_ms(1000), 5000);

        // Halfway
        assert_eq!(receipt.elapsed_ms(3500), 2500);
        assert_eq!(receipt.remaining_ms(3500), 2500);

        // At timeout
        assert_eq!(receipt.elapsed_ms(6000), 5000);
        assert_eq!(receipt.remaining_ms(6000), 0);

        // Past timeout
        assert_eq!(receipt.elapsed_ms(10000), 9000);
        assert_eq!(receipt.remaining_ms(10000), 0);
    }

    #[test]
    fn test_receipt_status_transitions() {
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let mut receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);

        assert_eq!(receipt.status, ReceiptStatus::Sent);

        receipt.set_delivered();
        assert_eq!(receipt.status, ReceiptStatus::Delivered);

        // Can also transition to failed
        let mut receipt2 = PacketReceipt::new(packet_hash, dest_hash, 1000);
        receipt2.set_failed();
        assert_eq!(receipt2.status, ReceiptStatus::Failed);
    }

    #[test]
    fn test_validate_proof_valid() {
        let identity = new_identity();
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);

        // Create a valid proof
        let proof = identity.create_proof(&packet_hash).unwrap();

        // Validation should succeed
        assert!(receipt.validate_proof(&proof, &identity));
    }

    #[test]
    fn test_validate_proof_wrong_hash() {
        let identity = new_identity();
        let packet_hash = [0x42u8; 32];
        let wrong_hash = [0x43u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);

        // Create proof for wrong hash
        let proof = identity.create_proof(&wrong_hash).unwrap();

        // Validation should fail (hash mismatch)
        assert!(!receipt.validate_proof(&proof, &identity));
    }

    #[test]
    fn test_validate_proof_wrong_identity() {
        let alice = new_identity();
        let bob = new_identity();
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);

        // Alice creates the proof
        let proof = alice.create_proof(&packet_hash).unwrap();

        // Bob cannot validate Alice's proof
        assert!(!receipt.validate_proof(&proof, &bob));
    }

    #[test]
    fn test_validate_proof_invalid_length() {
        let identity = new_identity();
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);

        // Too short
        assert!(!receipt.validate_proof(&[0u8; 50], &identity));

        // Too long
        assert!(!receipt.validate_proof(&[0u8; 100], &identity));
    }

    #[test]
    fn test_validate_proof_corrupted() {
        let identity = new_identity();
        let packet_hash = [0x42u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);
        let receipt = PacketReceipt::new(packet_hash, dest_hash, 1000);

        // Create valid proof, then corrupt it
        let mut proof = identity.create_proof(&packet_hash).unwrap();
        proof[50] ^= 0x01; // Flip a bit in the signature

        // Validation should fail
        assert!(!receipt.validate_proof(&proof, &identity));
    }

    #[test]
    fn test_truncated_hash_lookup() {
        // Test that receipts can be looked up by truncated hash
        let packet_hash1 = [0x42u8; 32];
        let packet_hash2 = [0x43u8; 32];
        let dest_hash = DestinationHash::new([0x01u8; 16]);

        let receipt1 = PacketReceipt::new(packet_hash1, dest_hash, 1000);
        let receipt2 = PacketReceipt::new(packet_hash2, dest_hash, 1000);

        // Different packet hashes should give different truncated hashes
        assert_ne!(receipt1.truncated_hash, receipt2.truncated_hash);

        // Truncated hash should match what we'd compute directly
        assert_eq!(receipt1.truncated_hash, truncated_hash(&packet_hash1));
    }
}
