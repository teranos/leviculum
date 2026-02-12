//! Channel system for reliable, bidirectional message delivery over Links
//!
//! Channels provide:
//! - Reliability (automatic retries)
//! - Ordering (16-bit sequence numbers)
//! - Message framing (typed messages with registration)
//! - Flow control (window-based congestion control)
//!
//! # Wire Format
//!
//! ```text
//! [MSGTYPE: 2 bytes BE] [SEQUENCE: 2 bytes BE] [LENGTH: 2 bytes BE] [DATA: variable]
//! ```
//!
//! # Example
//!
//! ```
//! use reticulum_core::link::channel::{Channel, Message, ChannelError};
//!
//! // Define a custom message type
//! struct MyMessage { data: Vec<u8> }
//!
//! impl Message for MyMessage {
//!     const MSGTYPE: u16 = 0x0001;
//!     fn pack(&self) -> Vec<u8> { self.data.clone() }
//!     fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
//!         Ok(Self { data: data.to_vec() })
//!     }
//! }
//!
//! // Create channel and send message
//! let mut channel = Channel::new();
//! let msg = MyMessage { data: vec![1, 2, 3] };
//! let packet_data = channel.send(&msg, 400, 1000, 100).unwrap();
//! assert!(!packet_data.is_empty());
//! ```

mod buffer;
mod envelope;
mod error;
mod stream;

pub use buffer::{
    max_data_len, stream_overhead, BufferedChannelWriter, RawChannelReader, RawChannelWriter,
    ReadResult, MAX_CHUNK_LEN,
};
#[cfg(feature = "compression")]
pub use buffer::{CompressingWriter, COMPRESSION_MIN_SIZE, COMPRESSION_TRIES, MAX_DECOMPRESS_SIZE};
pub use envelope::Envelope;
pub use error::ChannelError;
pub use stream::StreamDataMessage;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::constants::{
    CHANNEL_BACKOFF_BASE, CHANNEL_ENVELOPE_HEADER_SIZE, CHANNEL_MAX_TRIES,
    CHANNEL_MIN_TIMEOUT_BASE_MS, CHANNEL_MSGTYPE_RESERVED, CHANNEL_QUEUE_LEN_ADJUSTMENT,
    CHANNEL_RTT_FAST_MS, CHANNEL_RTT_MEDIUM_MS, CHANNEL_RTT_TIMEOUT_MULTIPLIER,
    CHANNEL_SEQ_MODULUS, CHANNEL_WINDOW_INITIAL, CHANNEL_WINDOW_MAX_FAST,
    CHANNEL_WINDOW_MAX_MEDIUM, CHANNEL_WINDOW_MAX_SLOW, CHANNEL_WINDOW_MIN_FAST,
    CHANNEL_WINDOW_MIN_SLOW,
};

/// Calculate f64 power for small non-negative integer exponents
///
/// This is a no_std compatible implementation of `f64::powf()`. In no_std
/// environments, the standard library's `f64::powf()` is not available
/// because it relies on the system's math library (libm).
///
/// For the channel timeout formula, exponents are always small non-negative
/// integers (typically 0-5), so simple iterative multiplication is sufficient
/// and more efficient than a general power function.
///
/// # Arguments
/// * `base` - The base value
/// * `exp` - The exponent (must be a small non-negative integer)
///
/// # Example
/// ```text
/// pow_f64(1.5, 0) == 1.0
/// pow_f64(1.5, 1) == 1.5
/// pow_f64(1.5, 2) == 2.25
/// ```
fn pow_f64(base: f64, exp: u32) -> f64 {
    let mut result = 1.0;
    for _ in 0..exp {
        result *= base;
    }
    result
}

/// Message trait - all channel messages must implement this
pub trait Message: Sized {
    /// Unique message type identifier (< 0xf000)
    const MSGTYPE: u16;

    /// Pack message into bytes
    fn pack(&self) -> Vec<u8>;

    /// Unpack message from bytes
    fn unpack(data: &[u8]) -> Result<Self, ChannelError>;
}

/// Message delivery state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    /// Message created but not yet sent
    New,
    /// Message sent, awaiting acknowledgment
    Sent,
    /// Message delivery confirmed
    Delivered,
    /// Message delivery failed (max retries exceeded)
    Failed,
}

/// Outbound envelope tracking
#[derive(Debug)]
struct OutboundEnvelope {
    /// The envelope data
    envelope: Envelope,
    /// Current delivery state
    state: MessageState,
    /// Number of transmission attempts
    tries: u8,
    /// When the envelope was last sent (milliseconds)
    sent_at_ms: u64,
    /// When the envelope will timeout (milliseconds)
    timeout_at_ms: u64,
}

impl OutboundEnvelope {
    fn new(envelope: Envelope) -> Self {
        Self {
            envelope,
            state: MessageState::New,
            tries: 0,
            sent_at_ms: 0,
            timeout_at_ms: 0,
        }
    }
}

/// Actions that may need to be taken after polling
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelAction {
    /// Retransmit this packet data
    Retransmit {
        /// Sequence number of the envelope
        sequence: u16,
        /// Packed envelope data to transmit
        data: Vec<u8>,
    },
    /// Link should be torn down (max retries exceeded)
    TearDownLink,
}

/// Channel for reliable message delivery over a Link
#[derive(Debug)]
pub struct Channel {
    /// Next sequence number to use for outgoing messages
    next_tx_sequence: u16,
    /// Next expected sequence number for incoming messages
    next_rx_sequence: u16,
    /// Outbound envelopes awaiting acknowledgment
    tx_ring: VecDeque<OutboundEnvelope>,
    /// Inbound envelopes received out of order
    rx_ring: VecDeque<Option<Envelope>>,
    /// Current window size
    window: usize,
    /// Minimum window size
    window_min: usize,
    /// Maximum window size
    window_max: usize,
    /// Maximum transmission attempts
    max_tries: u8,
}

impl Default for Channel {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel {
    /// Create a new channel with default settings
    pub fn new() -> Self {
        Self {
            next_tx_sequence: 0,
            next_rx_sequence: 0,
            tx_ring: VecDeque::new(),
            rx_ring: VecDeque::new(),
            window: CHANNEL_WINDOW_INITIAL,
            window_min: CHANNEL_WINDOW_MIN_SLOW,
            window_max: CHANNEL_WINDOW_MAX_SLOW,
            max_tries: CHANNEL_MAX_TRIES,
        }
    }

    /// Check if the channel is ready to send more messages
    ///
    /// Returns false if the send window is full.
    pub fn is_ready_to_send(&self) -> bool {
        self.tx_ring.len() < self.window
    }

    /// Get the maximum data unit for channel messages
    ///
    /// This is the link MDU minus the envelope header size.
    pub fn mdu(&self, link_mdu: usize) -> usize {
        link_mdu.saturating_sub(CHANNEL_ENVELOPE_HEADER_SIZE)
    }

    /// Get the current window size
    pub fn window(&self) -> usize {
        self.window
    }

    /// Get the maximum window size
    pub fn window_max(&self) -> usize {
        self.window_max
    }

    /// Get the number of outstanding (unacknowledged) messages
    pub fn outstanding(&self) -> usize {
        self.tx_ring.len()
    }

    /// Get the next transmit sequence number (without incrementing)
    pub fn next_tx_sequence(&self) -> u16 {
        self.next_tx_sequence
    }

    /// Get the next expected receive sequence number
    pub fn next_rx_sequence(&self) -> u16 {
        self.next_rx_sequence
    }

    /// Get the sequence number of the most recently sent message
    ///
    /// This wraps around correctly at the sequence modulus boundary.
    pub fn last_sent_sequence(&self) -> u16 {
        if self.next_tx_sequence == 0 {
            (CHANNEL_SEQ_MODULUS - 1) as u16
        } else {
            self.next_tx_sequence - 1
        }
    }

    /// Update window limits based on RTT
    ///
    /// Faster links get larger windows for better throughput.
    pub fn update_window_for_rtt(&mut self, rtt_ms: u64) {
        if rtt_ms < CHANNEL_RTT_FAST_MS {
            self.window_min = CHANNEL_WINDOW_MIN_FAST;
            self.window_max = CHANNEL_WINDOW_MAX_FAST;
        } else if rtt_ms < CHANNEL_RTT_MEDIUM_MS {
            self.window_min = CHANNEL_WINDOW_MIN_SLOW;
            self.window_max = CHANNEL_WINDOW_MAX_MEDIUM;
        } else {
            self.window_min = CHANNEL_WINDOW_MIN_SLOW;
            self.window_max = CHANNEL_WINDOW_MAX_SLOW;
        }
        // Clamp current window to new limits
        self.window = self.window.clamp(self.window_min, self.window_max);
    }

    /// Get the next sequence number and increment the counter
    fn next_sequence(&mut self) -> u16 {
        let seq = self.next_tx_sequence;
        self.next_tx_sequence = ((self.next_tx_sequence as u32 + 1) % CHANNEL_SEQ_MODULUS) as u16;
        seq
    }

    /// Validate a message type
    fn validate_msgtype(msgtype: u16) -> Result<(), ChannelError> {
        if msgtype >= CHANNEL_MSGTYPE_RESERVED {
            return Err(ChannelError::InvalidMsgType);
        }
        Ok(())
    }

    /// Send a message on the channel
    ///
    /// Returns the packed envelope data to be encrypted and sent over the link.
    ///
    /// # Arguments
    /// * `message` - The message to send
    /// * `link_mdu` - Maximum data unit for the link
    /// * `now_ms` - Current time in milliseconds
    /// * `rtt_ms` - Round-trip time in milliseconds
    ///
    /// # Errors
    /// - `InvalidMsgType` if the message type is reserved (>= 0xf000)
    /// - `TooLarge` if the message exceeds the channel MDU
    /// - `WindowFull` if the send window is full
    pub fn send<M: Message>(
        &mut self,
        message: &M,
        link_mdu: usize,
        now_ms: u64,
        rtt_ms: u64,
    ) -> Result<Vec<u8>, ChannelError> {
        Self::validate_msgtype(M::MSGTYPE)?;
        self.send_internal(M::MSGTYPE, &message.pack(), link_mdu, now_ms, rtt_ms)
    }

    /// Send a system message on the channel (bypasses MSGTYPE validation)
    ///
    /// This method is for system messages (MSGTYPE >= 0xf000) like StreamDataMessage.
    /// Unlike `send()`, it does not validate that the message type is in the user range.
    ///
    /// # Arguments
    /// * `message` - The system message to send
    /// * `link_mdu` - Maximum data unit for the link
    /// * `now_ms` - Current time in milliseconds
    /// * `rtt_ms` - Round-trip time in milliseconds
    ///
    /// # Errors
    /// - `TooLarge` if the message exceeds the channel MDU
    /// - `WindowFull` if the send window is full
    pub fn send_system<M: Message>(
        &mut self,
        message: &M,
        link_mdu: usize,
        now_ms: u64,
        rtt_ms: u64,
    ) -> Result<Vec<u8>, ChannelError> {
        self.send_internal(M::MSGTYPE, &message.pack(), link_mdu, now_ms, rtt_ms)
    }

    /// Internal send implementation used by both send() and send_system()
    fn send_internal(
        &mut self,
        msgtype: u16,
        data: &[u8],
        link_mdu: usize,
        now_ms: u64,
        rtt_ms: u64,
    ) -> Result<Vec<u8>, ChannelError> {
        let mdu = self.mdu(link_mdu);

        if data.len() > mdu {
            return Err(ChannelError::TooLarge);
        }

        if !self.is_ready_to_send() {
            tracing::debug!(
                tx_ring = self.tx_ring.len(),
                window = self.window,
                window_max = self.window_max,
                "channel: WindowFull — send rejected"
            );
            return Err(ChannelError::WindowFull);
        }

        let sequence = self.next_sequence();
        let envelope = Envelope::new(msgtype, sequence, data.to_vec());
        let packed = envelope.pack();

        let queue_len = self.tx_ring.len();
        let timeout_ms = self.calculate_timeout_ms(1, rtt_ms, queue_len);
        let mut outbound = OutboundEnvelope::new(envelope);
        outbound.state = MessageState::Sent;
        outbound.tries = 1;
        outbound.sent_at_ms = now_ms;
        outbound.timeout_at_ms = now_ms.saturating_add(timeout_ms);

        self.tx_ring.push_back(outbound);

        tracing::debug!(
            seq = sequence,
            tx_ring = self.tx_ring.len(),
            window = self.window,
            window_max = self.window_max,
            timeout_ms,
            "channel: sent"
        );

        Ok(packed)
    }

    /// Receive decrypted channel data from link
    ///
    /// Returns the envelope if it's the next expected in sequence,
    /// or None if it's out of order (will be buffered).
    ///
    /// # Arguments
    /// * `data` - Decrypted envelope data from the link
    pub fn receive(&mut self, data: &[u8]) -> Result<Option<Envelope>, ChannelError> {
        let envelope = Envelope::unpack(data)?;

        // Check if this is the next expected sequence
        if envelope.sequence == self.next_rx_sequence {
            self.next_rx_sequence =
                ((self.next_rx_sequence as u32 + 1) % CHANNEL_SEQ_MODULUS) as u16;

            // Pop placeholder from front of rx_ring if present (we just consumed this slot)
            if !self.rx_ring.is_empty() {
                self.rx_ring.pop_front();
            }

            return Ok(Some(envelope));
        }

        // Calculate the offset from expected sequence (handling wraparound)
        let offset = self.sequence_offset(envelope.sequence);

        // If offset is too large, this might be a very old or invalid packet
        if offset >= self.window_max * 2 {
            // Treat as duplicate or invalid
            return Ok(None);
        }

        // Buffer the out-of-order envelope
        while self.rx_ring.len() <= offset {
            self.rx_ring.push_back(None);
        }
        self.rx_ring[offset] = Some(envelope);

        Ok(None)
    }

    /// Calculate sequence offset accounting for wraparound
    fn sequence_offset(&self, sequence: u16) -> usize {
        let expected = self.next_rx_sequence as u32;
        let received = sequence as u32;

        if received >= expected {
            (received - expected) as usize
        } else {
            // Wraparound case
            (CHANNEL_SEQ_MODULUS - expected + received) as usize
        }
    }

    /// Receive and unpack a typed message from the channel
    ///
    /// This is the symmetric counterpart to `send<M>()`. It receives an envelope
    /// and unpacks it into the specified message type.
    ///
    /// # Arguments
    /// * `data` - Decrypted envelope data from the link
    ///
    /// # Returns
    /// - `Ok(Some(msg))` if a message was received and unpacked in sequence
    /// - `Ok(None)` if the message was buffered (out of order) or invalid type
    /// - `Err(...)` if unpacking failed
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum_core::link::channel::{Channel, Message, ChannelError};
    ///
    /// struct MyMessage { data: Vec<u8> }
    /// impl Message for MyMessage {
    ///     const MSGTYPE: u16 = 0x0001;
    ///     fn pack(&self) -> Vec<u8> { self.data.clone() }
    ///     fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
    ///         Ok(Self { data: data.to_vec() })
    ///     }
    /// }
    ///
    /// // Sender
    /// let mut sender = Channel::new();
    /// let packet_data = sender.send(&MyMessage { data: vec![1, 2, 3] }, 400, 1000, 100).unwrap();
    ///
    /// // Receiver
    /// let mut receiver = Channel::new();
    /// if let Some(msg) = receiver.receive_message::<MyMessage>(&packet_data).unwrap() {
    ///     assert_eq!(msg.data, vec![1, 2, 3]);
    /// }
    /// ```
    pub fn receive_message<M: Message>(&mut self, data: &[u8]) -> Result<Option<M>, ChannelError> {
        // First receive the envelope
        let envelope = match self.receive(data)? {
            Some(env) => env,
            None => return Ok(None), // Buffered or invalid
        };

        // Check message type
        if envelope.msgtype != M::MSGTYPE {
            // Wrong type - this could be a different message type
            // We've already consumed it from the sequence, so return None
            return Ok(None);
        }

        // Unpack the message
        let msg = M::unpack(&envelope.data)?;
        Ok(Some(msg))
    }

    /// Drain received messages that are ready (in sequence order)
    ///
    /// Call this after `receive()` to get any buffered messages that
    /// are now in sequence.
    pub fn drain_received(&mut self) -> Vec<Envelope> {
        let mut ready = Vec::new();

        while let Some(front) = self.rx_ring.front() {
            match front {
                Some(envelope) if envelope.sequence == self.next_rx_sequence => {
                    if let Some(Some(env)) = self.rx_ring.pop_front() {
                        self.next_rx_sequence =
                            ((self.next_rx_sequence as u32 + 1) % CHANNEL_SEQ_MODULUS) as u16;
                        ready.push(env);
                    }
                }
                None => {
                    // Placeholder for a message we haven't received yet - stop draining
                    break;
                }
                Some(_) => {
                    // Message with wrong sequence (shouldn't happen with proper buffering)
                    break;
                }
            }
        }

        ready
    }

    /// Mark an envelope as delivered (ACK received)
    ///
    /// This removes the envelope from the TX ring and adjusts the window.
    ///
    /// # Arguments
    /// * `sequence` - Sequence number of the delivered envelope
    /// * `rtt_ms` - Current RTT in milliseconds (for window adjustment)
    ///
    /// # Returns
    /// `true` if the ACK was for a known pending envelope, `false` otherwise
    /// (e.g., duplicate ACK or ACK for unknown sequence).
    pub fn mark_delivered(&mut self, sequence: u16, rtt_ms: u64) -> bool {
        if let Some(pos) = self
            .tx_ring
            .iter()
            .position(|e| e.envelope.sequence == sequence)
        {
            self.tx_ring.remove(pos);
            self.adjust_window(true, rtt_ms);
            tracing::debug!(
                seq = sequence,
                tx_ring = self.tx_ring.len(),
                window = self.window,
                "channel: delivered"
            );
            true
        } else {
            tracing::debug!(
                seq = sequence,
                tx_ring = self.tx_ring.len(),
                "channel: delivered — seq not found (duplicate ACK?)"
            );
            false
        }
    }

    /// Calculate timeout using Python Reticulum formula
    ///
    /// Formula: BACKOFF_BASE^(tries-1) * max(rtt*RTT_MULTIPLIER, MIN_TIMEOUT) * (queue_len+QUEUE_ADJ)
    fn calculate_timeout_ms(&self, tries: u8, rtt_ms: u64, queue_len: usize) -> u64 {
        let base_timeout =
            (rtt_ms as f64 * CHANNEL_RTT_TIMEOUT_MULTIPLIER).max(CHANNEL_MIN_TIMEOUT_BASE_MS);
        let retry_factor = pow_f64(CHANNEL_BACKOFF_BASE, tries.saturating_sub(1) as u32);
        let queue_factor = queue_len as f64 + CHANNEL_QUEUE_LEN_ADJUSTMENT;

        (base_timeout * retry_factor * queue_factor) as u64
    }

    /// Poll for timeouts and get actions to take
    ///
    /// Call this periodically to check for timed-out envelopes.
    ///
    /// # Arguments
    /// * `now_ms` - Current time in milliseconds
    /// * `rtt_ms` - Round-trip time in milliseconds
    pub fn poll(&mut self, now_ms: u64, rtt_ms: u64) -> Vec<ChannelAction> {
        let mut actions = Vec::new();
        let mut window_decrements = 0usize;

        // Collect queue length once at start (used for timeout calculation)
        let queue_len = self.tx_ring.len();

        // First pass: collect indices that need processing and their current tries
        let mut timed_out: Vec<(usize, u8)> = Vec::new();
        for (i, outbound) in self.tx_ring.iter().enumerate() {
            if outbound.state == MessageState::Sent && now_ms >= outbound.timeout_at_ms {
                timed_out.push((i, outbound.tries));
            }
        }

        // Second pass: process timed out envelopes
        for (i, tries) in timed_out {
            // Timeout occurred
            if tries >= self.max_tries {
                let seq = self.tx_ring[i].envelope.sequence;
                tracing::debug!(
                    seq,
                    tries,
                    max_tries = self.max_tries,
                    "channel: max retries exceeded — tearing down link"
                );
                self.tx_ring[i].state = MessageState::Failed;
                actions.push(ChannelAction::TearDownLink);
                window_decrements += 1;
                break; // Link is being torn down, no point continuing
            }

            // Calculate new timeout before mutating
            let new_tries = tries + 1;
            let timeout_ms = self.calculate_timeout_ms(new_tries, rtt_ms, queue_len);

            // Now mutate the outbound envelope
            let outbound = &mut self.tx_ring[i];
            outbound.tries = new_tries;
            outbound.sent_at_ms = now_ms;
            outbound.timeout_at_ms = now_ms.saturating_add(timeout_ms);
            tracing::debug!(
                seq = outbound.envelope.sequence,
                attempt = new_tries,
                timeout_ms,
                tx_ring = queue_len,
                window = self.window,
                "channel: retransmitting"
            );

            actions.push(ChannelAction::Retransmit {
                sequence: outbound.envelope.sequence,
                data: outbound.envelope.pack(),
            });

            window_decrements += 1;
        }

        // Apply window adjustments after iteration is complete
        for _ in 0..window_decrements {
            self.adjust_window(false, rtt_ms);
        }

        actions
    }

    /// Adjust window based on transmission success/failure
    fn adjust_window(&mut self, success: bool, rtt_ms: u64) {
        // First update limits based on RTT
        self.update_window_for_rtt(rtt_ms);

        if success {
            // Increase window on success
            if self.window < self.window_max {
                self.window += 1;
            }
        } else {
            // Decrease window on failure
            if self.window > self.window_min {
                self.window = self.window.saturating_sub(1);
            }
        }
    }

    /// Clear all pending outbound envelopes
    pub fn clear_tx(&mut self) {
        self.tx_ring.clear();
    }

    /// Clear all pending inbound envelopes
    pub fn clear_rx(&mut self) {
        self.rx_ring.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Test message implementation
    struct TestMessage {
        data: Vec<u8>,
    }

    impl Message for TestMessage {
        const MSGTYPE: u16 = 0x0001;

        fn pack(&self) -> Vec<u8> {
            self.data.clone()
        }

        fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
            Ok(Self {
                data: data.to_vec(),
            })
        }
    }

    #[test]
    fn test_channel_new() {
        let channel = Channel::new();
        assert_eq!(channel.next_tx_sequence, 0);
        assert_eq!(channel.next_rx_sequence, 0);
        assert_eq!(channel.window, CHANNEL_WINDOW_INITIAL);
        assert!(channel.is_ready_to_send());
    }

    #[test]
    fn test_sequence_increment() {
        let mut channel = Channel::new();
        assert_eq!(channel.next_sequence(), 0);
        assert_eq!(channel.next_sequence(), 1);
        assert_eq!(channel.next_sequence(), 2);
    }

    #[test]
    fn test_sequence_wraparound() {
        let mut channel = Channel::new();
        channel.next_tx_sequence = 0xFFFF;
        assert_eq!(channel.next_sequence(), 0xFFFF);
        assert_eq!(channel.next_sequence(), 0);
        assert_eq!(channel.next_sequence(), 1);
    }

    #[test]
    fn test_mdu_calculation() {
        let channel = Channel::new();
        let link_mdu = 464;
        let expected = link_mdu - CHANNEL_ENVELOPE_HEADER_SIZE;
        assert_eq!(channel.mdu(link_mdu), expected);
    }

    #[test]
    fn test_send_basic() {
        let mut channel = Channel::new();
        let msg = TestMessage {
            data: vec![1, 2, 3],
        };
        let result = channel.send(&msg, 464, 1000, 100);
        assert!(result.is_ok());

        let packed = result.unwrap();
        assert_eq!(packed.len(), CHANNEL_ENVELOPE_HEADER_SIZE + 3);

        // Check envelope contents
        let envelope = Envelope::unpack(&packed).unwrap();
        assert_eq!(envelope.msgtype, TestMessage::MSGTYPE);
        assert_eq!(envelope.sequence, 0);
        assert_eq!(envelope.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_send_too_large() {
        let mut channel = Channel::new();
        let msg = TestMessage {
            data: vec![0; 1000],
        };
        let result = channel.send(&msg, 100, 1000, 100);
        assert_eq!(result, Err(ChannelError::TooLarge));
    }

    #[test]
    fn test_send_window_full() {
        let mut channel = Channel::new();
        channel.window = 1;

        let msg = TestMessage { data: vec![1] };

        // First send should succeed
        assert!(channel.send(&msg, 464, 1000, 100).is_ok());

        // Second send should fail (window full)
        assert_eq!(
            channel.send(&msg, 464, 1000, 100),
            Err(ChannelError::WindowFull)
        );
    }

    #[test]
    fn test_invalid_msgtype() {
        struct ReservedMessage;
        impl Message for ReservedMessage {
            const MSGTYPE: u16 = 0xf000;
            fn pack(&self) -> Vec<u8> {
                Vec::new()
            }
            fn unpack(_: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self)
            }
        }

        let mut channel = Channel::new();
        let result = channel.send(&ReservedMessage, 464, 1000, 100);
        assert_eq!(result, Err(ChannelError::InvalidMsgType));
    }

    #[test]
    fn test_receive_in_order() {
        let mut channel = Channel::new();

        let envelope = Envelope::new(0x0001, 0, vec![1, 2, 3]);
        let packed = envelope.pack();

        let result = channel.receive(&packed);
        assert!(result.is_ok());
        let received = result.unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().sequence, 0);
        assert_eq!(channel.next_rx_sequence, 1);
    }

    #[test]
    fn test_receive_out_of_order() {
        let mut channel = Channel::new();

        // Receive sequence 1 first (out of order)
        let envelope1 = Envelope::new(0x0001, 1, vec![2]);
        let result = channel.receive(&envelope1.pack());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Buffered
        assert_eq!(channel.next_rx_sequence, 0); // Still expecting 0

        // Now receive sequence 0
        let envelope0 = Envelope::new(0x0001, 0, vec![1]);
        let result = channel.receive(&envelope0.pack());
        assert!(result.is_ok());
        let received = result.unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().sequence, 0);
        assert_eq!(channel.next_rx_sequence, 1);

        // Drain should give us sequence 1
        let drained = channel.drain_received();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].sequence, 1);
        assert_eq!(channel.next_rx_sequence, 2);
    }

    #[test]
    fn test_mark_delivered() {
        let mut channel = Channel::new();
        let msg = TestMessage { data: vec![1] };

        channel.send(&msg, 464, 1000, 100).unwrap();
        assert_eq!(channel.outstanding(), 1);

        // Should return true for known sequence
        assert!(channel.mark_delivered(0, 100));
        assert_eq!(channel.outstanding(), 0);

        // Should return false for unknown sequence
        assert!(!channel.mark_delivered(0, 100));
        assert!(!channel.mark_delivered(999, 100));
    }

    #[test]
    fn test_poll_timeout() {
        let mut channel = Channel::new();
        let msg = TestMessage { data: vec![1] };

        // Send message at time 1000
        channel.send(&msg, 464, 1000, 100).unwrap();

        // Poll before timeout - no actions
        let actions = channel.poll(1000, 100);
        assert!(actions.is_empty());

        // Poll after timeout - should get retransmit
        let actions = channel.poll(100_000, 100);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ChannelAction::Retransmit { sequence, .. } => {
                assert_eq!(*sequence, 0);
            }
            _ => panic!("Expected Retransmit action"),
        }
    }

    #[test]
    fn test_poll_max_retries() {
        let mut channel = Channel::new();
        channel.max_tries = 2;
        let msg = TestMessage { data: vec![1] };

        channel.send(&msg, 464, 0, 100).unwrap();

        // First timeout - retransmit
        let actions = channel.poll(10_000, 100);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], ChannelAction::Retransmit { .. }));

        // Second timeout - tear down
        let actions = channel.poll(100_000, 100);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], ChannelAction::TearDownLink));
    }

    #[test]
    fn test_window_adjustment_on_rtt() {
        let mut channel = Channel::new();

        // Fast RTT should increase max window
        channel.update_window_for_rtt(100);
        assert_eq!(channel.window_max, CHANNEL_WINDOW_MAX_FAST);

        // Medium RTT
        channel.update_window_for_rtt(500);
        assert_eq!(channel.window_max, CHANNEL_WINDOW_MAX_MEDIUM);

        // Slow RTT
        channel.update_window_for_rtt(2000);
        assert_eq!(channel.window_max, CHANNEL_WINDOW_MAX_SLOW);
    }

    #[test]
    fn test_timeout_formula() {
        let channel = Channel::new();

        // Basic timeout: max(100*2.5, 25) * 1.5^0 * (0+1.5) = 250 * 1 * 1.5 = 375
        let timeout = channel.calculate_timeout_ms(1, 100, 0);
        assert_eq!(timeout, 375);

        // With retries: 250 * 1.5^1 * 1.5 = 562.5
        let timeout = channel.calculate_timeout_ms(2, 100, 0);
        assert_eq!(timeout, 562);
    }

    #[test]
    fn test_send_system_allows_reserved_msgtype() {
        // send_system should allow system message types (>= 0xf000)
        let msg = StreamDataMessage::new(0, vec![1, 2, 3], false, false);

        let mut channel = Channel::new();
        let result = channel.send_system(&msg, 464, 1000, 100);
        assert!(result.is_ok(), "send_system should allow reserved MSGTYPE");

        let packed = result.unwrap();
        let envelope = Envelope::unpack(&packed).unwrap();
        assert_eq!(envelope.msgtype, StreamDataMessage::MSGTYPE);
        assert_eq!(envelope.msgtype, 0xff00);
    }

    #[test]
    fn test_send_rejects_system_msgtype() {
        // Regular send() should reject system message types
        let msg = StreamDataMessage::new(0, vec![1, 2, 3], false, false);

        let mut channel = Channel::new();
        let result = channel.send(&msg, 464, 1000, 100);
        assert_eq!(
            result,
            Err(ChannelError::InvalidMsgType),
            "send should reject reserved MSGTYPE"
        );
    }

    #[test]
    fn test_send_system_respects_window() {
        let mut channel = Channel::new();
        channel.window = 1;

        let msg = StreamDataMessage::new(0, vec![1], false, false);

        // First send should succeed
        assert!(channel.send_system(&msg, 464, 1000, 100).is_ok());

        // Second send should fail (window full)
        assert_eq!(
            channel.send_system(&msg, 464, 1000, 100),
            Err(ChannelError::WindowFull)
        );
    }

    #[test]
    fn test_window_max_accessor() {
        let mut channel = Channel::new();
        assert_eq!(channel.window_max(), CHANNEL_WINDOW_MAX_SLOW);

        channel.update_window_for_rtt(100);
        assert_eq!(channel.window_max(), CHANNEL_WINDOW_MAX_FAST);

        channel.update_window_for_rtt(500);
        assert_eq!(channel.window_max(), CHANNEL_WINDOW_MAX_MEDIUM);
    }

    #[test]
    fn test_send_system_respects_mdu() {
        let mut channel = Channel::new();
        let msg = StreamDataMessage::new(0, vec![0; 1000], false, false);

        // With small MDU, should fail
        let result = channel.send_system(&msg, 100, 1000, 100);
        assert_eq!(result, Err(ChannelError::TooLarge));
    }

    #[test]
    fn test_channel_receive_message_typed() {
        let mut sender = Channel::new();
        let mut receiver = Channel::new();

        let msg = TestMessage {
            data: vec![1, 2, 3, 4],
        };

        // Send message
        let packed = sender.send(&msg, 464, 1000, 100).unwrap();

        // Receive using typed API
        let received: Option<TestMessage> = receiver.receive_message(&packed).unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_channel_send_receive_symmetric() {
        // Test the complete symmetric workflow: send<M> -> receive_message<M>
        let mut sender = Channel::new();
        let mut receiver = Channel::new();

        // Send multiple messages
        let msg1 = TestMessage {
            data: vec![10, 20, 30],
        };
        let msg2 = TestMessage {
            data: vec![40, 50, 60],
        };

        let packed1 = sender.send(&msg1, 464, 1000, 100).unwrap();
        let packed2 = sender.send(&msg2, 464, 2000, 100).unwrap();

        // Receive in order
        let r1: Option<TestMessage> = receiver.receive_message(&packed1).unwrap();
        assert!(r1.is_some());
        assert_eq!(r1.unwrap().data, vec![10, 20, 30]);

        let r2: Option<TestMessage> = receiver.receive_message(&packed2).unwrap();
        assert!(r2.is_some());
        assert_eq!(r2.unwrap().data, vec![40, 50, 60]);
    }

    #[test]
    fn test_channel_receive_message_wrong_type() {
        // Define a different message type
        struct OtherMessage {
            value: u8,
        }

        impl Message for OtherMessage {
            const MSGTYPE: u16 = 0x9999;

            fn pack(&self) -> Vec<u8> {
                vec![self.value]
            }

            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                if data.is_empty() {
                    return Err(ChannelError::EnvelopeTruncated);
                }
                Ok(Self { value: data[0] })
            }
        }

        let mut sender = Channel::new();
        let mut receiver = Channel::new();

        // Send OtherMessage
        let msg = OtherMessage { value: 42 };
        let packed = sender.send(&msg, 464, 1000, 100).unwrap();

        // Try to receive as TestMessage - should return None (type mismatch)
        let result: Option<TestMessage> = receiver.receive_message(&packed).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_channel_receive_message_out_of_order() {
        let mut sender = Channel::new();
        let mut receiver = Channel::new();

        let msg0 = TestMessage { data: vec![0] };
        let msg1 = TestMessage { data: vec![1] };

        let packed0 = sender.send(&msg0, 464, 1000, 100).unwrap();
        let packed1 = sender.send(&msg1, 464, 2000, 100).unwrap();

        // Receive out of order (msg1 first)
        let r1: Option<TestMessage> = receiver.receive_message(&packed1).unwrap();
        assert!(r1.is_none()); // Should be buffered

        // Now receive msg0
        let r0: Option<TestMessage> = receiver.receive_message(&packed0).unwrap();
        assert!(r0.is_some());
        assert_eq!(r0.unwrap().data, vec![0]);

        // Drain should give us msg1
        let drained = receiver.drain_received();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].data, vec![1]);
    }
}
