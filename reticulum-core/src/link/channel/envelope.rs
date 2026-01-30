//! Channel envelope serialization
//!
//! Wire format (must match Python exactly):
//! ```text
//! [MSGTYPE: 2 bytes BE] [SEQUENCE: 2 bytes BE] [LENGTH: 2 bytes BE] [DATA: variable]
//! ```

use alloc::vec::Vec;

use super::error::ChannelError;
use crate::constants::CHANNEL_ENVELOPE_HEADER_SIZE;

/// Envelope wraps a message for transmission over a channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Message type identifier (< 0xf000 for user types)
    pub msgtype: u16,
    /// 16-bit sequence number with wraparound
    pub sequence: u16,
    /// Data payload length
    pub length: u16,
    /// Serialized message data
    pub data: Vec<u8>,
}

impl Envelope {
    /// Create a new envelope with the given message type and data
    ///
    /// # Arguments
    /// * `msgtype` - Message type identifier
    /// * `sequence` - Sequence number
    /// * `data` - Serialized message data
    pub fn new(msgtype: u16, sequence: u16, data: Vec<u8>) -> Self {
        let length = data.len() as u16;
        Self {
            msgtype,
            sequence,
            length,
            data,
        }
    }

    /// Pack the envelope into bytes for transmission
    ///
    /// Format: [MSGTYPE: 2 BE] [SEQUENCE: 2 BE] [LENGTH: 2 BE] [DATA: variable]
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CHANNEL_ENVELOPE_HEADER_SIZE + self.data.len());
        buf.extend_from_slice(&self.msgtype.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Unpack an envelope from bytes
    ///
    /// # Arguments
    /// * `raw` - Raw bytes containing the envelope
    ///
    /// # Errors
    /// Returns `InvalidEnvelope` if the data is too short or length doesn't match
    pub fn unpack(raw: &[u8]) -> Result<Self, ChannelError> {
        if raw.len() < CHANNEL_ENVELOPE_HEADER_SIZE {
            return Err(ChannelError::InvalidEnvelope);
        }

        let msgtype = u16::from_be_bytes([raw[0], raw[1]]);
        let sequence = u16::from_be_bytes([raw[2], raw[3]]);
        let length = u16::from_be_bytes([raw[4], raw[5]]);

        let expected_len = CHANNEL_ENVELOPE_HEADER_SIZE + length as usize;
        if raw.len() < expected_len {
            return Err(ChannelError::InvalidEnvelope);
        }

        let data = raw[CHANNEL_ENVELOPE_HEADER_SIZE..expected_len].to_vec();

        Ok(Self {
            msgtype,
            sequence,
            length,
            data,
        })
    }

    /// Get the total packed size of this envelope
    pub fn packed_size(&self) -> usize {
        CHANNEL_ENVELOPE_HEADER_SIZE + self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_envelope_pack_unpack_roundtrip() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let envelope = Envelope::new(0x1234, 0x5678, data.clone());

        let packed = envelope.pack();
        assert_eq!(packed.len(), CHANNEL_ENVELOPE_HEADER_SIZE + 4);

        // Check header bytes
        assert_eq!(packed[0..2], [0x12, 0x34]); // msgtype BE
        assert_eq!(packed[2..4], [0x56, 0x78]); // sequence BE
        assert_eq!(packed[4..6], [0x00, 0x04]); // length BE
        assert_eq!(&packed[6..], &data); // data

        let unpacked = Envelope::unpack(&packed).unwrap();
        assert_eq!(unpacked.msgtype, 0x1234);
        assert_eq!(unpacked.sequence, 0x5678);
        assert_eq!(unpacked.length, 4);
        assert_eq!(unpacked.data, data);
    }

    #[test]
    fn test_envelope_empty_data() {
        let envelope = Envelope::new(0x0001, 0x0000, Vec::new());
        let packed = envelope.pack();
        assert_eq!(packed.len(), CHANNEL_ENVELOPE_HEADER_SIZE);

        let unpacked = Envelope::unpack(&packed).unwrap();
        assert_eq!(unpacked.msgtype, 0x0001);
        assert_eq!(unpacked.sequence, 0x0000);
        assert_eq!(unpacked.length, 0);
        assert!(unpacked.data.is_empty());
    }

    #[test]
    fn test_envelope_max_sequence() {
        let envelope = Envelope::new(0xefff, 0xffff, vec![0xAA]);
        let packed = envelope.pack();

        let unpacked = Envelope::unpack(&packed).unwrap();
        assert_eq!(unpacked.msgtype, 0xefff);
        assert_eq!(unpacked.sequence, 0xffff);
    }

    #[test]
    fn test_envelope_unpack_too_short() {
        let short = [0x00, 0x01, 0x00];
        assert_eq!(Envelope::unpack(&short), Err(ChannelError::InvalidEnvelope));
    }

    #[test]
    fn test_envelope_unpack_header_only() {
        // Valid header but declares 4 bytes of data with none present
        let header_only = [0x00, 0x01, 0x00, 0x02, 0x00, 0x04];
        assert_eq!(
            Envelope::unpack(&header_only),
            Err(ChannelError::InvalidEnvelope)
        );
    }

    #[test]
    fn test_envelope_unpack_truncated_data() {
        // Header says 4 bytes but only 2 present
        let truncated = [0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0xAA, 0xBB];
        assert_eq!(
            Envelope::unpack(&truncated),
            Err(ChannelError::InvalidEnvelope)
        );
    }

    #[test]
    fn test_envelope_packed_size() {
        let envelope = Envelope::new(0x0001, 0x0000, vec![0; 100]);
        assert_eq!(envelope.packed_size(), CHANNEL_ENVELOPE_HEADER_SIZE + 100);
    }
}
