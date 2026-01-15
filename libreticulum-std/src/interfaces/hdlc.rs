//! HDLC framing for stream-based interfaces
//!
//! Used by TCP and Serial interfaces to frame packets.
//! Format: [FLAG (0x7E)] [Escaped Data] [CRC-16] [FLAG (0x7E)]

/// HDLC flag byte
pub const FLAG: u8 = 0x7E;

/// HDLC escape byte
pub const ESCAPE: u8 = 0x7D;

/// XOR value for escaped bytes
pub const ESCAPE_XOR: u8 = 0x20;

/// CRC-16-CCITT polynomial
const CRC_POLY: u16 = 0x1021;

/// Calculate CRC-16-CCITT
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;

    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ CRC_POLY;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

/// Escape a byte if needed
fn needs_escape(byte: u8) -> bool {
    byte == FLAG || byte == ESCAPE
}

/// Frame data with HDLC encoding
pub fn frame(data: &[u8], output: &mut Vec<u8>) {
    output.clear();

    // Start flag
    output.push(FLAG);

    // Calculate CRC over unescaped data
    let crc = crc16(data);

    // Escape and write data
    for &byte in data {
        if needs_escape(byte) {
            output.push(ESCAPE);
            output.push(byte ^ ESCAPE_XOR);
        } else {
            output.push(byte);
        }
    }

    // Escape and write CRC (big-endian)
    let crc_bytes = crc.to_be_bytes();
    for &byte in &crc_bytes {
        if needs_escape(byte) {
            output.push(ESCAPE);
            output.push(byte ^ ESCAPE_XOR);
        } else {
            output.push(byte);
        }
    }

    // End flag
    output.push(FLAG);
}

/// HDLC deframer state machine
pub struct Deframer {
    buffer: Vec<u8>,
    in_frame: bool,
    escape_next: bool,
}

/// Deframing result
pub enum DeframeResult {
    /// Need more data
    NeedMore,
    /// Complete frame (without CRC, CRC verified)
    Frame(Vec<u8>),
    /// CRC error
    CrcError,
    /// Frame too short
    TooShort,
}

impl Deframer {
    /// Create a new deframer
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(600),
            in_frame: false,
            escape_next: false,
        }
    }

    /// Reset the deframer state
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.in_frame = false;
        self.escape_next = false;
    }

    /// Process incoming bytes
    pub fn process(&mut self, data: &[u8]) -> Vec<DeframeResult> {
        let mut results = Vec::new();

        for &byte in data {
            if let Some(result) = self.process_byte(byte) {
                results.push(result);
            }
        }

        results
    }

    /// Process a single byte
    fn process_byte(&mut self, byte: u8) -> Option<DeframeResult> {
        if byte == FLAG {
            if self.in_frame && !self.buffer.is_empty() {
                // End of frame
                let result = self.finalize_frame();
                self.reset();
                return Some(result);
            } else {
                // Start of frame
                self.in_frame = true;
                self.buffer.clear();
                self.escape_next = false;
            }
        } else if self.in_frame {
            if self.escape_next {
                self.buffer.push(byte ^ ESCAPE_XOR);
                self.escape_next = false;
            } else if byte == ESCAPE {
                self.escape_next = true;
            } else {
                self.buffer.push(byte);
            }
        }
        // Bytes outside of frame are ignored

        None
    }

    /// Finalize and verify a complete frame
    fn finalize_frame(&mut self) -> DeframeResult {
        // Need at least 2 bytes for CRC
        if self.buffer.len() < 2 {
            return DeframeResult::TooShort;
        }

        let data_len = self.buffer.len() - 2;
        let data = &self.buffer[..data_len];
        let received_crc =
            u16::from_be_bytes([self.buffer[data_len], self.buffer[data_len + 1]]);

        let calculated_crc = crc16(data);

        if received_crc == calculated_crc {
            DeframeResult::Frame(data.to_vec())
        } else {
            DeframeResult::CrcError
        }
    }
}

impl Default for Deframer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16() {
        // Test vector: "123456789" should give 0x29B1
        let data = b"123456789";
        let crc = crc16(data);
        assert_eq!(crc, 0x29B1);
    }

    #[test]
    fn test_frame_roundtrip() {
        let data = b"Hello, HDLC!";
        let mut framed = Vec::new();
        frame(data, &mut framed);

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);

        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(decoded, data),
            _ => panic!("Expected Frame result"),
        }
    }

    #[test]
    fn test_escape_flag_byte() {
        // Data containing FLAG byte should be escaped
        let data = [0x00, FLAG, 0xFF];
        let mut framed = Vec::new();
        frame(&data, &mut framed);

        // Check that FLAG is escaped
        assert!(framed.contains(&ESCAPE));

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);

        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(decoded.as_slice(), data),
            _ => panic!("Expected Frame result"),
        }
    }

    #[test]
    fn test_escape_escape_byte() {
        // Data containing ESCAPE byte should be escaped
        let data = [0x00, ESCAPE, 0xFF];
        let mut framed = Vec::new();
        frame(&data, &mut framed);

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);

        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(decoded.as_slice(), data),
            _ => panic!("Expected Frame result"),
        }
    }

    #[test]
    fn test_incremental_processing() {
        let data = b"Test data";
        let mut framed = Vec::new();
        frame(data, &mut framed);

        let mut deframer = Deframer::new();

        // Process byte by byte
        for (i, &byte) in framed.iter().enumerate() {
            let results = deframer.process(&[byte]);
            if i < framed.len() - 1 {
                assert!(results.is_empty());
            } else {
                assert_eq!(results.len(), 1);
            }
        }
    }
}
