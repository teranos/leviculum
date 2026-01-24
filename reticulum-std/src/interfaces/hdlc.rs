//! HDLC framing for stream-based interfaces
//!
//! Used by TCP and Serial interfaces to frame packets.
//!
//! Reticulum uses simplified HDLC framing WITHOUT CRC:
//! Format: [FLAG (0x7E)] [Escaped Data] [FLAG (0x7E)]
//!
//! The `frame_with_crc` and CRC verification functions are kept for
//! potential future use with interfaces that require CRC.

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

/// Frame data with simplified HDLC encoding (no CRC)
///
/// This matches Python Reticulum's framing format.
pub fn frame(data: &[u8], output: &mut Vec<u8>) {
    output.clear();

    // Start flag
    output.push(FLAG);

    // Escape and write data
    for &byte in data {
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

/// Frame data with HDLC encoding including CRC-16
#[allow(dead_code)]
pub fn frame_with_crc(data: &[u8], output: &mut Vec<u8>) {
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
    /// Complete frame
    Frame(Vec<u8>),
    /// Frame too short (empty)
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

    /// Finalize a complete frame (no CRC verification)
    fn finalize_frame(&mut self) -> DeframeResult {
        if self.buffer.is_empty() {
            return DeframeResult::TooShort;
        }

        DeframeResult::Frame(self.buffer.clone())
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

        // Frame should be: FLAG + escaped_data + FLAG
        assert_eq!(framed[0], FLAG);
        assert_eq!(framed[framed.len() - 1], FLAG);

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);

        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(decoded.as_slice(), data.as_slice()),
            _ => panic!("Expected Frame result"),
        }
    }

    #[test]
    fn test_escape_flag_byte() {
        // Data containing FLAG byte should be escaped
        let data = [0x00, FLAG, 0xFF];
        let mut framed = Vec::new();
        frame(&data, &mut framed);

        // Check that FLAG is escaped (should see ESCAPE followed by FLAG^0x20)
        let escaped_flag = FLAG ^ ESCAPE_XOR;
        assert!(framed.windows(2).any(|w| w == [ESCAPE, escaped_flag]));

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);

        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(decoded.as_slice(), data.as_slice()),
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
            DeframeResult::Frame(decoded) => assert_eq!(decoded.as_slice(), data.as_slice()),
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

    #[test]
    fn test_frame_with_crc_roundtrip() {
        // Test the CRC variant still works for internal consistency
        let data = b"Hello, HDLC with CRC!";
        let mut framed = Vec::new();
        frame_with_crc(data, &mut framed);

        // Frame should include data + 2 byte CRC
        // We can't easily verify this without a CRC-aware deframer
        // Just verify it's longer than the no-CRC version
        let mut framed_no_crc = Vec::new();
        frame(data, &mut framed_no_crc);

        // CRC version should be at least 2 bytes longer (might be more due to escaping)
        assert!(framed.len() >= framed_no_crc.len() + 2);
    }

    // Python Reticulum interop test vectors
    // These vectors are generated by generate_vectors.py from Python Reticulum

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_python_vector_simple() {
        // Simple data "Hello" with no escaping needed
        let data = hex_decode("48656c6c6f");
        let expected = hex_decode("7e48656c6c6f7e");

        let mut framed = Vec::new();
        frame(&data, &mut framed);
        assert_eq!(framed, expected, "Simple frame mismatch with Python");

        // Also verify deframe
        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);
        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(*decoded, data),
            _ => panic!("Expected Frame result"),
        }
    }

    #[test]
    fn test_python_vector_with_flag() {
        // Data containing FLAG byte (0x7E): [0x00, 0x7E, 0xFF]
        let data = hex_decode("007eff");
        let expected = hex_decode("7e007d5eff7e");

        let mut framed = Vec::new();
        frame(&data, &mut framed);
        assert_eq!(framed, expected, "Frame with FLAG byte mismatch with Python");

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);
        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(*decoded, data),
            _ => panic!("Expected Frame result"),
        }
    }

    #[test]
    fn test_python_vector_with_escape() {
        // Data containing ESCAPE byte (0x7D): [0x00, 0x7D, 0xFF]
        let data = hex_decode("007dff");
        let expected = hex_decode("7e007d5dff7e");

        let mut framed = Vec::new();
        frame(&data, &mut framed);
        assert_eq!(framed, expected, "Frame with ESCAPE byte mismatch with Python");

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);
        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(*decoded, data),
            _ => panic!("Expected Frame result"),
        }
    }

    #[test]
    fn test_python_vector_with_both() {
        // Data containing both FLAG and ESCAPE: [0x7E, 0x00, 0x7D, 0xFF]
        let data = hex_decode("7e007dff");
        let expected = hex_decode("7e7d5e007d5dff7e");

        let mut framed = Vec::new();
        frame(&data, &mut framed);
        assert_eq!(framed, expected, "Frame with both special bytes mismatch with Python");

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);
        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(*decoded, data),
            _ => panic!("Expected Frame result"),
        }
    }

    #[test]
    fn test_python_vector_packet() {
        // A real Reticulum packet
        let data = hex_decode("0000010203040506070809101112131415160048656c6c6f");
        let expected = hex_decode("7e0000010203040506070809101112131415160048656c6c6f7e");

        let mut framed = Vec::new();
        frame(&data, &mut framed);
        assert_eq!(framed, expected, "Real packet frame mismatch with Python");

        let mut deframer = Deframer::new();
        let results = deframer.process(&framed);
        assert_eq!(results.len(), 1);
        match &results[0] {
            DeframeResult::Frame(decoded) => assert_eq!(*decoded, data),
            _ => panic!("Expected Frame result"),
        }
    }
}
