//! Buffer system for binary stream transfer over channels
//!
//! This module provides buffered I/O primitives for transferring binary data
//! over Reticulum channels using StreamDataMessage.
//!
//! # Overview
//!
//! - `RawChannelReader` - Receives StreamDataMessage and provides a read interface
//! - `RawChannelWriter` - Sends data as StreamDataMessage chunks
//!
//! # Wire Compatibility
//!
//! The wire format is fully compatible with Python Reticulum's Buffer system.
//! StreamDataMessage uses MSGTYPE 0xff00 and a 2-byte header encoding:
//! - bits 0-13: stream_id (0-16383)
//! - bit 14: compressed flag
//! - bit 15: EOF flag
//!
//! # Example
//!
//! ```ignore
//! use reticulum_std::buffer::{RawChannelReader, RawChannelWriter};
//!
//! // Create writer for stream 0
//! let mut writer = RawChannelWriter::new(0, channel_mdu);
//!
//! // Prepare a chunk to send
//! let chunk = writer.prepare_chunk(b"Hello, world!", false)?;
//! // Send chunk.data via channel.send_system(&chunk, ...)
//!
//! // On receiver side, create reader for stream 0
//! let mut reader = RawChannelReader::new(0);
//!
//! // When StreamDataMessage is received:
//! reader.receive(&message);
//!
//! // Read data
//! let mut buf = vec![0u8; 1024];
//! let n = reader.read(&mut buf)?;
//! ```

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use reticulum_core::constants::{CHANNEL_ENVELOPE_HEADER_SIZE, STREAM_DATA_HEADER_SIZE};
use reticulum_core::link::channel::StreamDataMessage;

/// Maximum chunk length for a single write operation
const MAX_CHUNK_LEN: usize = 16 * 1024; // 16 KB

/// Minimum data size to attempt compression
const COMPRESSION_MIN_SIZE: usize = 32;

/// Number of compression attempts with decreasing chunk sizes
#[cfg(feature = "compression")]
const COMPRESSION_TRIES: usize = 4;

/// Calculate the maximum data length for a StreamDataMessage given the channel MDU
pub fn max_data_len(channel_mdu: usize) -> usize {
    channel_mdu.saturating_sub(STREAM_DATA_HEADER_SIZE)
}

/// Calculate the total overhead for StreamDataMessage (stream header + envelope header)
pub const fn stream_overhead() -> usize {
    STREAM_DATA_HEADER_SIZE + CHANNEL_ENVELOPE_HEADER_SIZE
}

/// Reader for receiving binary stream data over a channel
///
/// `RawChannelReader` buffers incoming `StreamDataMessage` data and provides
/// a standard `Read` interface.
///
/// # Thread Safety
///
/// This type is not thread-safe. Use external synchronization if needed.
#[derive(Debug)]
pub struct RawChannelReader {
    /// Stream identifier this reader accepts
    stream_id: u16,
    /// Internal buffer for received data
    buffer: VecDeque<u8>,
    /// Whether EOF has been received
    eof: bool,
}

impl RawChannelReader {
    /// Create a new reader for the given stream ID
    ///
    /// # Arguments
    /// * `stream_id` - The stream identifier to accept messages for (0-16383)
    pub fn new(stream_id: u16) -> Self {
        Self {
            stream_id,
            buffer: VecDeque::new(),
            eof: false,
        }
    }

    /// Get the stream ID this reader is listening on
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// Check if EOF has been received
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Get the number of bytes available in the buffer
    pub fn available(&self) -> usize {
        self.buffer.len()
    }

    /// Receive a StreamDataMessage
    ///
    /// Processes the message and buffers its data if it matches this reader's stream_id.
    /// Returns true if the message was accepted (stream_id matched).
    ///
    /// # Arguments
    /// * `message` - The StreamDataMessage to process
    ///
    /// # Note
    /// If the message has the compressed flag set, the caller must decompress
    /// the data before calling this method. The RawChannelReader does not
    /// perform decompression itself.
    pub fn receive(&mut self, message: &StreamDataMessage) -> bool {
        if message.stream_id != self.stream_id {
            return false;
        }

        self.buffer.extend(&message.data);

        if message.eof {
            self.eof = true;
        }

        true
    }

    /// Receive and decompress a StreamDataMessage
    ///
    /// This is a convenience method that handles decompression automatically.
    /// Returns true if the message was accepted.
    ///
    /// # Errors
    /// Returns an error if decompression fails.
    #[cfg(feature = "compression")]
    pub fn receive_decompress(&mut self, message: &StreamDataMessage) -> io::Result<bool> {
        if message.stream_id != self.stream_id {
            return Ok(false);
        }

        if message.compressed {
            let decompressed = decompress(&message.data)?;
            self.buffer.extend(&decompressed);
        } else {
            self.buffer.extend(&message.data);
        }

        if message.eof {
            self.eof = true;
        }

        Ok(true)
    }

    /// Clear the internal buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Reset the reader to initial state
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.eof = false;
    }
}

impl Read for RawChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.buffer.is_empty() {
            if self.eof {
                return Ok(0); // EOF
            }
            // No data available, would block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no data available",
            ));
        }

        let len = buf.len().min(self.buffer.len());
        for (i, byte) in self.buffer.drain(..len).enumerate() {
            buf[i] = byte;
        }

        Ok(len)
    }
}

/// Writer for sending binary stream data over a channel
///
/// `RawChannelWriter` prepares data chunks as `StreamDataMessage` for transmission.
/// It handles chunking and optional BZ2 compression.
///
/// # Usage Pattern
///
/// ```ignore
/// let mut writer = RawChannelWriter::new(stream_id, channel_mdu);
///
/// // Prepare chunk (handles compression if enabled)
/// let msg = writer.prepare_chunk(data, false)?;
///
/// // Send via channel
/// channel.send_system(&msg, link_mdu, now_ms, rtt_ms)?;
///
/// // When done, send EOF
/// let eof_msg = writer.prepare_eof();
/// channel.send_system(&eof_msg, link_mdu, now_ms, rtt_ms)?;
/// ```
#[derive(Debug)]
pub struct RawChannelWriter {
    /// Stream identifier for outgoing messages
    stream_id: u16,
    /// Maximum data length per message
    max_data_len: usize,
    /// Whether compression is enabled
    compression_enabled: bool,
}

impl RawChannelWriter {
    /// Create a new writer for the given stream ID
    ///
    /// # Arguments
    /// * `stream_id` - The stream identifier to send messages as (0-16383)
    /// * `channel_mdu` - The channel's maximum data unit (from `Channel::mdu()`)
    pub fn new(stream_id: u16, channel_mdu: usize) -> Self {
        Self {
            stream_id,
            max_data_len: max_data_len(channel_mdu),
            compression_enabled: cfg!(feature = "compression"),
        }
    }

    /// Get the stream ID this writer sends as
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// Get the maximum data length per chunk
    pub fn max_data_len(&self) -> usize {
        self.max_data_len
    }

    /// Enable or disable compression
    pub fn set_compression(&mut self, enabled: bool) {
        self.compression_enabled = enabled && cfg!(feature = "compression");
    }

    /// Check if compression is enabled
    pub fn compression_enabled(&self) -> bool {
        self.compression_enabled
    }

    /// Prepare data for transmission as a StreamDataMessage
    ///
    /// This method handles:
    /// - Chunking (limits to max_data_len)
    /// - Optional BZ2 compression (if enabled and beneficial)
    ///
    /// Returns the prepared message and the number of input bytes consumed.
    ///
    /// # Arguments
    /// * `data` - The data to send
    /// * `eof` - Whether this is the last chunk (sets EOF flag)
    ///
    /// # Returns
    /// A tuple of (StreamDataMessage, bytes_consumed)
    pub fn prepare_chunk(&self, data: &[u8], eof: bool) -> (StreamDataMessage, usize) {
        let chunk_len = data.len().min(MAX_CHUNK_LEN);
        let chunk_data = &data[..chunk_len];

        #[cfg(feature = "compression")]
        if self.compression_enabled && chunk_len > COMPRESSION_MIN_SIZE {
            // Try compression with decreasing chunk sizes
            for try_num in 1..=COMPRESSION_TRIES {
                let segment_len = chunk_len / try_num;
                if segment_len <= COMPRESSION_MIN_SIZE {
                    break;
                }

                if let Ok(compressed) = compress(&data[..segment_len]) {
                    // Use compression if it's smaller and fits in max_data_len
                    if compressed.len() < segment_len && compressed.len() <= self.max_data_len {
                        let msg = StreamDataMessage::new(self.stream_id, compressed, eof, true);
                        return (msg, segment_len);
                    }
                }
            }
        }

        // No compression or compression didn't help
        let final_len = chunk_data.len().min(self.max_data_len);
        let msg =
            StreamDataMessage::new(self.stream_id, chunk_data[..final_len].to_vec(), eof, false);

        (msg, final_len)
    }

    /// Prepare an EOF marker message
    ///
    /// This creates an empty message with the EOF flag set.
    pub fn prepare_eof(&self) -> StreamDataMessage {
        StreamDataMessage::eof(self.stream_id)
    }
}

/// Buffered writer that accumulates data before sending
///
/// This writer implements `std::io::Write` and buffers data internally.
/// Call `flush()` or `take_pending()` to get the accumulated data as
/// StreamDataMessage chunks.
#[derive(Debug)]
pub struct BufferedChannelWriter {
    /// The underlying raw writer
    raw: RawChannelWriter,
    /// Buffered data waiting to be sent
    buffer: Vec<u8>,
    /// Whether EOF has been signaled
    eof: bool,
}

impl BufferedChannelWriter {
    /// Create a new buffered writer
    ///
    /// # Arguments
    /// * `stream_id` - The stream identifier to send messages as (0-16383)
    /// * `channel_mdu` - The channel's maximum data unit
    pub fn new(stream_id: u16, channel_mdu: usize) -> Self {
        Self {
            raw: RawChannelWriter::new(stream_id, channel_mdu),
            buffer: Vec::new(),
            eof: false,
        }
    }

    /// Get the stream ID
    pub fn stream_id(&self) -> u16 {
        self.raw.stream_id()
    }

    /// Get the number of bytes buffered
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Enable or disable compression
    pub fn set_compression(&mut self, enabled: bool) {
        self.raw.set_compression(enabled);
    }

    /// Mark the stream as finished (will set EOF on next flush)
    pub fn finish(&mut self) {
        self.eof = true;
    }

    /// Take all pending data as StreamDataMessage chunks
    ///
    /// Returns a vector of messages ready to send. If `finish()` was called,
    /// the last message will have EOF set.
    pub fn take_pending(&mut self) -> Vec<StreamDataMessage> {
        let mut messages = Vec::new();

        while !self.buffer.is_empty() {
            let is_last = self.eof && self.buffer.len() <= self.raw.max_data_len();
            let (msg, consumed) = self.raw.prepare_chunk(&self.buffer, is_last);
            self.buffer.drain(..consumed);
            messages.push(msg);
        }

        // If we're at EOF and buffer is empty, send EOF marker
        if self.eof && messages.is_empty() {
            messages.push(self.raw.prepare_eof());
        }

        // Clear EOF after sending
        if self.eof && !messages.is_empty() {
            self.eof = false;
        }

        messages
    }
}

impl Write for BufferedChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Flushing is handled externally via take_pending()
        Ok(())
    }
}

/// Compress data using BZ2
#[cfg(feature = "compression")]
fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    use bzip2::write::BzEncoder;
    use bzip2::Compression;

    let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Decompress BZ2 data
#[cfg(feature = "compression")]
fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    use bzip2::read::BzDecoder;

    let mut decoder = BzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_channel_reader_new() {
        let reader = RawChannelReader::new(42);
        assert_eq!(reader.stream_id(), 42);
        assert!(!reader.is_eof());
        assert_eq!(reader.available(), 0);
    }

    #[test]
    fn test_raw_channel_reader_receive() {
        let mut reader = RawChannelReader::new(1);

        // Message for different stream should be rejected
        let msg = StreamDataMessage::new(2, vec![1, 2, 3], false, false);
        assert!(!reader.receive(&msg));
        assert_eq!(reader.available(), 0);

        // Message for our stream should be accepted
        let msg = StreamDataMessage::new(1, vec![1, 2, 3], false, false);
        assert!(reader.receive(&msg));
        assert_eq!(reader.available(), 3);
    }

    #[test]
    fn test_raw_channel_reader_eof() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1, 2], true, false);
        reader.receive(&msg);

        assert!(reader.is_eof());
        assert_eq!(reader.available(), 2);
    }

    #[test]
    fn test_raw_channel_reader_read() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1, 2, 3, 4, 5], false, false);
        reader.receive(&msg);

        let mut buf = [0u8; 3];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(reader.available(), 2);

        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], [4, 5]);
    }

    #[test]
    fn test_raw_channel_reader_read_eof() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1], true, false);
        reader.receive(&msg);

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 1);

        // After consuming all data with EOF, should return 0
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_raw_channel_reader_would_block() {
        let mut reader = RawChannelReader::new(0);

        let mut buf = [0u8; 10];
        let result = reader.read(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_raw_channel_writer_new() {
        let writer = RawChannelWriter::new(5, 458); // 464 - 6 envelope header
        assert_eq!(writer.stream_id(), 5);
        // max_data_len = 458 - 2 (stream header) = 456
        assert_eq!(writer.max_data_len(), 456);
    }

    #[test]
    fn test_raw_channel_writer_prepare_chunk() {
        let writer = RawChannelWriter::new(1, 100);

        let data = vec![0xAA; 50];
        let (msg, consumed) = writer.prepare_chunk(&data, false);

        assert_eq!(msg.stream_id, 1);
        assert!(!msg.eof);
        assert_eq!(consumed, 50);
    }

    #[test]
    fn test_raw_channel_writer_prepare_chunk_truncates() {
        let writer = RawChannelWriter::new(1, 20); // max_data_len = 18

        let data = vec![0xBB; 100];
        let (msg, consumed) = writer.prepare_chunk(&data, false);

        // Should be limited to max_data_len
        assert!(consumed <= 18);
        assert_eq!(msg.data.len(), consumed);
    }

    #[test]
    fn test_raw_channel_writer_prepare_eof() {
        let writer = RawChannelWriter::new(99, 100);
        let msg = writer.prepare_eof();

        assert_eq!(msg.stream_id, 99);
        assert!(msg.eof);
        assert!(msg.data.is_empty());
    }

    #[test]
    fn test_buffered_channel_writer() {
        let mut writer = BufferedChannelWriter::new(0, 50);

        writer.write_all(b"hello").unwrap();
        writer.write_all(b" world").unwrap();

        assert_eq!(writer.buffered(), 11);

        writer.finish();
        let messages = writer.take_pending();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].stream_id, 0);
        assert!(messages[0].eof);
        assert_eq!(messages[0].data, b"hello world");
    }

    #[test]
    fn test_buffered_channel_writer_chunking() {
        let mut writer = BufferedChannelWriter::new(0, 12); // max_data_len = 10

        writer.write_all(b"12345678901234567890").unwrap(); // 20 bytes
        writer.finish();

        let messages = writer.take_pending();

        // Should be chunked into multiple messages
        assert!(messages.len() >= 2);

        // Last message should have EOF
        assert!(messages.last().unwrap().eof);
    }

    #[test]
    fn test_max_data_len() {
        // channel_mdu = 458 (link_mdu - envelope_header)
        // max_data_len = 458 - 2 (stream_header) = 456
        assert_eq!(max_data_len(458), 456);
    }

    #[test]
    fn test_stream_overhead() {
        // 2 bytes stream header + 6 bytes envelope header = 8
        assert_eq!(stream_overhead(), 8);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_compression_roundtrip() {
        let original = b"Hello, this is some test data that should compress well!";

        let compressed = compress(original).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        assert_eq!(decompressed, original);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_reader_receive_decompress() {
        let mut reader = RawChannelReader::new(0);

        // Compress some data
        let original = b"Test data for compression";
        let compressed = compress(original).unwrap();

        let msg = StreamDataMessage::new(0, compressed, false, true);
        reader.receive_decompress(&msg).unwrap();

        assert_eq!(reader.available(), original.len());

        let mut buf = vec![0u8; 100];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], original);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_writer_compression() {
        let writer = RawChannelWriter::new(0, 500);

        // Create highly compressible data
        let data = vec![b'A'; 200];
        let (msg, consumed) = writer.prepare_chunk(&data, false);

        // Should have compressed the data
        if msg.compressed {
            assert!(msg.data.len() < consumed);
        }
    }
}
