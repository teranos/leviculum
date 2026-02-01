//! Buffer system for binary stream transfer over channels (no_std compatible)
//!
//! This module provides buffered I/O primitives for transferring binary data
//! over Reticulum channels using StreamDataMessage.
//!
//! # Overview
//!
//! - `RawChannelReader` - Receives StreamDataMessage and buffers data for reading
//! - `RawChannelWriter` - Prepares data chunks as StreamDataMessage for sending
//! - `BufferedChannelWriter` - Accumulates data before chunking into messages
//!
//! # Wire Compatibility
//!
//! The wire format is fully compatible with Python Reticulum's Buffer system.
//! StreamDataMessage uses MSGTYPE 0xff00 and a 2-byte header encoding:
//! - bits 0-13: stream_id (0-16383)
//! - bit 14: compressed flag
//! - bit 15: EOF flag
//!
//! # Compression
//!
//! This no_std implementation does not include compression. For BZ2 compression
//! support, use `reticulum-std` which provides compression wrappers.
//!
//! Data sent without compression (compressed=false) is fully wire-compatible
//! with Python Reticulum, which accepts both compressed and uncompressed data.
//!
//! # Example
//!
//! ```ignore
//! use reticulum_core::link::channel::{RawChannelReader, RawChannelWriter, StreamDataMessage};
//!
//! // Create writer for stream 0
//! let writer = RawChannelWriter::new(0, 458); // channel MDU
//!
//! // Prepare a chunk to send
//! let (msg, consumed) = writer.prepare_chunk(b"Hello, world!", false);
//! // Send msg via channel.send_system(...)
//!
//! // On receiver side
//! let mut reader = RawChannelReader::new(0);
//! reader.receive(&msg);
//!
//! // Read data
//! let mut buf = [0u8; 64];
//! let n = reader.read(&mut buf);
//! ```

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::StreamDataMessage;
use crate::constants::{CHANNEL_ENVELOPE_HEADER_SIZE, STREAM_DATA_HEADER_SIZE};

/// Maximum chunk length for a single write operation (16 KB)
pub const MAX_CHUNK_LEN: usize = 16 * 1024;

/// Calculate the maximum data length for a StreamDataMessage given the channel MDU
#[inline]
pub fn max_data_len(channel_mdu: usize) -> usize {
    channel_mdu.saturating_sub(STREAM_DATA_HEADER_SIZE)
}

/// Calculate the total overhead for StreamDataMessage (stream header + envelope header)
#[inline]
pub const fn stream_overhead() -> usize {
    STREAM_DATA_HEADER_SIZE + CHANNEL_ENVELOPE_HEADER_SIZE
}

/// Result of a read operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadResult {
    /// Successfully read N bytes
    Read(usize),
    /// No data available, would block (not EOF)
    WouldBlock,
    /// End of stream reached, no more data
    Eof,
}

/// Reader for receiving binary stream data over a channel
///
/// `RawChannelReader` buffers incoming `StreamDataMessage` data and provides
/// a read interface for consuming the buffered data.
///
/// # no_std Compatibility
///
/// This type uses `alloc::collections::VecDeque` for buffering and works
/// in no_std environments with the alloc crate.
///
/// # Compression
///
/// This reader does NOT handle decompression. If you receive compressed
/// messages (StreamDataMessage.compressed == true), you must decompress
/// the data before calling `receive()`, or use the compression wrappers
/// in `reticulum-std`.
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

    /// Check if data is available to read
    pub fn has_data(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Receive a StreamDataMessage
    ///
    /// Processes the message and buffers its data if it matches this reader's stream_id.
    /// Returns true if the message was accepted (stream_id matched).
    ///
    /// # Arguments
    /// * `message` - The StreamDataMessage to process
    ///
    /// # Compression Note
    ///
    /// If the message has `compressed == true`, the caller must decompress
    /// `message.data` before calling this method. This no_std implementation
    /// does not include decompression.
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

    /// Receive raw data directly (for pre-decompressed data)
    ///
    /// Use this when you've already decompressed the data externally.
    ///
    /// # Arguments
    /// * `data` - The data to buffer
    /// * `eof` - Whether this marks end of stream
    pub fn receive_data(&mut self, data: &[u8], eof: bool) {
        self.buffer.extend(data);
        if eof {
            self.eof = true;
        }
    }

    /// Read data from the buffer
    ///
    /// # Arguments
    /// * `buf` - Buffer to read into
    ///
    /// # Returns
    /// - `ReadResult::Read(n)` - Successfully read n bytes
    /// - `ReadResult::WouldBlock` - No data available (not EOF)
    /// - `ReadResult::Eof` - End of stream, no more data will arrive
    pub fn read(&mut self, buf: &mut [u8]) -> ReadResult {
        if self.buffer.is_empty() {
            if self.eof {
                return ReadResult::Eof;
            }
            return ReadResult::WouldBlock;
        }

        let len = buf.len().min(self.buffer.len());
        for (i, byte) in self.buffer.drain(..len).enumerate() {
            buf[i] = byte;
        }

        ReadResult::Read(len)
    }

    /// Read all available data into a new Vec
    ///
    /// Returns the buffered data and clears the internal buffer.
    pub fn read_all(&mut self) -> Vec<u8> {
        self.buffer.drain(..).collect()
    }

    /// Peek at available data without consuming it
    ///
    /// # Arguments
    /// * `buf` - Buffer to copy data into
    ///
    /// # Returns
    /// Number of bytes copied (may be less than buf.len())
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let len = buf.len().min(self.buffer.len());
        for (i, &byte) in self.buffer.iter().take(len).enumerate() {
            buf[i] = byte;
        }
        len
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

/// Writer for sending binary stream data over a channel
///
/// `RawChannelWriter` prepares data chunks as `StreamDataMessage` for transmission.
/// It handles chunking data to fit within the channel MDU.
///
/// # no_std Compatibility
///
/// This type is fully no_std compatible. It does not perform compression.
/// For compression support, use the wrappers in `reticulum-std`.
///
/// # Usage Pattern
///
/// ```ignore
/// let writer = RawChannelWriter::new(stream_id, channel_mdu);
///
/// // Prepare chunk (no compression)
/// let (msg, consumed) = writer.prepare_chunk(data, false);
///
/// // Send via channel
/// channel.send_system(&msg, link_mdu, now_ms, rtt_ms)?;
///
/// // When done, send EOF
/// let msg = writer.prepare_eof();
/// channel.send_system(&msg, link_mdu, now_ms, rtt_ms)?;
/// ```
#[derive(Debug, Clone)]
pub struct RawChannelWriter {
    /// Stream identifier for outgoing messages
    stream_id: u16,
    /// Maximum data length per message
    max_data_len: usize,
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

    /// Prepare data for transmission as a StreamDataMessage
    ///
    /// This method chunks data to fit within max_data_len. No compression
    /// is applied (compressed flag will be false).
    ///
    /// # Arguments
    /// * `data` - The data to send
    /// * `eof` - Whether this is the last chunk (sets EOF flag)
    ///
    /// # Returns
    /// A tuple of (StreamDataMessage, bytes_consumed)
    pub fn prepare_chunk(&self, data: &[u8], eof: bool) -> (StreamDataMessage, usize) {
        let chunk_len = data.len().min(MAX_CHUNK_LEN).min(self.max_data_len);
        let msg = StreamDataMessage::new(
            self.stream_id,
            data[..chunk_len].to_vec(),
            eof,
            false, // No compression in no_std
        );
        (msg, chunk_len)
    }

    /// Prepare a pre-compressed chunk for transmission
    ///
    /// Use this when you've compressed the data externally and want to
    /// send it with the compressed flag set.
    ///
    /// # Arguments
    /// * `compressed_data` - The compressed data
    /// * `eof` - Whether this is the last chunk
    ///
    /// # Returns
    /// The StreamDataMessage ready to send
    pub fn prepare_compressed_chunk(
        &self,
        compressed_data: Vec<u8>,
        eof: bool,
    ) -> StreamDataMessage {
        StreamDataMessage::new(self.stream_id, compressed_data, eof, true)
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
/// This writer accumulates data internally and produces StreamDataMessage
/// chunks when `take_pending()` is called.
///
/// # no_std Compatibility
///
/// This type is fully no_std compatible. Messages are produced without
/// compression. For compression support, use the wrappers in `reticulum-std`.
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

    /// Get the maximum data length per chunk
    pub fn max_data_len(&self) -> usize {
        self.raw.max_data_len()
    }

    /// Get the number of bytes buffered
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Check if there is pending data
    pub fn has_pending(&self) -> bool {
        !self.buffer.is_empty() || self.eof
    }

    /// Write data to the buffer
    ///
    /// # Arguments
    /// * `data` - Data to buffer
    ///
    /// # Returns
    /// Number of bytes written (always data.len())
    pub fn write(&mut self, data: &[u8]) -> usize {
        self.buffer.extend_from_slice(data);
        data.len()
    }

    /// Mark the stream as finished (will set EOF on next take_pending)
    pub fn finish(&mut self) {
        self.eof = true;
    }

    /// Check if finish() has been called
    pub fn is_finished(&self) -> bool {
        self.eof
    }

    /// Take all pending data as StreamDataMessage chunks
    ///
    /// Returns a vector of messages ready to send. If `finish()` was called,
    /// the last message will have EOF set.
    ///
    /// Messages are produced without compression.
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

        // Clear EOF flag after sending
        if self.eof && !messages.is_empty() {
            self.eof = false;
        }

        messages
    }

    /// Clear buffered data without sending
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.eof = false;
    }

    /// Get access to the underlying RawChannelWriter
    pub fn raw_writer(&self) -> &RawChannelWriter {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_raw_channel_reader_new() {
        let reader = RawChannelReader::new(42);
        assert_eq!(reader.stream_id(), 42);
        assert!(!reader.is_eof());
        assert_eq!(reader.available(), 0);
        assert!(!reader.has_data());
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
        assert!(reader.has_data());
    }

    #[test]
    fn test_raw_channel_reader_receive_data() {
        let mut reader = RawChannelReader::new(0);

        reader.receive_data(&[1, 2, 3], false);
        assert_eq!(reader.available(), 3);
        assert!(!reader.is_eof());

        reader.receive_data(&[4, 5], true);
        assert_eq!(reader.available(), 5);
        assert!(reader.is_eof());
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
        assert_eq!(reader.read(&mut buf), ReadResult::Read(3));
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(reader.available(), 2);

        assert_eq!(reader.read(&mut buf), ReadResult::Read(2));
        assert_eq!(&buf[..2], [4, 5]);
    }

    #[test]
    fn test_raw_channel_reader_read_eof() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1], true, false);
        reader.receive(&msg);

        let mut buf = [0u8; 10];
        assert_eq!(reader.read(&mut buf), ReadResult::Read(1));

        // After consuming all data with EOF, should return Eof
        assert_eq!(reader.read(&mut buf), ReadResult::Eof);
    }

    #[test]
    fn test_raw_channel_reader_would_block() {
        let mut reader = RawChannelReader::new(0);

        let mut buf = [0u8; 10];
        assert_eq!(reader.read(&mut buf), ReadResult::WouldBlock);
    }

    #[test]
    fn test_raw_channel_reader_read_all() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1, 2, 3, 4, 5], false, false);
        reader.receive(&msg);

        let data = reader.read_all();
        assert_eq!(data, vec![1, 2, 3, 4, 5]);
        assert_eq!(reader.available(), 0);
    }

    #[test]
    fn test_raw_channel_reader_peek() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1, 2, 3], false, false);
        reader.receive(&msg);

        let mut buf = [0u8; 2];
        assert_eq!(reader.peek(&mut buf), 2);
        assert_eq!(buf, [1, 2]);

        // Data should still be there
        assert_eq!(reader.available(), 3);
    }

    #[test]
    fn test_raw_channel_reader_reset() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1, 2, 3], true, false);
        reader.receive(&msg);

        assert!(reader.is_eof());
        assert_eq!(reader.available(), 3);

        reader.reset();
        assert!(!reader.is_eof());
        assert_eq!(reader.available(), 0);
    }

    #[test]
    fn test_raw_channel_writer_new() {
        let writer = RawChannelWriter::new(5, 458);
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
        assert!(!msg.compressed);
        assert_eq!(consumed, 50);
        assert_eq!(msg.data.len(), 50);
    }

    #[test]
    fn test_raw_channel_writer_prepare_chunk_truncates() {
        let writer = RawChannelWriter::new(1, 20); // max_data_len = 18

        let data = vec![0xBB; 100];
        let (msg, consumed) = writer.prepare_chunk(&data, false);

        // Should be limited to max_data_len
        assert_eq!(consumed, 18);
        assert_eq!(msg.data.len(), 18);
    }

    #[test]
    fn test_raw_channel_writer_prepare_compressed_chunk() {
        let writer = RawChannelWriter::new(1, 100);

        let compressed_data = vec![0xCC; 30];
        let msg = writer.prepare_compressed_chunk(compressed_data.clone(), true);

        assert_eq!(msg.stream_id, 1);
        assert!(msg.eof);
        assert!(msg.compressed);
        assert_eq!(msg.data, compressed_data);
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
    fn test_buffered_channel_writer_new() {
        let writer = BufferedChannelWriter::new(0, 50);
        assert_eq!(writer.stream_id(), 0);
        assert_eq!(writer.buffered(), 0);
        assert!(!writer.has_pending());
    }

    #[test]
    fn test_buffered_channel_writer_write() {
        let mut writer = BufferedChannelWriter::new(0, 50);

        let n = writer.write(b"hello");
        assert_eq!(n, 5);
        assert_eq!(writer.buffered(), 5);

        let n = writer.write(b" world");
        assert_eq!(n, 6);
        assert_eq!(writer.buffered(), 11);
    }

    #[test]
    fn test_buffered_channel_writer_take_pending() {
        let mut writer = BufferedChannelWriter::new(0, 50);

        writer.write(b"hello world");
        writer.finish();

        let messages = writer.take_pending();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].stream_id, 0);
        assert!(messages[0].eof);
        assert!(!messages[0].compressed);
        assert_eq!(messages[0].data, b"hello world");
    }

    #[test]
    fn test_buffered_channel_writer_chunking() {
        let mut writer = BufferedChannelWriter::new(0, 12); // max_data_len = 10

        writer.write(b"12345678901234567890"); // 20 bytes
        writer.finish();

        let messages = writer.take_pending();

        // Should be chunked into multiple messages
        assert!(messages.len() >= 2);

        // Last message should have EOF
        assert!(messages.last().unwrap().eof);

        // Total data should match
        let total: Vec<u8> = messages
            .iter()
            .flat_map(|m| m.data.iter().copied())
            .collect();
        assert_eq!(total, b"12345678901234567890");
    }

    #[test]
    fn test_buffered_channel_writer_clear() {
        let mut writer = BufferedChannelWriter::new(0, 50);

        writer.write(b"test data");
        writer.finish();

        assert!(writer.has_pending());

        writer.clear();

        assert!(!writer.has_pending());
        assert_eq!(writer.buffered(), 0);
        assert!(!writer.is_finished());
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
}
