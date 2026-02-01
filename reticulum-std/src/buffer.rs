//! Compression extensions for the buffer system
//!
//! This module re-exports the core buffer types from `reticulum-core` and adds
//! BZ2 compression support that requires std.
//!
//! # Core Types (re-exported)
//!
//! - [`RawChannelReader`] - Receives and buffers StreamDataMessage data
//! - [`RawChannelWriter`] - Prepares data chunks as StreamDataMessage
//! - [`BufferedChannelWriter`] - Accumulates data before chunking
//!
//! # Compression Extensions
//!
//! - [`decompress_bz2`] - Decompress BZ2 data
//! - [`compress_bz2`] - Compress data with BZ2
//! - [`RawChannelReaderExt`] - Extension trait for decompressing received messages
//! - [`CompressingWriter`] - Writer wrapper that applies BZ2 compression
//!
//! # std::io Adapters
//!
//! - [`IoReadAdapter`] - Adapts RawChannelReader to std::io::Read
//! - [`IoWriteAdapter`] - Adapts BufferedChannelWriter to std::io::Write
//!
//! # Example
//!
//! ```ignore
//! use reticulum_std::buffer::{RawChannelReader, RawChannelReaderExt, CompressingWriter};
//!
//! // Receiving with automatic decompression
//! let mut reader = RawChannelReader::new(0);
//! reader.receive_decompress(&message)?; // Handles compressed messages
//!
//! // Sending with compression
//! let writer = CompressingWriter::new(0, channel_mdu);
//! let (msg, consumed) = writer.prepare_chunk_compressed(data, false)?;
//! ```

use std::io::{self, Read, Write};

#[cfg(feature = "compression")]
use bzip2::read::BzDecoder;
#[cfg(feature = "compression")]
use bzip2::write::BzEncoder;
#[cfg(feature = "compression")]
use bzip2::Compression;

// Re-export core types
pub use reticulum_core::link::channel::{
    max_data_len, stream_overhead, BufferedChannelWriter, RawChannelReader, RawChannelWriter,
    ReadResult, StreamDataMessage, MAX_CHUNK_LEN,
};

// Re-export core compression types when using compression-nostd feature
#[cfg(feature = "compression-nostd")]
pub use reticulum_core::compression::{
    compress as compress_core, decompress as decompress_core,
    decompress_auto as decompress_auto_core, CompressionError as CoreCompressionError,
};
#[cfg(feature = "compression-nostd")]
pub use reticulum_core::link::channel::{
    CompressingWriter as CoreCompressingWriter, COMPRESSION_MIN_SIZE as CORE_COMPRESSION_MIN_SIZE,
    COMPRESSION_TRIES as CORE_COMPRESSION_TRIES, MAX_DECOMPRESS_SIZE,
};

/// Minimum data size to attempt compression (smaller data often doesn't compress well)
#[cfg(feature = "compression")]
pub const COMPRESSION_MIN_SIZE: usize = 32;

/// Number of compression attempts with decreasing chunk sizes
#[cfg(feature = "compression")]
pub const COMPRESSION_TRIES: usize = 4;

// ─── Compression Functions ──────────────────────────────────────────────────

/// Decompress BZ2 data
///
/// # Arguments
/// * `data` - BZ2 compressed data
///
/// # Returns
/// Decompressed data or an IO error
#[cfg(feature = "compression")]
pub fn decompress_bz2(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = BzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Compress data with BZ2
///
/// # Arguments
/// * `data` - Data to compress
///
/// # Returns
/// Compressed data or an IO error
#[cfg(feature = "compression")]
pub fn compress_bz2(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

// ─── Reader Extension Trait ─────────────────────────────────────────────────

/// Extension trait for RawChannelReader with compression support
#[cfg(feature = "compression")]
pub trait RawChannelReaderExt {
    /// Receive and decompress a StreamDataMessage
    ///
    /// If the message has the compressed flag set, the data is automatically
    /// decompressed using BZ2 before being buffered.
    ///
    /// # Arguments
    /// * `message` - The StreamDataMessage to process
    ///
    /// # Returns
    /// - `Ok(true)` if the message was accepted (stream_id matched)
    /// - `Ok(false)` if the message was for a different stream
    /// - `Err(...)` if decompression failed
    fn receive_decompress(&mut self, message: &StreamDataMessage) -> io::Result<bool>;
}

#[cfg(feature = "compression")]
impl RawChannelReaderExt for RawChannelReader {
    fn receive_decompress(&mut self, message: &StreamDataMessage) -> io::Result<bool> {
        if message.stream_id != self.stream_id() {
            return Ok(false);
        }

        if message.compressed {
            let decompressed = decompress_bz2(&message.data)?;
            self.receive_data(&decompressed, message.eof);
        } else {
            self.receive_data(&message.data, message.eof);
        }

        Ok(true)
    }
}

// ─── Compressing Writer ─────────────────────────────────────────────────────

/// Writer that applies BZ2 compression to data before sending
///
/// This wrapper around `RawChannelWriter` tries to compress data and uses
/// compression if it results in smaller output.
#[cfg(feature = "compression")]
#[derive(Debug, Clone)]
pub struct CompressingWriter {
    inner: RawChannelWriter,
}

#[cfg(feature = "compression")]
impl CompressingWriter {
    /// Create a new compressing writer
    ///
    /// # Arguments
    /// * `stream_id` - The stream identifier (0-16383)
    /// * `channel_mdu` - The channel's maximum data unit
    pub fn new(stream_id: u16, channel_mdu: usize) -> Self {
        Self {
            inner: RawChannelWriter::new(stream_id, channel_mdu),
        }
    }

    /// Get the stream ID
    pub fn stream_id(&self) -> u16 {
        self.inner.stream_id()
    }

    /// Get the maximum data length per chunk
    pub fn max_data_len(&self) -> usize {
        self.inner.max_data_len()
    }

    /// Get the inner RawChannelWriter
    pub fn inner(&self) -> &RawChannelWriter {
        &self.inner
    }

    /// Prepare a chunk without compression
    ///
    /// Use this when you don't want compression for this chunk.
    pub fn prepare_chunk(&self, data: &[u8], eof: bool) -> (StreamDataMessage, usize) {
        self.inner.prepare_chunk(data, eof)
    }

    /// Prepare a chunk with optional compression
    ///
    /// Tries to compress the data using BZ2. If compression results in smaller
    /// output that fits within max_data_len, the compressed data is used.
    /// Otherwise, uncompressed data is sent.
    ///
    /// # Arguments
    /// * `data` - Data to send
    /// * `eof` - Whether this is the last chunk
    ///
    /// # Returns
    /// A tuple of (StreamDataMessage, bytes_consumed)
    pub fn prepare_chunk_compressed(
        &self,
        data: &[u8],
        eof: bool,
    ) -> io::Result<(StreamDataMessage, usize)> {
        let chunk_len = data.len().min(MAX_CHUNK_LEN);
        let chunk_data = &data[..chunk_len];

        // Try compression if data is large enough
        if chunk_len > COMPRESSION_MIN_SIZE {
            for try_num in 1..=COMPRESSION_TRIES {
                let segment_len = chunk_len / try_num;
                if segment_len <= COMPRESSION_MIN_SIZE {
                    break;
                }

                if let Ok(compressed) = compress_bz2(&data[..segment_len]) {
                    // Use compression if it's smaller and fits in max_data_len
                    if compressed.len() < segment_len && compressed.len() <= self.max_data_len() {
                        let msg = self.inner.prepare_compressed_chunk(compressed, eof);
                        return Ok((msg, segment_len));
                    }
                }
            }
        }

        // No compression or compression didn't help
        Ok(self.inner.prepare_chunk(chunk_data, eof))
    }

    /// Prepare an EOF marker message
    pub fn prepare_eof(&self) -> StreamDataMessage {
        self.inner.prepare_eof()
    }
}

// ─── std::io Adapters ───────────────────────────────────────────────────────

/// Adapter that implements std::io::Read for RawChannelReader
///
/// This allows using RawChannelReader with standard Rust I/O interfaces.
///
/// # Blocking Behavior
///
/// When no data is available and EOF has not been received, `read()` returns
/// `WouldBlock`. For non-blocking use, check `has_data()` before reading.
pub struct IoReadAdapter<'a> {
    reader: &'a mut RawChannelReader,
}

impl<'a> IoReadAdapter<'a> {
    /// Create a new adapter wrapping a RawChannelReader
    pub fn new(reader: &'a mut RawChannelReader) -> Self {
        Self { reader }
    }
}

impl<'a> Read for IoReadAdapter<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.reader.read(buf) {
            ReadResult::Read(n) => Ok(n),
            ReadResult::Eof => Ok(0),
            ReadResult::WouldBlock => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no data available",
            )),
        }
    }
}

/// Adapter that implements std::io::Write for BufferedChannelWriter
///
/// Note: This adapter only buffers data. You must call `take_pending()` on
/// the underlying writer to get the actual messages to send.
pub struct IoWriteAdapter<'a> {
    writer: &'a mut BufferedChannelWriter,
}

impl<'a> IoWriteAdapter<'a> {
    /// Create a new adapter wrapping a BufferedChannelWriter
    pub fn new(writer: &'a mut BufferedChannelWriter) -> Self {
        Self { writer }
    }
}

impl<'a> Write for IoWriteAdapter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(self.writer.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        // Flushing is handled externally via take_pending()
        Ok(())
    }
}

// ─── Convenience Functions ──────────────────────────────────────────────────

/// Create an std::io::Read adapter for a RawChannelReader
pub fn as_read(reader: &mut RawChannelReader) -> IoReadAdapter<'_> {
    IoReadAdapter::new(reader)
}

/// Create an std::io::Write adapter for a BufferedChannelWriter
pub fn as_write(writer: &mut BufferedChannelWriter) -> IoWriteAdapter<'_> {
    IoWriteAdapter::new(writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_read_adapter() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1, 2, 3, 4, 5], false, false);
        reader.receive(&msg);

        let mut adapter = IoReadAdapter::new(&mut reader);
        let mut buf = [0u8; 3];

        let n = adapter.read(&mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [1, 2, 3]);
    }

    #[test]
    fn test_io_read_adapter_eof() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(0, vec![1], true, false);
        reader.receive(&msg);

        let mut adapter = IoReadAdapter::new(&mut reader);
        let mut buf = [0u8; 10];

        // Read the data
        let n = adapter.read(&mut buf).unwrap();
        assert_eq!(n, 1);

        // EOF returns 0
        let n = adapter.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_io_read_adapter_would_block() {
        let mut reader = RawChannelReader::new(0);
        let mut adapter = IoReadAdapter::new(&mut reader);
        let mut buf = [0u8; 10];

        let result = adapter.read(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_io_write_adapter() {
        let mut writer = BufferedChannelWriter::new(0, 100);

        {
            let mut adapter = IoWriteAdapter::new(&mut writer);
            adapter.write_all(b"hello world").unwrap();
        }

        assert_eq!(writer.buffered(), 11);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_compress_decompress_roundtrip() {
        let original = b"Hello, this is some test data that should compress well!";

        let compressed = compress_bz2(original).unwrap();
        let decompressed = decompress_bz2(&compressed).unwrap();

        assert_eq!(decompressed, original);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_reader_receive_decompress() {
        let mut reader = RawChannelReader::new(0);

        // Compress some data
        let original = b"Test data for compression";
        let compressed = compress_bz2(original).unwrap();

        let msg = StreamDataMessage::new(0, compressed, false, true);
        reader.receive_decompress(&msg).unwrap();

        assert_eq!(reader.available(), original.len());

        let data = reader.read_all();
        assert_eq!(data, original);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_reader_receive_decompress_uncompressed() {
        let mut reader = RawChannelReader::new(0);

        // Uncompressed message
        let msg = StreamDataMessage::new(0, vec![1, 2, 3], false, false);
        reader.receive_decompress(&msg).unwrap();

        assert_eq!(reader.available(), 3);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_reader_receive_decompress_wrong_stream() {
        let mut reader = RawChannelReader::new(0);

        let msg = StreamDataMessage::new(1, vec![1, 2, 3], false, false);
        let accepted = reader.receive_decompress(&msg).unwrap();

        assert!(!accepted);
        assert_eq!(reader.available(), 0);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_compressing_writer() {
        let writer = CompressingWriter::new(0, 500);

        // Create highly compressible data
        let data = vec![b'A'; 200];
        let (msg, consumed) = writer.prepare_chunk_compressed(&data, false).unwrap();

        // Should have compressed the data (or used uncompressed if compression didn't help)
        assert!(consumed > 0);
        assert_eq!(msg.stream_id, 0);

        if msg.compressed {
            assert!(msg.data.len() < consumed);
        }
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_compressing_writer_small_data() {
        let writer = CompressingWriter::new(0, 500);

        // Small data shouldn't be compressed
        let data = vec![b'X'; 10];
        let (msg, consumed) = writer.prepare_chunk_compressed(&data, false).unwrap();

        assert!(!msg.compressed);
        assert_eq!(consumed, 10);
    }
}
