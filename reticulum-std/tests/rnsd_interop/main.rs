//! Live interoperability tests with Python rnsd
//!
//! These tests require a running rnsd instance on localhost:4242.
//! Run with: cargo test --package reticulum-std --test rnsd_interop -- --ignored
//!
//! To enable: start rnsd with a TCPServerInterface on 127.0.0.1:4242
//!
//! ## Testing Strategy
//!
//! Interop tests must verify EXTERNAL compatibility, not just internal consistency.
//! Key principles:
//!
//! 1. **Never rely on self-verification alone** - If we sign with our code and verify
//!    with our code, bugs in format won't be caught. Always verify against rnsd.
//!
//! 2. **Monitor rnsd logs for errors** - rnsd logs validation failures. Check logs
//!    after each test to catch format mismatches.
//!
//! 3. **Verify round-trip propagation** - An announce isn't "accepted" just because
//!    the connection stays open. Verify rnsd actually propagates it.
//!
//! 4. **Use multiple connections** - Send on one connection, receive on another.
//!    This proves rnsd processed the packet, not just buffered it.
//!
//! ## Module Organization
//!
//! - `common`     - Shared helpers, constants, test infrastructure
//! - `basic`      - Basic connectivity and packet format tests
//! - `crypto`     - Cryptographic verification of real network announces
//! - `announce`   - Announce creation, propagation, and adversarial tests
//! - `protocol`   - Protocol correctness: byte layouts, known vectors, flags
//! - `link`       - Link establishment and data exchange
//! - `stress`     - Concurrency, rate limiting, burst handling
//! - `resilience` - Error recovery, reconnection, malformed packet tolerance
//! - `transport`  - Transport + TcpClientInterface integration

mod common;
mod harness;
mod daemon_tests;
mod basic;
mod crypto;
mod announce;
mod protocol;
mod link;
mod stress;
mod resilience;
mod transport;
