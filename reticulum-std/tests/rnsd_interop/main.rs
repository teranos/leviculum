//! Interoperability tests with Python Reticulum.
//!
//! These tests verify that our Rust implementation correctly interoperates
//! with the Python Reticulum reference implementation. Tests are organized
//! into two categories:
//!
//! ## Test Categories
//!
//! 1. **Unit Tests** - Pure logic tests that don't require a daemon:
//!    - `protocol_tests` - Flag encoding, hash derivation, packet layout
//!
//! 2. **Interop Tests** - Tests using the TestDaemon infrastructure:
//!    - `daemon_tests` - Core announce/path tests
//!    - `discovery_tests` - Bidirectional discovery tests
//!    - `link_tests` - Link establishment tests
//!    - `flow_tests` - End-to-end flow tests
//!
//! ## Running Tests
//!
//! ```sh
//! # Run all interop tests (includes daemon tests that auto-spawn Python daemon)
//! cargo test --package reticulum-std --test rnsd_interop
//!
//! # Run with verbose output
//! cargo test --package reticulum-std --test rnsd_interop -- --nocapture
//!
//! # Run specific test module
//! cargo test --package reticulum-std --test rnsd_interop daemon_tests
//! cargo test --package reticulum-std --test rnsd_interop protocol_tests
//! ```

mod common;
mod harness;
mod daemon_tests;
mod discovery_tests;
mod link_tests;
mod flow_tests;
mod protocol_tests;
