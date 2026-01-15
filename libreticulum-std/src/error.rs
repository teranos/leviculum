//! Error types for leviculum-std

use thiserror::Error;

/// Main error type for leviculum operations
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Interface error
    #[error("Interface error: {0}")]
    Interface(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Link error
    #[error("Link error: {0}")]
    Link(String),

    /// Identity error
    #[error("Identity error: {0}")]
    Identity(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;
