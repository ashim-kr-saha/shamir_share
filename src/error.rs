use std::io;
use thiserror::Error;

/// Error type for Shamir's Secret Sharing operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ShamirError {
    /// Invalid threshold value (must be 2 <= threshold <= total_shares)
    #[error("Invalid threshold value {0}")]
    InvalidThreshold(u8),

    /// Invalid total shares count (must be >= 2)
    #[error("Invalid share count {0}")]
    InvalidShareCount(u8),

    /// Threshold exceeds total shares
    #[error("Threshold {threshold} exceeds total shares {total_shares}")]
    ThresholdTooLarge { threshold: u8, total_shares: u8 },

    /// Insufficient shares for reconstruction
    #[error("Need at least {needed} shares, got {got}")]
    InsufficientShares { needed: u8, got: u8 },

    /// Invalid share index requested (must be non-zero)
    #[error("Invalid share index {0}")]
    InvalidShareIndex(u8),

    /// General I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Data integrity check failed
    #[error("Data integrity check failed")]
    IntegrityCheckFailed,

    /// Invalid share format or content
    #[error("Invalid share format")]
    InvalidShareFormat,

    /// Inconsistent share lengths
    #[error("Inconsistent share lengths")]
    InconsistentShareLength,

    /// Compression error
    #[error("Compression error: {0}")]
    CompressionError(String),

    /// Decompression error
    #[error("Decompression error: {0}")]
    DecompressionError(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Secure random number generator failure
    #[error("RNG error: {0}")]
    RngError(String),
}

pub type Result<T> = std::result::Result<T, ShamirError>;
