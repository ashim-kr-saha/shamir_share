//! A secure and efficient Rust library for Shamir's Secret Sharing
//!
//! This library provides an implementation of Shamir's Secret Sharing scheme,
//! allowing sensitive data to be split into multiple shares, where a threshold
//! number of shares is required to reconstruct the original data.
//!
//! # Quick Start
//!
//! ```
//! use shamir_share::{ShamirShare, FileShareStore, ShareStore};
//!
//! // Create a scheme with 5 shares and threshold 3
//! let mut scheme = ShamirShare::new(5, 3).unwrap();
//!
//! // Split a secret
//! let secret = b"my secret data";
//! let shares = scheme.split(secret).unwrap();
//!
//! // Store shares
//! let temp_dir = tempfile::tempdir().unwrap();
//! let mut store = FileShareStore::new(temp_dir.path()).unwrap();
//! for share in &shares {
//!     store.store_share(share).unwrap();
//! }
//!
//! // Reconstruct from 3 shares
//! let loaded_shares = vec![
//!     store.load_share(1).unwrap(),
//!     store.load_share(2).unwrap(),
//!     store.load_share(3).unwrap(),
//! ];
//! let reconstructed = ShamirShare::reconstruct(&loaded_shares).unwrap();
//! assert_eq!(reconstructed, secret);
//! ```

mod config;
mod error;
mod finite_field;
mod shamir;
mod storage;

pub use config::{Config, SplitMode};
pub use error::{Result, ShamirError};
pub use finite_field::FiniteField;
pub use shamir::{ShamirShare, Share};
pub use storage::{FileShareStore, ShareStore};

// Re-export common types for convenience
pub mod prelude {
    pub use super::{
        Config, FileShareStore, Result, ShamirError, ShamirShare, Share, ShareStore, SplitMode,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_full_workflow() -> Result<()> {
        // Create a temporary directory for storing shares
        let temp_dir = tempdir()?;
        let mut store = FileShareStore::new(temp_dir.path())?;

        // Create secret data
        let secret = b"This is a secret message that needs to be protected!";

        // Configure Shamir's Secret Sharing
        let mut shamir = ShamirShare::new(5, 3)?;

        // Split the secret into shares
        let shares = shamir.split(secret)?;

        // Store all shares
        for share in &shares {
            store.store_share(share)?;
        }

        // List available shares
        let available_shares = store.list_shares()?;
        assert_eq!(available_shares.len(), 5);

        // Load a subset of shares for reconstruction
        let mut reconstruction_shares = Vec::new();
        for &index in &available_shares[0..3] {
            reconstruction_shares.push(store.load_share(index)?);
        }

        // Reconstruct the secret
        let reconstructed = ShamirShare::reconstruct(&reconstruction_shares)?;
        assert_eq!(&reconstructed, secret);

        Ok(())
    }

    #[test]
    fn test_with_config() -> Result<()> {
        let temp_dir = tempdir()?;
        let mut store = FileShareStore::new(temp_dir.path())?;

        // Create a custom configuration
        let _config = Config::new()
            .with_chunk_size(1024)?
            .with_mode(SplitMode::Sequential)
            .with_compression(true)
            .with_integrity_check(true);

        // Create and split secret
        let secret = b"Secret data with custom configuration";
        let mut shamir = ShamirShare::new(5, 3)?;
        let shares = shamir.split(secret)?;

        // Store and reconstruct
        for share in &shares {
            store.store_share(share)?;
        }

        let mut loaded_shares = Vec::new();
        for i in 1..=3 {
            loaded_shares.push(store.load_share(i)?);
        }

        let reconstructed = ShamirShare::reconstruct(&loaded_shares)?;
        assert_eq!(&reconstructed, secret);

        Ok(())
    }

    #[test]
    fn test_error_handling() {
        // Test invalid parameters
        assert!(matches!(
            ShamirShare::new(2, 3),
            Err(ShamirError::ThresholdTooLarge { .. })
        ));

        // Test invalid share reconstruction
        let mut shamir = ShamirShare::new(5, 3).unwrap();
        let shares = shamir.split(b"test").unwrap();

        // Try to reconstruct with insufficient shares
        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..2]),
            Err(ShamirError::InsufficientShares { .. })
        ));
    }
}
