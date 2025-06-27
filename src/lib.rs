//! A secure and efficient Rust library for Shamir's Secret Sharing
//!
//! This library provides a security-first implementation of Shamir's Secret Sharing scheme
//! with constant-time operations to prevent side-channel attacks. Split sensitive data
//! into multiple shares where only a threshold number is needed for reconstruction.
//!
//! ## Security Features
//!
//! - **Constant-time GF(2^8) arithmetic** - No lookup tables, resistant to cache-timing attacks
//! - **Cryptographically secure random generation** - Uses ChaCha20Rng seeded from OsRng  
//! - **Integrity verification** - SHA-256 hash checking with constant-time comparison
//! - **Memory safety** - Written in safe Rust with zero unsafe blocks
//!
//! # Quick Start
//!
//! ## Basic Usage
//! ```
//! use shamir_share::{ShamirShare, FileShareStore, ShareStore};
//!
//! // Create a scheme with 5 shares and threshold 3
//! let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
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
//!
//! ## Lazy Share Generation with Dealer
//! ```
//! use shamir_share::ShamirShare;
//!
//! let mut scheme = ShamirShare::builder(10, 5).build().unwrap();
//! let secret = b"my secret data";
//!
//! // Generate only the shares you need
//! let shares: Vec<_> = scheme.dealer(secret).take(5).collect();
//!
//! // Or use iterator methods for advanced filtering
//! let even_shares: Vec<_> = scheme.dealer(secret)
//!     .filter(|share| share.index % 2 == 0)
//!     .take(5)
//!     .collect();
//!
//! let reconstructed = ShamirShare::reconstruct(&shares).unwrap();
//! assert_eq!(reconstructed, secret);
//! ```

mod config;
mod error;
mod finite_field;
pub mod hsss;
mod shamir;
mod storage;

pub use config::{Config, SplitMode};
pub use error::{Result, ShamirError};
pub use finite_field::FiniteField;
pub use hsss::{AccessLevel, HierarchicalShare, Hsss, HsssBuilder};
pub use shamir::{Dealer, ShamirShare, ShamirShareBuilder, Share};
pub use storage::{FileShareStore, ShareStore};

// Re-export common types for convenience
pub mod prelude {
    pub use super::{
        AccessLevel, Config, Dealer, FileShareStore, HierarchicalShare, Hsss, HsssBuilder, Result,
        ShamirError, ShamirShare, ShamirShareBuilder, Share, ShareStore, SplitMode,
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
        let mut shamir = ShamirShare::builder(5, 3).build()?;

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
        let mut shamir = ShamirShare::builder(5, 3).build()?;
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
            ShamirShare::builder(2, 3).build(),
            Err(ShamirError::ThresholdTooLarge { .. })
        ));

        // Test invalid share reconstruction
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(b"test").unwrap();

        // Try to reconstruct with insufficient shares
        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..2]),
            Err(ShamirError::InsufficientShares { .. })
        ));
    }
}
