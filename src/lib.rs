//! A secure and efficient Rust library for Shamir's Secret Sharing
//!
//! This library provides a security-first implementation of Shamir's Secret Sharing scheme
//! with constant-time operations to prevent side-channel attacks. Split sensitive data
//! into multiple shares where only a threshold number is needed for reconstruction.
//!
//! ## Security Features
//!
//! - **Constant-time GF(2^8) arithmetic** - Eliminates lookup tables and secret-dependent branches to prevent cache-timing attacks
//! - **Cryptographically secure random generation** - Uses `ChaCha20Rng` seeded from system entropy (`SysRng`) or caller-provided RNG
//! - **Corruption detection** - SHA-256 digest verification with constant-time comparison (`subtle::ConstantTimeEq`) to detect accidental bit-rot and framing desynchronization
//! - **Canonical wire format** - Self-contained zero-dependency binary serialization via `Share::to_bytes()` and `Share::from_bytes()`
//! - **Memory hygiene** - Securely clears sensitive buffers on drop with fallback zeroization and optional `zeroize` crate integration
//! - **Memory safety** - Written in 100% safe Rust with zero unsafe blocks (`#![forbid(unsafe_code)]`)
//! - **Embedded & Enclave Ready** - Full `#![no_std]` + `alloc` support for embedded devices, hardware wallets, and WebAssembly
//!
//! # Quick Start
//!
//! ## Basic Usage
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use shamir_share::{ShamirShare, Share};
//!
//! // Create a scheme with 5 shares and threshold 3
//! let scheme = ShamirShare::builder(5, 3).build().unwrap();
//!
//! // Split a secret
//! let secret = b"my secret data";
//! let shares = scheme.split(secret).unwrap();
//!
//! // Serialize shares to canonical bytes
//! let serialized_shares: Vec<Vec<u8>> = shares.iter().map(|s| s.to_bytes()).collect();
//!
//! // Deserialize and reconstruct from 3 shares
//! let loaded_shares: Vec<Share> = serialized_shares[0..3]
//!     .iter()
//!     .map(|b| Share::from_bytes(b).unwrap())
//!     .collect();
//! let reconstructed = ShamirShare::reconstruct(&loaded_shares).unwrap();
//! assert_eq!(reconstructed.as_slice(), secret);
//! # }
//! ```
//!
//! ## Lazy Share Generation with Dealer
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use shamir_share::ShamirShare;
//!
//! let scheme = ShamirShare::builder(10, 5).build().unwrap();
//! let secret = b"my secret data";
//!
//! // Generate only the shares you need
//! let shares: Vec<_> = scheme.try_dealer(secret).unwrap().take(5).collect();
//!
//! // Or use iterator methods for advanced filtering
//! let even_shares: Vec<_> = scheme.try_dealer(secret).unwrap()
//!     .filter(|share| share.index % 2 == 0)
//!     .take(5)
//!     .collect();
//!
//! let reconstructed = ShamirShare::reconstruct(&shares).unwrap();
//! assert_eq!(reconstructed.as_slice(), secret);
//! # }
//! ```

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

#[cfg(feature = "zeroize")]
pub use zeroize::Zeroizing;

#[cfg(not(feature = "zeroize"))]
pub trait ZeroizeFallback {
    fn zeroize_fallback(&mut self);
}

#[cfg(not(feature = "zeroize"))]
impl<T: AsMut<[u8]>> ZeroizeFallback for T {
    fn zeroize_fallback(&mut self) {
        let slice = self.as_mut();
        for b in slice.iter_mut() {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            *b = 0;
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(not(feature = "zeroize"))]
pub struct Zeroizing<T: ZeroizeFallback>(pub T);

#[cfg(not(feature = "zeroize"))]
impl<T: ZeroizeFallback> Zeroizing<T> {
    pub fn new(val: T) -> Self {
        Self(val)
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ZeroizeFallback + Clone> Clone for Zeroizing<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ZeroizeFallback + PartialEq> PartialEq for Zeroizing<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ZeroizeFallback + Eq> Eq for Zeroizing<T> {}

#[cfg(not(feature = "zeroize"))]
impl<T: ZeroizeFallback> core::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Zeroizing { .. }")
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ZeroizeFallback> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize_fallback();
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ZeroizeFallback> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ZeroizeFallback> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

mod config;
mod error;
mod finite_field;
#[cfg(feature = "hsss")]
pub mod hsss;
mod shamir;

pub use config::{Config, MAX_CONFIG_CHUNK_SIZE, MAX_DEFAULT_STREAM_DECOMPRESSED_SIZE, SplitMode};
pub use error::{Result, ShamirError};
pub use finite_field::FiniteField;
#[cfg(feature = "hsss")]
pub use hsss::{AccessLevel, HierarchicalShare, Hsss, HsssBuilder};
pub use shamir::{
    Dealer, MAX_SHARE_DATA_LEN, SHARE_WIRE_MAGIC, SHARE_WIRE_VERSION, ShamirShare,
    ShamirShareBuilder, Share, ShareView,
};

#[cfg(feature = "streaming")]
pub use shamir::{STREAM_ID_SIZE, STREAM_MAGIC, STREAM_VERSION};

// Re-export common types for convenience
pub mod prelude {
    #[cfg(feature = "hsss")]
    pub use super::{AccessLevel, HierarchicalShare, Hsss, HsssBuilder};
    pub use super::{
        Config, Dealer, FiniteField, MAX_SHARE_DATA_LEN, Result, SHARE_WIRE_MAGIC,
        SHARE_WIRE_VERSION, ShamirError, ShamirShare, ShamirShareBuilder, Share, ShareView,
        SplitMode, Zeroizing,
    };
    #[cfg(feature = "streaming")]
    pub use super::{STREAM_ID_SIZE, STREAM_MAGIC, STREAM_VERSION};
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn test_full_workflow() -> Result<()> {
        let secret = b"This is a secret message that needs to be protected!";

        // Configure Shamir's Secret Sharing
        let shamir = ShamirShare::builder(5, 3).build()?;

        // Split the secret into shares
        let shares = shamir.split(secret)?;

        // Serialize all shares to canonical wire format
        let mut serialized = Vec::new();
        for share in &shares {
            serialized.push(share.to_bytes());
        }
        assert_eq!(serialized.len(), 5);

        // Deserialize a subset of shares for reconstruction
        let mut reconstruction_shares = Vec::new();
        for bytes in &serialized[0..3] {
            reconstruction_shares.push(Share::from_bytes(bytes)?);
        }

        // Reconstruct the secret
        let reconstructed = ShamirShare::reconstruct(&reconstruction_shares)?;
        assert_eq!(reconstructed.as_slice(), secret);

        Ok(())
    }

    #[test]
    fn test_with_config() -> Result<()> {
        // Create a custom configuration
        #[allow(unused_mut)]
        let mut config = Config::new()
            .with_chunk_size(1024)?
            .with_mode(SplitMode::Sequential)
            .with_integrity_check(true);

        #[cfg(feature = "compress")]
        {
            config = config.with_compression(true);
        }

        // Create and split secret
        let secret = b"Secret data with custom configuration";
        let shamir = ShamirShare::builder(5, 3).with_config(config).build()?;
        let shares = shamir.split(secret)?;

        // Serialize and reconstruct
        let mut loaded_shares = Vec::new();
        for share in &shares[0..3] {
            let bytes = share.to_bytes();
            loaded_shares.push(Share::from_bytes(&bytes)?);
        }

        let reconstructed = ShamirShare::reconstruct(&loaded_shares)?;
        assert_eq!(reconstructed.as_slice(), secret);

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
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(b"test").unwrap();

        // Try to reconstruct with insufficient shares
        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..2]),
            Err(ShamirError::InsufficientShares { .. })
        ));
    }
}
