use crate::config::{Config, SplitMode};
use crate::error::{Result, ShamirError};
use crate::finite_field::FiniteField;
use rand::TryRng;
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};
use rayon::iter::ParallelIterator;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use subtle::ConstantTimeEq;

use crate::Zeroizing;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

const HASH_SIZE: usize = 32; // SHA-256 output size
const SALT_SIZE: usize = 32; // Ephemeral 256-bit salt for in-memory shares (F-01, F-02)
const STREAM_CHUNK_SALT_SIZE: usize = 16; // Ephemeral 128-bit chunk salt for streams (F-01, F-02)
const MAX_STREAM_CHUNK_SIZE: usize = (64 * 1024 * 1024) + (256 * 1024) + 256;
#[cfg(feature = "compress")]
const MAX_DECOMPRESSED_CHUNK_SIZE: u64 = 64 * 1024 * 1024; // 64 MiB cap for decompression

/// Magic bytes for the binary stream framing format ("SHS_STR")
pub const STREAM_MAGIC: &[u8; 7] = b"SHS_STR";
/// Current version of the streaming format
pub const STREAM_VERSION: u8 = 2;
/// Byte size of the unique stream identifier (128 bits)
pub const STREAM_ID_SIZE: usize = 16;

/// A share in Shamir's Secret Sharing scheme
///
/// Each share contains a portion of the secret data along with metadata needed for reconstruction.
/// Individual shares reveal no information about the original secret without meeting the threshold.
///
/// # Security
///
/// - Share data is computed using constant-time GF(2^8) arithmetic
/// - Contains integrity metadata to detect corruption during reconstruction
/// - Secret data in memory is zeroized on drop when the `zeroize` feature is enabled
/// - Debug formatting redacts raw secret data to prevent accidental leakage in logs
/// - Implements constant-time equality comparisons (`subtle::ConstantTimeEq`)
/// - Safe to store and transmit independently
///
/// # Example
/// ```
/// use shamir_share::{Share, ShamirShare};
///
/// let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
/// let shares = shamir.split(b"secret").unwrap();
/// let share = &shares[0];
///
/// assert_eq!(share.index, 1);
/// assert_eq!(share.threshold, 3);
/// assert_eq!(share.total_shares, 5);
/// ```
#[non_exhaustive]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Share {
    /// Index of the share (x-coordinate in the polynomial, 1..=255)
    pub index: u8,
    /// The share data (y-coordinates for each byte of the secret)
    pub data: Vec<u8>,
    /// Minimum number of shares required for reconstruction (>= 2)
    pub threshold: u8,
    /// Total number of shares created (>= 2)
    pub total_shares: u8,
    /// Whether integrity checking was enabled when this share was created
    pub integrity_check: bool,
    /// Whether the data was compressed before splitting
    pub compression: bool,
}

impl ConstantTimeEq for Share {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let index_eq = self.index.ct_eq(&other.index);
        let threshold_eq = self.threshold.ct_eq(&other.threshold);
        let total_shares_eq = self.total_shares.ct_eq(&other.total_shares);
        let integrity_eq = (self.integrity_check as u8).ct_eq(&(other.integrity_check as u8));
        let compression_eq = (self.compression as u8).ct_eq(&(other.compression as u8));
        let data_eq = self.data.ct_eq(&other.data);

        index_eq & threshold_eq & total_shares_eq & integrity_eq & compression_eq & data_eq
    }
}

impl PartialEq for Share {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for Share {}

impl Share {
    /// Creates a new share with the given parameters
    pub fn new(
        index: u8,
        data: Vec<u8>,
        threshold: u8,
        total_shares: u8,
        integrity_check: bool,
        compression: bool,
    ) -> Self {
        Self {
            index,
            data,
            threshold,
            total_shares,
            integrity_check,
            compression,
        }
    }

    /// Creates a borrowed, zero-allocation view of this share
    #[inline]
    pub fn as_view(&self) -> ShareView<'_> {
        ShareView {
            index: self.index,
            data: &self.data,
            threshold: self.threshold,
            total_shares: self.total_shares,
            integrity_check: self.integrity_check,
            compression: self.compression,
        }
    }

    /// Applies a zero-polynomial delta share to this share in-place to refresh it.
    ///
    /// This enables decentralized proactive secret sharing without collecting
    /// secret shares into a central process.
    ///
    /// # Security
    /// Verifies that the delta share's index matches this share's index to prevent
    /// index confusion attacks.
    ///
    /// # Errors
    /// Returns [`ShamirError::InvalidShareIndex`] if `self.index != delta.index`.
    /// Returns [`ShamirError::InconsistentShareLength`] if `delta.data.len() != self.data.len()`.
    pub fn apply_refresh_delta(&mut self, delta: &Share) -> Result<()> {
        if self.index != delta.index {
            return Err(ShamirError::InvalidShareIndex(delta.index));
        }
        if delta.data.len() != self.data.len() {
            return Err(ShamirError::InconsistentShareLength);
        }
        for (b, d) in self.data.iter_mut().zip(&delta.data) {
            *b ^= d;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("data_len", &self.data.len())
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("integrity_check", &self.integrity_check)
            .field("compression", &self.compression)
            .finish()
    }
}

/// A lightweight view into share data for reconstruction without allocation
///
/// This struct provides a borrowed view of share data to avoid cloning during
/// reconstruction operations. It is used by `reconstruct_from_views` and
/// hierarchical secret sharing to eliminate allocation pressure.
///
/// # Security
///
/// - Maintains the same security properties as `Share`
/// - Uses borrowed data to avoid unnecessary allocations
/// - Constant-time equality operations are preserved
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct ShareView<'a> {
    /// Index of the share (x-coordinate in the polynomial, 1..=255)
    pub index: u8,
    /// Borrowed reference to the share data
    pub data: &'a [u8],
    /// Minimum number of shares required for reconstruction
    pub threshold: u8,
    /// Total number of shares created
    pub total_shares: u8,
    /// Whether integrity checking was enabled when this share was created
    pub integrity_check: bool,
    /// Whether the data was compressed before splitting
    pub compression: bool,
}

impl<'a> std::fmt::Debug for ShareView<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareView")
            .field("index", &self.index)
            .field("data_len", &self.data.len())
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("integrity_check", &self.integrity_check)
            .field("compression", &self.compression)
            .finish()
    }
}

impl<'a> ConstantTimeEq for ShareView<'a> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let index_eq = self.index.ct_eq(&other.index);
        let threshold_eq = self.threshold.ct_eq(&other.threshold);
        let total_shares_eq = self.total_shares.ct_eq(&other.total_shares);
        let integrity_eq = (self.integrity_check as u8).ct_eq(&(other.integrity_check as u8));
        let compression_eq = (self.compression as u8).ct_eq(&(other.compression as u8));
        let data_eq = self.data.ct_eq(other.data);

        index_eq & threshold_eq & total_shares_eq & integrity_eq & compression_eq & data_eq
    }
}

impl<'a> PartialEq for ShareView<'a> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl<'a> Eq for ShareView<'a> {}

/// Lazy iterator for generating shares using Shamir's Secret Sharing
///
/// The `Dealer` provides a memory-efficient way to generate shares on-demand without
/// storing all shares in memory at once. It pre-computes the polynomial coefficients
/// and evaluates them lazily for each requested share.
///
/// # Security
///
/// - Polynomial coefficients are generated once using cryptographically secure randomness
/// - Each share evaluation uses constant-time GF(2^8) arithmetic
/// - Respects `total_shares` configured in the builder (stopping after yielding `total_shares`)
///
/// # Example
/// ```
/// use shamir_share::ShamirShare;
///
/// let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
/// let secret = b"secret data";
///
/// // Generate shares lazily
/// let shares: Vec<_> = shamir.try_dealer(secret).unwrap().take(3).collect();
/// assert_eq!(shares.len(), 3);
///
/// // Reconstruct
/// let reconstructed = ShamirShare::reconstruct(&shares).unwrap();
/// assert_eq!(reconstructed.as_slice(), secret);
/// ```
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Dealer {
    /// The data to be split (with integrity hash if enabled)
    data: Vec<u8>,
    /// Pre-computed random polynomial coefficients for all bytes
    /// Layout: [byte0_coeff1, byte0_coeff2, ..., byte1_coeff1, byte1_coeff2, ...]
    coefficients: Vec<u8>,
    /// Current share index (x-coordinate), starts at 1
    current_x: u8,
    /// Threshold for reconstruction
    threshold: u8,
    /// Total shares configured
    total_shares: u8,
    /// Whether integrity checking is enabled
    integrity_check: bool,
    /// Whether the data was compressed before splitting
    compression: bool,
}

impl std::fmt::Debug for Dealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dealer")
            .field("current_x", &self.current_x)
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("integrity_check", &self.integrity_check)
            .field("compression", &self.compression)
            .finish()
    }
}

/// Main implementation of Shamir's Secret Sharing scheme
///
/// This implementation prioritizes security with constant-time operations to prevent
/// side-channel attacks. Uses GF(256) arithmetic for polynomial operations and
/// ChaCha20 CSPRNG for generating polynomial coefficients.
///
/// # Security Features
///
/// - **Constant-time operations**: All GF(2^8) arithmetic uses constant-time algorithms
/// - **Secure random generation**: ChaCha20Rng seeded from SysRng for polynomial coefficients
/// - **Integrity verification**: SHA-256 hash prepended to secret with constant-time verification
/// - **Side-channel resistance**: No lookup tables or data-dependent branching
/// - **Memory hygiene**: Sensitive buffers are zeroized on drop
///
/// # Example
/// ```
/// use shamir_share::ShamirShare;
///
/// // Create a scheme with 5 total shares and threshold of 3
/// let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
///
/// // Split a secret
/// let secret = b"my secret data";
/// let shares = scheme.split(secret).unwrap();
///
/// // Reconstruct with 3 shares
/// let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
/// assert_eq!(reconstructed.as_slice(), secret);
/// ```
#[derive(Clone)]
pub struct ShamirShare {
    /// Total number of shares to generate
    total_shares: u8,
    /// Minimum number of shares needed for reconstruction
    threshold: u8,
    /// Configuration options for the sharing scheme
    config: Config,
}

impl std::fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShamirShare")
            .field("total_shares", &self.total_shares)
            .field("threshold", &self.threshold)
            .field("config", &self.config)
            .finish()
    }
}

/// Builder for configuring and creating ShamirShare instances
///
/// This builder pattern allows for flexible configuration of the Shamir's Secret Sharing
/// scheme while maintaining ergonomic defaults. Use `ShamirShare::builder()` to create
/// a new builder instance.
///
/// # Example
/// ```
/// use shamir_share::{ShamirShare, Config, SplitMode};
///
/// let config = Config::new()
///     .with_integrity_check(false)
///     .with_mode(SplitMode::Parallel);
///
/// let shamir = ShamirShare::builder(5, 3)
///     .with_config(config)
///     .build()
///     .unwrap();
/// ```
pub struct ShamirShareBuilder {
    total_shares: u8,
    threshold: u8,
    config: Config,
}

impl ShamirShareBuilder {
    /// Creates a new builder with the specified parameters and default configuration
    ///
    /// # Arguments
    /// * `total_shares` - Total number of shares to create (2-255)
    /// * `threshold` - Minimum shares required for reconstruction (2-total_shares)
    pub fn new(total_shares: u8, threshold: u8) -> Self {
        Self {
            total_shares,
            threshold,
            config: Config::default(),
        }
    }

    /// Sets a custom configuration for the ShamirShare instance
    ///
    /// # Arguments
    /// * `config` - Configuration options to use
    ///
    /// # Example
    /// ```
    /// use shamir_share::{ShamirShare, Config};
    ///
    /// let config = Config::new().with_integrity_check(false);
    /// let shamir = ShamirShare::builder(5, 3)
    ///     .with_config(config)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Builds the ShamirShare instance with validation
    ///
    /// # Returns
    /// A configured ShamirShare instance ready for use
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - `total_shares` is less than 2
    /// - `threshold` is less than 2
    /// - `threshold` > `total_shares`
    /// - Configuration validation fails
    pub fn build(self) -> Result<ShamirShare> {
        if self.total_shares < 2 {
            return Err(ShamirError::InvalidShareCount(self.total_shares));
        }
        if self.threshold < 2 {
            return Err(ShamirError::InvalidThreshold(self.threshold));
        }
        if self.threshold > self.total_shares {
            return Err(ShamirError::ThresholdTooLarge {
                threshold: self.threshold,
                total_shares: self.total_shares,
            });
        }

        self.config.validate()?;

        Ok(ShamirShare {
            total_shares: self.total_shares,
            threshold: self.threshold,
            config: self.config,
        })
    }
}

impl ShamirShare {
    #[inline]
    fn compute_digest(
        domain: &[u8],
        meta: &[u8],
        salt: &[u8],
        payload: &[u8],
        auth_key: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        if let Some(key) = auth_key {
            let mut ipad = [0x36u8; 64];
            let mut opad = [0x5cu8; 64];
            for i in 0..32 {
                ipad[i] ^= key[i];
                opad[i] ^= key[i];
            }
            let mut inner = Sha256::new();
            inner.update(ipad);
            inner.update(domain);
            inner.update(meta);
            inner.update(salt);
            inner.update(payload);
            let inner_hash = inner.finalize();

            let mut outer = Sha256::new();
            outer.update(opad);
            outer.update(inner_hash);
            outer.finalize().into()
        } else {
            let mut hasher = Sha256::new();
            hasher.update(domain);
            hasher.update(meta);
            hasher.update(salt);
            hasher.update(payload);
            hasher.finalize().into()
        }
    }

    #[inline]
    fn local_rng() -> Result<ChaCha20Rng> {
        ChaCha20Rng::try_from_rng(&mut SysRng).map_err(|e| ShamirError::RngError(e.to_string()))
    }

    #[cfg(feature = "compress")]
    fn decompress_bounded(payload: &[u8], max_limit: u64) -> Result<Zeroizing<Vec<u8>>> {
        let expected_size = zstd::stream::decompressed_size(payload);
        if let Some(size) = expected_size {
            if size > max_limit {
                return Err(ShamirError::DecompressionError(
                    "Decompressed payload exceeds allowed limit".into(),
                ));
            }
        }

        let initial_capacity = expected_size
            .map(|s| s as usize)
            .unwrap_or(4096)
            .min(64 * 1024)
            .min(max_limit as usize);

        let mut decompressed = Zeroizing::new(Vec::with_capacity(initial_capacity));
        let decoder = zstd::Decoder::new(payload)
            .map_err(|e| ShamirError::DecompressionError(e.to_string()))?;

        let mut limited_reader = decoder.take(max_limit + 1);
        let mut read_buf = Zeroizing::new([0u8; 16384]);

        loop {
            let n = limited_reader
                .read(&mut *read_buf)
                .map_err(|e| ShamirError::DecompressionError(e.to_string()))?;
            if n == 0 {
                break;
            }
            if (decompressed.len() as u64) + (n as u64) > max_limit {
                return Err(ShamirError::DecompressionError(
                    "Decompressed payload exceeds allowed limit".into(),
                ));
            }
            if decompressed.capacity() - decompressed.len() < n {
                let new_cap = (decompressed.capacity() * 2)
                    .max(decompressed.len() + n)
                    .min(max_limit as usize);
                let mut new_decompressed = Zeroizing::new(Vec::with_capacity(new_cap));
                new_decompressed.extend_from_slice(&decompressed);
                decompressed = new_decompressed;
            }
            decompressed.extend_from_slice(&read_buf[..n]);
        }

        Ok(decompressed)
    }

    /// Returns the threshold (minimum number of shares needed for reconstruction)
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Returns the total number of shares configured for this scheme
    pub fn total_shares(&self) -> u8 {
        self.total_shares
    }

    /// Returns a reference to the configuration options for this scheme
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Creates a builder for configuring a ShamirShare instance
    ///
    /// This is the recommended way to create ShamirShare instances as it allows
    /// for flexible configuration through the builder pattern.
    ///
    /// # Arguments
    /// * `total_shares` - Total number of shares to create (2-255)
    /// * `threshold` - Minimum shares required for reconstruction (2-total_shares)
    ///
    /// # Example
    /// ```
    /// use shamir_share::{ShamirShare, Config};
    ///
    /// // With default configuration
    /// let shamir = ShamirShare::builder(5, 3).build().unwrap();
    ///
    /// // With custom configuration
    /// let config = Config::new().with_integrity_check(false);
    /// let shamir = ShamirShare::builder(5, 3)
    ///     .with_config(config)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder(total_shares: u8, threshold: u8) -> ShamirShareBuilder {
        ShamirShareBuilder::new(total_shares, threshold)
    }

    /// Creates a lazy iterator for generating shares on-demand
    ///
    /// This method provides a memory-efficient way to generate shares without storing
    /// all of them in memory at once. The dealer pre-computes polynomial coefficients
    /// and evaluates them lazily for each requested share.
    ///
    /// Returns a `Result` containing the [`Dealer`] iterator, or a [`ShamirError`] if
    /// compression fails, random number generator seeding fails, or allocation overflows.
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    ///
    /// let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
    /// let secret = b"secret data";
    ///
    /// let shares: Vec<_> = scheme.try_dealer(secret).unwrap().take(3).collect();
    /// assert_eq!(shares.len(), 3);
    /// ```
    pub fn try_dealer(&self, secret: &[u8]) -> Result<Dealer> {
        if secret.len() > crate::config::MAX_CONFIG_CHUNK_SIZE {
            return Err(ShamirError::InvalidConfig(format!(
                "Secret length {} exceeds maximum in-memory size {}; use split_stream instead",
                secret.len(),
                crate::config::MAX_CONFIG_CHUNK_SIZE
            )));
        }

        let payload = Zeroizing::new(if self.config.compression() {
            #[cfg(feature = "compress")]
            {
                zstd::encode_all(secret, 0)
                    .map_err(|e| ShamirError::CompressionError(e.to_string()))?
            }
            #[cfg(not(feature = "compress"))]
            {
                return Err(ShamirError::InvalidConfig(
                    "Compression requested but crate was compiled without 'compress' feature"
                        .into(),
                ));
            }
        } else {
            secret.to_vec()
        });

        let integrity_flag = if self.config.integrity_check() { 1 } else { 0 };
        let compression_flag = if self.config.compression() { 2 } else { 0 };
        let flags = integrity_flag | compression_flag;

        let mut data_to_split =
            Zeroizing::new(Vec::with_capacity(if self.config.integrity_check() {
                SALT_SIZE + HASH_SIZE + payload.len()
            } else {
                payload.len()
            }));

        if self.config.integrity_check() {
            let mut salt = Zeroizing::new([0u8; SALT_SIZE]);
            SysRng
                .try_fill_bytes(&mut *salt)
                .map_err(|e| ShamirError::RngError(e.to_string()))?;

            let domain = if self.config.authentication_key().is_some() {
                b"SHS1_HMAC_V3\0".as_slice()
            } else {
                b"SHS1_KEYED_V3\0".as_slice()
            };
            let hash = Self::compute_digest(
                domain,
                &[flags, self.threshold, self.total_shares],
                &*salt,
                &payload,
                self.config.authentication_key(),
            );

            data_to_split.extend_from_slice(&*salt);
            data_to_split.extend_from_slice(&hash);
        }
        data_to_split.extend_from_slice(&payload);

        let secret_len = data_to_split.len();
        let t = self.threshold as usize;
        let num_coeffs = secret_len.checked_mul(t - 1).ok_or_else(|| {
            ShamirError::InvalidConfig("Data length overflow in coefficient generation".into())
        })?;

        if num_coeffs > crate::config::MAX_CONFIG_CHUNK_SIZE {
            return Err(ShamirError::InvalidConfig(format!(
                "Total coefficient memory {} bytes exceeds maximum allowed buffer size of {} bytes; use streaming instead",
                num_coeffs,
                crate::config::MAX_CONFIG_CHUNK_SIZE
            )));
        }

        let mut coefficients = vec![0u8; num_coeffs];
        let mut rng = Self::local_rng()?;
        rng.fill_bytes(&mut coefficients);

        Ok(Dealer {
            data: std::mem::take(&mut data_to_split),
            coefficients,
            current_x: 1,
            threshold: self.threshold,
            total_shares: self.total_shares,
            integrity_check: self.config.integrity_check(),
            compression: self.config.compression(),
        })
    }

    /// Splits a secret into multiple shares using polynomial interpolation
    ///
    /// This method uses constant-time GF(2^8) arithmetic and cryptographically secure
    /// random number generation to create shares. If `config.integrity_check` is enabled,
    /// a SHA-256 hash is prepended to the secret for integrity verification during reconstruction.
    ///
    /// # Arguments
    /// * `secret` - Byte slice to protect
    ///
    /// # Returns
    /// Vector of [`Share`] objects containing the split data
    ///
    /// # Security
    /// - Uses ChaCha20Rng reseeded from SysRng for generating polynomial coefficients
    /// - All operations are constant-time to prevent side-channel attacks
    /// - Evaluates polynomial across threads when `SplitMode::Parallel` is configured
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    ///
    /// let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
    /// let shares = scheme.split(b"secret data").unwrap();
    /// assert_eq!(shares.len(), 5);
    /// ```
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Share>> {
        match self.config.mode() {
            SplitMode::Parallel => {
                let dealer = self.try_dealer(secret)?;
                let data = &dealer.data;
                let coefficients = &dealer.coefficients;
                let t = dealer.threshold as usize;
                let total_shares = dealer.total_shares;
                let integrity_check = dealer.integrity_check;
                let compression = dealer.compression;
                let secret_len = data.len();

                let shares: Vec<Share> = (1..=total_shares)
                    .into_par_iter()
                    .map(|x_val| {
                        let x = FiniteField::new(x_val);
                        let share_data: Vec<u8> = (0..secret_len)
                            .map(|byte_idx| {
                                let mut acc =
                                    FiniteField::new(coefficients[byte_idx * (t - 1) + (t - 2)]);
                                for j in (1..t - 1).rev() {
                                    let coeff = FiniteField::new(
                                        coefficients[byte_idx * (t - 1) + (j - 1)],
                                    );
                                    acc = acc * x + coeff;
                                }
                                acc = acc * x + FiniteField::new(data[byte_idx]);
                                acc.0
                            })
                            .collect();

                        Share {
                            index: x_val,
                            data: share_data,
                            threshold: t as u8,
                            total_shares,
                            integrity_check,
                            compression,
                        }
                    })
                    .collect();

                Ok(shares)
            }
            _ => {
                let dealer = self.try_dealer(secret)?;
                Ok(dealer.collect())
            }
        }
    }

    /// Reconstructs the original secret from shares using Lagrange interpolation
    ///
    /// This method uses constant-time GF(2^8) arithmetic for reconstruction and performs
    /// integrity verification using constant-time hash comparison to detect accidental bit-rot
    /// and tampering if the shares were created with integrity checking enabled.
    ///
    /// Note that if more than `threshold` shares are provided, only the first `threshold` shares
    /// in the slice are evaluated during interpolation and validation.
    ///
    /// # Arguments
    /// * `shares` - Slice of shares to use for reconstruction
    ///
    /// # Returns
    /// The original secret data if reconstruction and integrity verification succeed
    ///
    /// # Security
    /// - All GF(2^8) operations are constant-time
    /// - SHA-256 integrity verification with constant-time comparison before decompression
    /// - Rejects indices with value 0 and duplicate indices
    /// - Rejects threshold < 2 and verifies all share metadata matches
    ///
    /// # Security Note
    /// This static method derives threshold, total shares, and integrity/compression flags
    /// directly from share headers. In hostile-input or multi-tenant environments where
    /// shares may be untrusted, use [`reconstruct_with_scheme`](Self::reconstruct_with_scheme)
    /// to enforce strict scheme validation.
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - No shares provided or fewer shares than threshold
    /// - Share threshold < 2 or threshold > total_shares
    /// - Shares have inconsistent lengths, thresholds, or integrity settings
    /// - Share index is 0 or duplicate indices are provided
    /// - Integrity check fails (tampering or corruption detected)
    /// - Decompression fails or bomb threshold exceeded (> 64 MiB)
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    ///
    /// let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
    /// let shares = scheme.split(b"data").unwrap();
    ///
    /// // Reconstruct with first 3 shares
    /// let secret = ShamirShare::reconstruct(&shares[0..3]).unwrap();
    /// assert_eq!(secret.as_slice(), b"data");
    /// ```
    pub fn reconstruct(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
        let views: Vec<ShareView<'_>> = shares.iter().map(|s| s.as_view()).collect();
        Self::reconstruct_from_views(&views)
    }

    /// Reconstructs the original secret from borrowed `ShareView`s without cloning share data
    ///
    /// This method performs identical validation and reconstruction as [`reconstruct`](Self::reconstruct),
    /// but operates on borrowed slice views to avoid memory allocations and deep cloning.
    ///
    /// Note that if more than `threshold` views are provided, only the first `threshold` views
    /// in the slice are evaluated during interpolation and validation.
    ///
    /// # Arguments
    /// * `views` - Slice of borrowed share views
    pub fn reconstruct_from_views(views: &[ShareView<'_>]) -> Result<Zeroizing<Vec<u8>>> {
        Self::reconstruct_from_views_with_mode(views, SplitMode::default(), None)
    }

    /// Reconstructs the secret while strictly validating share metadata against the scheme's parameters
    ///
    /// Unlike the static [`reconstruct`](Self::reconstruct), this method enforces that every share's
    /// threshold, total_shares, integrity_check, and compression flags match `self.threshold`,
    /// `self.total_shares`, and `self.config`.
    ///
    /// # Errors
    /// Returns [`ShamirError::InsufficientShares`] if fewer than `self.threshold` shares are provided.
    /// Returns [`ShamirError::InvalidShareFormat`] if any share's metadata differs from the scheme.
    pub fn reconstruct_with_scheme(&self, shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
        let views: Vec<ShareView<'_>> = shares.iter().map(|s| s.as_view()).collect();
        self.reconstruct_from_views_with_scheme(&views)
    }

    /// Reconstructs the secret from `ShareView`s while strictly validating against the scheme's parameters
    pub fn reconstruct_from_views_with_scheme(
        &self,
        views: &[ShareView<'_>],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if views.is_empty() {
            return Err(ShamirError::InsufficientShares {
                needed: self.threshold,
                got: 0,
            });
        }

        if views.len() < self.threshold as usize {
            return Err(ShamirError::InsufficientShares {
                needed: self.threshold,
                got: u8::try_from(views.len()).unwrap_or(u8::MAX),
            });
        }

        if views.len() > self.total_shares as usize {
            return Err(ShamirError::InvalidShareFormat);
        }

        for v in views {
            if v.threshold != self.threshold
                || v.total_shares != self.total_shares
                || v.integrity_check != self.config.integrity_check()
                || v.compression != self.config.compression()
            {
                return Err(ShamirError::InvalidShareFormat);
            }
        }

        Self::reconstruct_from_views_with_mode(views, self.config.mode(), Some(self))
    }

    fn reconstruct_from_views_with_mode(
        views: &[ShareView<'_>],
        mode: SplitMode,
        scheme: Option<&ShamirShare>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if views.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 2, got: 0 });
        }

        let threshold = views[0].threshold;
        let total_shares = views[0].total_shares;
        let integrity_check = views[0].integrity_check;
        let compression = views[0].compression;
        let data_len = views[0].data.len();

        if threshold < 2 || threshold > total_shares {
            return Err(ShamirError::InvalidThreshold(threshold));
        }

        if views.len() < threshold as usize {
            return Err(ShamirError::InsufficientShares {
                needed: threshold,
                got: views.len() as u8,
            });
        }

        if views.len() > total_shares as usize {
            return Err(ShamirError::InvalidShareFormat);
        }

        if let Some(s) = scheme {
            if threshold != s.threshold
                || total_shares != s.total_shares
                || integrity_check != s.config.integrity_check()
                || compression != s.config.compression()
            {
                return Err(ShamirError::InvalidShareFormat);
            }
        } else if !integrity_check {
            return Err(ShamirError::InvalidShareFormat);
        }

        for v in views {
            if v.threshold != threshold
                || v.total_shares != total_shares
                || v.integrity_check != integrity_check
                || v.compression != compression
            {
                return Err(ShamirError::InvalidShareFormat);
            }
            if v.data.len() != data_len {
                return Err(ShamirError::InconsistentShareLength);
            }
            if v.index == 0 || v.index > total_shares {
                return Err(ShamirError::InvalidShareIndex(v.index));
            }
        }

        for i in 0..views.len() {
            for j in (i + 1)..views.len() {
                if views[i].index == views[j].index {
                    return Err(ShamirError::InvalidShareFormat);
                }
            }
        }

        let active_views = &views[..threshold as usize];
        let reconstructed_data = Self::reconstruct_chunk_from_views_with_mode(active_views, mode)?;

        // F-05: Verify all excess supplied views against the reconstructed polynomial using constant-time comparison
        if views.len() > threshold as usize {
            for excess_view in &views[threshold as usize..] {
                let mut alt_views = active_views.to_vec();
                alt_views[0] = *excess_view;
                let alt_reconstructed =
                    Self::reconstruct_chunk_from_views_with_mode(&alt_views, mode)?;
                if !bool::from(
                    alt_reconstructed
                        .as_slice()
                        .ct_eq(reconstructed_data.as_slice()),
                ) {
                    return Err(ShamirError::IntegrityCheckFailed);
                }
            }
        }

        if integrity_check {
            if reconstructed_data.len() < SALT_SIZE + HASH_SIZE {
                return Err(ShamirError::IntegrityCheckFailed);
            }
            let salt = &reconstructed_data[..SALT_SIZE];
            let expected_hash = &reconstructed_data[SALT_SIZE..SALT_SIZE + HASH_SIZE];
            let payload = &reconstructed_data[SALT_SIZE + HASH_SIZE..];

            let flags = (if integrity_check { 1 } else { 0 }) | (if compression { 2 } else { 0 });
            let auth_key = scheme.and_then(|s| s.config.authentication_key());
            let domain = if auth_key.is_some() {
                b"SHS1_HMAC_V3\0".as_slice()
            } else {
                b"SHS1_KEYED_V3\0".as_slice()
            };

            let calculated_hash = Self::compute_digest(
                domain,
                &[flags, threshold, total_shares],
                salt,
                payload,
                auth_key,
            );

            if !bool::from(calculated_hash.as_slice().ct_eq(expected_hash)) {
                return Err(ShamirError::IntegrityCheckFailed);
            }

            if compression {
                #[cfg(feature = "compress")]
                {
                    Self::decompress_bounded(payload, MAX_DECOMPRESSED_CHUNK_SIZE)
                }
                #[cfg(not(feature = "compress"))]
                {
                    Err(ShamirError::InvalidConfig(
                        "Share requires 'compress' feature to decompress".into(),
                    ))
                }
            } else {
                Ok(Zeroizing::new(payload.to_vec()))
            }
        } else if compression {
            #[cfg(feature = "compress")]
            {
                Self::decompress_bounded(&reconstructed_data, MAX_DECOMPRESSED_CHUNK_SIZE)
            }
            #[cfg(not(feature = "compress"))]
            {
                Err(ShamirError::InvalidConfig(
                    "Share requires 'compress' feature to decompress".into(),
                ))
            }
        } else {
            Ok(Zeroizing::new(reconstructed_data.to_vec()))
        }
    }

    /// Splits data from a stream into multiple share streams using chunk-based processing
    ///
    /// This method reads data from the source in chunks of `config.chunk_size`, splits each chunk
    /// independently, and writes the resulting shares to the destination writers. Each chunk is
    /// processed with optional integrity checking and written with length prefixes for reconstruction.
    ///
    /// # Arguments
    /// * `source` - Reader to read data from
    /// * `destinations` - Array of writers, one for each share (must equal `total_shares`)
    ///
    /// # Data Format
    /// Each destination stream begins with a 28-byte header followed by a sequence of length-prefixed chunks
    /// and a terminal zero-length end-of-stream (EOS) marker:
    /// ```text
    /// [7-byte magic b"SHS_STR"][1-byte version 2][16-byte random stream_id][1-byte flags][1-byte share index][1-byte threshold][1-byte total_shares]
    /// [4-byte length][share chunk 0 data]
    /// [4-byte length][share chunk 1 data]
    /// ...
    /// [4-byte length = 0] (EOS marker)
    /// ```
    /// - `magic`: ASCII `SHS_STR` (7 bytes)
    /// - `version`: Stream format version (`2`)
    /// - `stream_id`: 16-byte random nonce from `SysRng` binding chunks to this specific stream session
    /// - `flags`: Bit 0 = SHA-256 integrity check enabled; Bit 1 = zstd compression enabled; Bits 2-7 reserved
    /// - `share index`: 1-based index (x-coordinate) of this share stream
    /// - `threshold`: Minimum shares required for reconstruction (>= 2)
    /// - `total_shares`: Total number of shares produced (>= threshold)
    /// - Each chunk is prefixed by a 4-byte little-endian length followed by the share chunk bytes
    /// - The stream concludes with a 4-byte `0u32` length signifying clean completion
    ///
    /// # Security
    /// - Chunks bind the 16-byte `stream_id`, chunk sequence index, and terminal `is_last` flag into the SHA-256 / HMAC-SHA256 digest
    /// - Constant-time operations maintain side-channel security
    /// - Chunk-level integrity checking enables early detection of accidental bit-rot or framing desynchronization
    /// - Terminal EOS frame and authenticated final chunk prevent silent truncation attacks
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - Number of destinations does not match `total_shares`
    /// - I/O errors occur during reading, writing, or flushing
    /// - Compression fails or memory buffer overflow occurs
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    /// use std::io::Cursor;
    ///
    /// let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
    /// let data = b"This is a test message for streaming";
    /// let mut source = Cursor::new(data);
    /// let mut destinations = vec![Vec::new(); 3];
    /// let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
    ///     .iter_mut()
    ///     .map(|d| Cursor::new(std::mem::take(d)))
    ///     .collect();
    ///
    /// shamir.split_stream(&mut source, &mut dest_cursors).unwrap();
    /// ```
    pub fn split_stream<R: Read, W: Write>(
        &self,
        source: &mut R,
        destinations: &mut [W],
    ) -> Result<()> {
        let mut rng = Self::local_rng()?;
        if destinations.len() != self.total_shares as usize {
            return Err(ShamirError::InvalidConfig(format!(
                "Expected {} destinations, got {}",
                self.total_shares,
                destinations.len()
            )));
        }

        let integrity_flag = if self.config.integrity_check() { 1 } else { 0 };
        let compression_flag = if self.config.compression() { 2 } else { 0 };
        let flags = integrity_flag | compression_flag;

        let mut stream_id = Zeroizing::new([0u8; STREAM_ID_SIZE]);
        SysRng
            .try_fill_bytes(&mut *stream_id)
            .map_err(|e| ShamirError::RngError(e.to_string()))?;

        // Write 28-byte stream header to all destinations:
        // [STREAM_MAGIC: 7][STREAM_VERSION: 2][stream_id: 16][flags: 1][share_index: 1][threshold: 1][total_shares: 1]
        for (i, dest) in destinations.iter_mut().enumerate() {
            let mut header = [0u8; 28];
            header[0..7].copy_from_slice(STREAM_MAGIC);
            header[7] = STREAM_VERSION;
            header[8..24].copy_from_slice(&*stream_id);
            header[24] = flags;
            header[25] = (i + 1) as u8;
            header[26] = self.threshold;
            header[27] = self.total_shares;
            dest.write_all(&header).map_err(ShamirError::IoError)?;
        }

        let chunk_size = self.config.chunk_size();
        let mut current_chunk_buf = Zeroizing::new(vec![0u8; chunk_size]);
        let mut next_chunk_buf = Zeroizing::new(vec![0u8; chunk_size]);
        let mut share_data_buffers: Vec<Zeroizing<Vec<u8>>> = (0..self.total_shares)
            .map(|_| Zeroizing::new(Vec::new()))
            .collect();

        let mut current_bytes = 0;
        while current_bytes < chunk_size {
            match source.read(&mut current_chunk_buf[current_bytes..]) {
                Ok(0) => break,
                Ok(n) => current_bytes += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(ShamirError::IoError(e)),
            }
        }

        let mut chunk_index: u64 = 0;

        loop {
            let mut next_bytes = 0;
            if current_bytes > 0 {
                while next_bytes < chunk_size {
                    match source.read(&mut next_chunk_buf[next_bytes..]) {
                        Ok(0) => break,
                        Ok(n) => next_bytes += n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(ShamirError::IoError(e)),
                    }
                }
            }

            let is_last: u8 = if next_bytes == 0 { 1 } else { 0 };
            let raw_chunk = &current_chunk_buf[..current_bytes];

            let payload = Zeroizing::new(if self.config.compression() {
                #[cfg(feature = "compress")]
                {
                    zstd::encode_all(raw_chunk, 0)
                        .map_err(|e| ShamirError::CompressionError(e.to_string()))?
                }
                #[cfg(not(feature = "compress"))]
                {
                    return Err(ShamirError::InvalidConfig(
                        "Compression requested but crate was compiled without 'compress' feature"
                            .into(),
                    ));
                }
            } else {
                raw_chunk.to_vec()
            });

            let chunk_with_digest = Zeroizing::new(if self.config.integrity_check() {
                let mut chunk_salt = Zeroizing::new([0u8; STREAM_CHUNK_SALT_SIZE]);
                rng.fill_bytes(&mut *chunk_salt);

                let auth_key = self.config.authentication_key();
                let domain = if auth_key.is_some() {
                    b"SHS1_STR_HMAC_V2\0".as_slice()
                } else {
                    b"SHS1_STR_KEYED_V2\0".as_slice()
                };

                let mut meta = Vec::with_capacity(7 + 4 + 16 + 1 + 8);
                meta.extend_from_slice(STREAM_MAGIC);
                meta.extend_from_slice(&[STREAM_VERSION, flags, self.threshold, self.total_shares]);
                meta.extend_from_slice(&*stream_id);
                meta.push(is_last);
                meta.extend_from_slice(&chunk_index.to_le_bytes());

                let hash = Self::compute_digest(domain, &meta, &*chunk_salt, &payload, auth_key);

                let mut data =
                    Vec::with_capacity(STREAM_CHUNK_SALT_SIZE + HASH_SIZE + 1 + payload.len());
                data.extend_from_slice(&*chunk_salt);
                data.extend_from_slice(&hash);
                data.push(is_last);
                data.extend_from_slice(&payload);
                data
            } else {
                let mut nonce = Zeroizing::new([0u8; 8]);
                rng.fill_bytes(&mut *nonce);
                let mut data = Vec::with_capacity(8 + 1 + payload.len());
                data.extend_from_slice(&*nonce);
                data.push(is_last);
                data.extend_from_slice(&payload);
                data
            });

            self.split_chunk_into(&chunk_with_digest, &mut share_data_buffers, &mut rng)?;

            for (i, share_data) in share_data_buffers.iter().enumerate() {
                let length = u32::try_from(share_data.len()).map_err(|_| {
                    ShamirError::StorageError("Chunk share length exceeds u32::MAX".into())
                })?;
                destinations[i]
                    .write_all(&length.to_le_bytes())
                    .map_err(ShamirError::IoError)?;
                destinations[i]
                    .write_all(share_data)
                    .map_err(ShamirError::IoError)?;
            }

            if is_last == 1 {
                break;
            }

            std::mem::swap(&mut current_chunk_buf, &mut next_chunk_buf);
            current_bytes = next_bytes;
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| ShamirError::StorageError("Chunk index overflow".into()))?;
        }

        // Terminal EOS frame: length 0u32 signals clean end-of-stream
        for dest in destinations.iter_mut() {
            dest.write_all(&0u32.to_le_bytes())
                .map_err(ShamirError::IoError)?;
            dest.flush().map_err(ShamirError::IoError)?;
        }

        Ok(())
    }

    /// Reconstructs data from multiple share streams using chunk-based processing
    ///
    /// This method reads share data from multiple sources in lock-step, reconstructs each chunk
    /// independently, and writes the original data incrementally to the destination. It validates stream headers
    /// across all sources before reading chunks and verifies integrity digests prior to decompression.
    ///
    /// # Important
    /// Plaintext chunks are written incrementally to `destination` as each chunk is verified.
    /// If an error occurs midway through reconstruction (e.g. `IntegrityCheckFailed` or an unexpected EOF),
    /// the caller must discard the partially written data in `destination`.
    ///
    /// Note that if more than `threshold` stream sources are provided, only the first `threshold` sources
    /// in the slice are evaluated during reconstruction.
    ///
    /// # Arguments
    /// * `sources` - Array of readers, one for each share (must have at least `threshold` sources)
    /// * `destination` - Writer to write reconstructed data to
    ///
    /// # Data Format
    /// Each source stream must contain the format written by [`ShamirShare::split_stream`]:
    /// 28-byte stream header `[magic, version, stream_id, flags, index, threshold, total_shares]`,
    /// followed by 4-byte length-prefixed share chunks, ending with a 4-byte `0u32` EOF sentinel.
    ///
    /// # Security
    /// - Verifies header consistency across all sources (magic b"SHS_STR", version 2, matching stream_id, threshold >= 2, matching flags, unique non-zero indices)
    /// - Rejects reserved header flag bits
    /// - Capped chunk length allocation (<= 64 MiB) prevents OOM DoS attacks
    /// - Constant-time chunk reconstruction and SHA-256 verification
    /// - Bounded decompression (up to 64 MiB per chunk) only runs *after* integrity verification
    /// - Rejects unexpected mid-stream EOFs and prefix truncation attacks
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - Fewer sources than the required threshold are provided
    /// - Stream headers are inconsistent, corrupted, or contain index 0 / duplicate indices
    /// - Integrity check fails for any chunk (tampering or corruption detected)
    /// - I/O errors occur during reading or writing
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    /// use std::io::Cursor;
    ///
    /// let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
    /// let data = b"test data";
    /// let mut source = Cursor::new(data);
    /// let mut destinations = vec![Vec::new(); 3];
    /// let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
    ///     .iter_mut()
    ///     .map(|d| Cursor::new(std::mem::take(d)))
    ///     .collect();
    /// shamir.split_stream(&mut source, &mut dest_cursors).unwrap();
    /// let share_data: Vec<Vec<u8>> = dest_cursors
    ///     .into_iter()
    ///     .map(|cursor| cursor.into_inner())
    ///     .collect();
    ///
    /// // Reconstruct from the first 2 shares
    /// let mut sources = vec![
    ///     Cursor::new(share_data[0].clone()),
    ///     Cursor::new(share_data[1].clone()),
    /// ];
    /// let mut destination = Vec::new();
    /// let mut dest_cursor = Cursor::new(&mut destination);
    ///
    /// ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();
    /// assert_eq!(&destination, data);
    /// ```
    /// Reconstructs data from multiple share streams using chunk-based processing
    ///
    /// # Security Note
    /// This static method derives threshold, total shares, and integrity/compression flags
    /// directly from stream headers. In hostile-input environments where shares may be untrusted,
    /// use [`reconstruct_stream_with_scheme`](Self::reconstruct_stream_with_scheme)
    /// to enforce strict scheme validation.
    pub fn reconstruct_stream<R: Read, W: Write>(
        sources: &mut [R],
        destination: &mut W,
    ) -> Result<()> {
        Self::reconstruct_stream_internal(sources, destination, None)
    }

    /// Reconstructs a stream while strictly validating stream headers against the scheme's parameters
    pub fn reconstruct_stream_with_scheme<R: Read, W: Write>(
        &self,
        sources: &mut [R],
        destination: &mut W,
    ) -> Result<()> {
        Self::reconstruct_stream_internal(sources, destination, Some(self))
    }

    fn reconstruct_stream_internal<R: Read, W: Write>(
        sources: &mut [R],
        destination: &mut W,
        scheme: Option<&ShamirShare>,
    ) -> Result<()> {
        if sources.len() < 2 {
            return Err(ShamirError::InsufficientShares {
                needed: 2,
                got: sources.len() as u8,
            });
        }

        let mut headers: Vec<[u8; 28]> = Vec::with_capacity(sources.len());
        for source in sources.iter_mut() {
            let mut header = [0u8; 28];
            source
                .read_exact(&mut header)
                .map_err(ShamirError::IoError)?;
            headers.push(header);
        }

        // Check magic and version across all streams
        for h in &headers {
            if &h[0..7] != STREAM_MAGIC {
                return Err(ShamirError::InvalidShareFormat);
            }
            if h[7] != STREAM_VERSION {
                return Err(ShamirError::InvalidShareFormat);
            }
        }

        let stream_id: [u8; 16] = headers[0][8..24].try_into().unwrap();
        let first_flags = headers[0][24];
        if (first_flags & !0b11) != 0 {
            return Err(ShamirError::InvalidShareFormat);
        }
        let integrity_check = (first_flags & 1) != 0;
        let compression = (first_flags & 2) != 0;
        let threshold = headers[0][26];
        let total_shares = headers[0][27];

        if threshold < 2 || threshold > total_shares {
            return Err(ShamirError::InvalidThreshold(threshold));
        }

        if let Some(s) = scheme {
            if threshold != s.threshold
                || total_shares != s.total_shares
                || integrity_check != s.config.integrity_check()
                || compression != s.config.compression()
            {
                return Err(ShamirError::InvalidShareFormat);
            }
        } else if !integrity_check {
            return Err(ShamirError::InvalidShareFormat);
        }

        if sources.len() < threshold as usize {
            return Err(ShamirError::InsufficientShares {
                needed: threshold,
                got: u8::try_from(sources.len()).unwrap_or(u8::MAX),
            });
        }

        if sources.len() > total_shares as usize {
            return Err(ShamirError::InvalidShareFormat);
        }

        for header in &headers {
            if header[8..24] != stream_id
                || header[24] != first_flags
                || header[26] != threshold
                || header[27] != total_shares
            {
                return Err(ShamirError::InvalidShareFormat);
            }
            let index = header[25];
            if index == 0 || index > total_shares {
                return Err(ShamirError::InvalidShareIndex(index));
            }
        }

        for i in 0..headers.len() {
            for j in (i + 1)..headers.len() {
                if headers[i][25] == headers[j][25] {
                    return Err(ShamirError::InvalidShareFormat);
                }
            }
        }

        let active_count = threshold as usize;
        let share_indices: Vec<u8> = headers[..active_count].iter().map(|h| h[25]).collect();

        // Hoist Lagrange coefficient computation outside the chunk loop
        let lagrange_coefficients =
            Self::compute_lagrange_coefficients_from_indices(&share_indices)?;

        let mut excess_basis_coefficients =
            Vec::with_capacity(sources.len().saturating_sub(active_count));
        for excess_header in &headers[active_count..] {
            let basis = Self::compute_lagrange_basis_at_target(&share_indices, excess_header[25])?;
            excess_basis_coefficients.push(basis);
        }

        let mut chunk_lengths_buffer = Vec::with_capacity(sources.len());
        let mut reconstructed_chunk_buffer = Zeroizing::new(Vec::new());

        #[cfg(feature = "compress")]
        let max_stream_output_bytes = scheme
            .and_then(|s| s.config.max_decompressed_stream_size())
            .unwrap_or(crate::config::MAX_DEFAULT_STREAM_DECOMPRESSED_SIZE);
        #[cfg(feature = "compress")]
        let mut total_decompressed_bytes: u64 = 0;

        let mut chunk_index: u64 = 0;
        let mut stream_finished = false;

        let mut active_block_bufs: Vec<Zeroizing<Vec<u8>>> = (0..active_count)
            .map(|_| Zeroizing::new(vec![0u8; 65536]))
            .collect();
        let mut excess_expected_block = Zeroizing::new([0u8; 65536]);
        let mut excess_read_buf = Zeroizing::new([0u8; 65536]);

        while !stream_finished {
            chunk_lengths_buffer.clear();

            for source in sources.iter_mut() {
                let mut length_bytes = [0u8; 4];
                source
                    .read_exact(&mut length_bytes)
                    .map_err(ShamirError::IoError)?;
                let length = u32::from_le_bytes(length_bytes) as usize;
                chunk_lengths_buffer.push(length);
            }

            let first_len = chunk_lengths_buffer[0];

            if first_len == 0 {
                return Err(ShamirError::IoError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected end of stream before terminal chunk",
                )));
            }

            if first_len > MAX_STREAM_CHUNK_SIZE
                || !chunk_lengths_buffer.iter().all(|&l| l == first_len)
            {
                return Err(ShamirError::InconsistentShareLength);
            }

            if reconstructed_chunk_buffer.len() != first_len {
                reconstructed_chunk_buffer.clear();
                reconstructed_chunk_buffer
                    .try_reserve_exact(first_len)
                    .map_err(|_| {
                        ShamirError::StorageError("Memory allocation failed for chunk".into())
                    })?;
                reconstructed_chunk_buffer.resize(first_len, 0);
            } else {
                reconstructed_chunk_buffer.fill(0);
            }

            let mut read_total = 0;
            while read_total < first_len {
                let to_read = (first_len - read_total).min(65536);
                for (i, source) in sources[..active_count].iter_mut().enumerate() {
                    source
                        .read_exact(&mut active_block_bufs[i][..to_read])
                        .map_err(ShamirError::IoError)?;
                    let coeff = lagrange_coefficients[i];
                    for b in 0..to_read {
                        let f_byte = FiniteField::new(active_block_bufs[i][b]);
                        reconstructed_chunk_buffer[read_total + b] ^= (coeff * f_byte).0;
                    }
                }

                for (e, source) in sources[active_count..].iter_mut().enumerate() {
                    excess_expected_block[..to_read].fill(0);
                    let basis = &excess_basis_coefficients[e];
                    for (i, block) in active_block_bufs.iter().enumerate() {
                        let coeff = basis[i];
                        for b in 0..to_read {
                            let f_byte = FiniteField::new(block[b]);
                            excess_expected_block[b] ^= (coeff * f_byte).0;
                        }
                    }
                    source
                        .read_exact(&mut excess_read_buf[..to_read])
                        .map_err(ShamirError::IoError)?;
                    if !bool::from(
                        excess_read_buf[..to_read].ct_eq(&excess_expected_block[..to_read]),
                    ) {
                        return Err(ShamirError::IntegrityCheckFailed);
                    }
                }

                read_total += to_read;
            }

            let (is_last, payload) = if integrity_check {
                if reconstructed_chunk_buffer.len() < STREAM_CHUNK_SALT_SIZE + HASH_SIZE + 1 {
                    return Err(ShamirError::IntegrityCheckFailed);
                }
                let chunk_salt = &reconstructed_chunk_buffer[..STREAM_CHUNK_SALT_SIZE];
                let expected_hash = &reconstructed_chunk_buffer
                    [STREAM_CHUNK_SALT_SIZE..STREAM_CHUNK_SALT_SIZE + HASH_SIZE];
                let is_last = reconstructed_chunk_buffer[STREAM_CHUNK_SALT_SIZE + HASH_SIZE];
                let payload = &reconstructed_chunk_buffer[STREAM_CHUNK_SALT_SIZE + HASH_SIZE + 1..];

                let auth_key = scheme.and_then(|s| s.config.authentication_key());
                let domain = if auth_key.is_some() {
                    b"SHS1_STR_HMAC_V2\0".as_slice()
                } else {
                    b"SHS1_STR_KEYED_V2\0".as_slice()
                };

                let mut meta = Vec::with_capacity(7 + 4 + 16 + 1 + 8);
                meta.extend_from_slice(STREAM_MAGIC);
                meta.extend_from_slice(&[STREAM_VERSION, first_flags, threshold, total_shares]);
                meta.extend_from_slice(&stream_id);
                meta.push(is_last);
                meta.extend_from_slice(&chunk_index.to_le_bytes());

                let calculated_hash =
                    Self::compute_digest(domain, &meta, chunk_salt, payload, auth_key);

                if !bool::from(calculated_hash.as_slice().ct_eq(expected_hash)) {
                    return Err(ShamirError::IntegrityCheckFailed);
                }
                (is_last, payload)
            } else {
                if reconstructed_chunk_buffer.len() < 8 + 1 {
                    return Err(ShamirError::InvalidShareFormat);
                }
                let is_last = reconstructed_chunk_buffer[8];
                let payload = &reconstructed_chunk_buffer[9..];
                (is_last, payload)
            };

            if is_last != 0 && is_last != 1 {
                return Err(ShamirError::InvalidShareFormat);
            }

            if compression {
                #[cfg(feature = "compress")]
                {
                    let remaining_limit =
                        max_stream_output_bytes.saturating_sub(total_decompressed_bytes);
                    let decompressed = Self::decompress_bounded(payload, remaining_limit)?;
                    total_decompressed_bytes = total_decompressed_bytes
                        .checked_add(decompressed.len() as u64)
                        .ok_or_else(|| {
                            ShamirError::DecompressionError(
                                "Stream decompressed size overflow".into(),
                            )
                        })?;
                    if total_decompressed_bytes > max_stream_output_bytes {
                        return Err(ShamirError::DecompressionError(
                            "Cumulative decompressed stream exceeds maximum allowed limit".into(),
                        ));
                    }
                    destination
                        .write_all(&decompressed)
                        .map_err(ShamirError::IoError)?;
                }
                #[cfg(not(feature = "compress"))]
                {
                    return Err(ShamirError::InvalidConfig(
                        "Share requires 'compress' feature to decompress".into(),
                    ));
                }
            } else {
                destination
                    .write_all(payload)
                    .map_err(ShamirError::IoError)?;
            }

            if is_last == 1 {
                stream_finished = true;
            }

            chunk_index = chunk_index
                .checked_add(1)
                .ok_or_else(|| ShamirError::StorageError("Chunk index overflow".into()))?;
        }

        // Verify the terminal EOS marker (0u32) on all sources
        for source in sources.iter_mut() {
            let mut eos_bytes = [0u8; 4];
            source
                .read_exact(&mut eos_bytes)
                .map_err(ShamirError::IoError)?;
            if u32::from_le_bytes(eos_bytes) != 0 {
                return Err(ShamirError::InvalidShareFormat);
            }
            // Verify that no trailing data exists after EOS
            let mut trailing = [0u8; 1];
            if source.read(&mut trailing).map_err(ShamirError::IoError)? != 0 {
                return Err(ShamirError::InvalidShareFormat);
            }
        }

        destination.flush().map_err(ShamirError::IoError)?;
        Ok(())
    }

    /// Helper method to split a single chunk of data into pre-allocated share data buffers
    ///
    /// Evaluates the polynomial for each share using Horner's method with random coefficients.
    /// Used internally by `split_stream` to eliminate allocation pressure in the hot loop.
    ///
    /// # Arguments
    /// * `data` - The chunk data to split
    /// * `destination_buffers` - Pre-allocated reusable buffers for each share
    /// * `rng` - CSPRNG for coefficient generation
    ///
    /// # Security
    /// - Constant-time polynomial evaluation
    /// - Cryptographically secure randomness for polynomial coefficients
    fn split_chunk_into(
        &self,
        data: &[u8],
        destination_buffers: &mut [Zeroizing<Vec<u8>>],
        rng: &mut ChaCha20Rng,
    ) -> Result<()> {
        let chunk_len = data.len();
        let t = self.threshold as usize;
        let _ = chunk_len.checked_mul(t - 1).ok_or_else(|| {
            ShamirError::InvalidConfig("Data length overflow in coefficient generation".into())
        })?;

        for dest in destination_buffers.iter_mut() {
            dest.clear();
            dest.reserve(chunk_len);
        }

        const STRIP_SIZE: usize = 65536;
        let max_strip_coeffs = STRIP_SIZE
            .checked_mul(t - 1)
            .ok_or_else(|| ShamirError::InvalidConfig("Coefficient length overflow".into()))?;
        let mut strip_coeffs = Zeroizing::new(vec![0u8; max_strip_coeffs]);

        for chunk_slice in data.chunks(STRIP_SIZE) {
            let strip_len = chunk_slice.len();
            let strip_num_coeffs = strip_len * (t - 1);
            rng.fill_bytes(&mut strip_coeffs[..strip_num_coeffs]);

            for (i, dest) in destination_buffers.iter_mut().enumerate() {
                let x = FiniteField::new((i + 1) as u8);
                for (byte_idx, &data_byte) in chunk_slice.iter().enumerate() {
                    let offset = byte_idx * (t - 1);
                    let mut acc = FiniteField::new(strip_coeffs[offset + (t - 2)]);
                    for j in (1..t - 1).rev() {
                        let coeff = FiniteField::new(strip_coeffs[offset + (j - 1)]);
                        acc = acc * x + coeff;
                    }
                    acc = acc * x + FiniteField::new(data_byte);
                    dest.push(acc.0);
                }
            }
        }

        Ok(())
    }

    /// Helper method to compute Lagrange coefficients from raw share indices
    ///
    /// Calculates $L_i(0) = \prod_{j \neq i} \frac{x_j}{x_j - x_i}$ in GF(2^8).
    /// Used by both reconstruction methods to compute coefficients once per operation.
    #[inline]
    fn compute_lagrange_coefficients_from_indices(indices: &[u8]) -> Result<Vec<FiniteField>> {
        for &x in indices {
            if x == 0 {
                return Err(ShamirError::InvalidShareIndex(0));
            }
        }

        for i in 0..indices.len() {
            for j in (i + 1)..indices.len() {
                if indices[i] == indices[j] {
                    return Err(ShamirError::InvalidShareFormat);
                }
            }
        }

        let xs: Vec<FiniteField> = indices.iter().map(|&idx| FiniteField::new(idx)).collect();
        let p = xs.iter().fold(FiniteField::new(1), |acc, &x| acc * x);
        let lagrange_coefficients: Result<Vec<FiniteField>> = xs
            .iter()
            .enumerate()
            .map(|(i, &x_i)| {
                let x_i_inv = x_i.inverse().ok_or(ShamirError::InvalidShareIndex(0))?;
                let numerator = p * x_i_inv;
                let mut denominator = FiniteField::new(1);
                for (j, &x_j) in xs.iter().enumerate() {
                    if i != j {
                        denominator = denominator * (x_i + x_j);
                    }
                }
                denominator
                    .inverse()
                    .ok_or(ShamirError::InvalidShareFormat)
                    .map(|inv| numerator * inv)
            })
            .collect();

        lagrange_coefficients
    }

    #[inline]
    fn compute_lagrange_basis_at_target(indices: &[u8], target_x: u8) -> Result<Vec<FiniteField>> {
        let xs: Vec<FiniteField> = indices.iter().map(|&idx| FiniteField::new(idx)).collect();
        let target = FiniteField::new(target_x);
        let mut basis = Vec::with_capacity(xs.len());
        for (i, &x_i) in xs.iter().enumerate() {
            let mut num = FiniteField::new(1);
            let mut den = FiniteField::new(1);
            for (j, &x_j) in xs.iter().enumerate() {
                if i != j {
                    num = num * (target + x_j);
                    den = den * (x_i + x_j);
                }
            }
            let den_inv = den.inverse().ok_or(ShamirError::InvalidShareFormat)?;
            basis.push(num * den_inv);
        }
        Ok(basis)
    }

    /// Helper method to compute Lagrange coefficients from borrowed `ShareView`s without allocation
    ///
    /// # Arguments
    /// * `share_views` - Slice of share views to compute coefficients for
    ///
    /// # Returns
    /// Vector of Lagrange coefficients for each share
    ///
    /// # Security
    /// - Constant-time field inversion and multiplication
    /// - Validates non-zero unique share indices
    #[inline]
    fn compute_lagrange_coefficients_from_views(
        share_views: &[ShareView],
    ) -> Result<Vec<FiniteField>> {
        let indices: Vec<u8> = share_views.iter().map(|v| v.index).collect();
        Self::compute_lagrange_coefficients_from_indices(&indices)
    }

    /// Optimized helper method to reconstruct a single chunk from share views with zero-copy
    ///
    /// # Arguments
    /// * `views` - Slice of borrowed share views
    ///
    /// # Returns
    /// The reconstructed data bytes wrapped in [`Zeroizing`]
    ///
    /// # Security
    /// - Constant-time Lagrange interpolation
    /// - Sequential memory access with cache locality
    /// - Thread pool parallelization gated on `secret_len >= 16384`
    /// - Validates share consistency before processing
    #[inline]
    fn reconstruct_chunk_from_views_with_mode(
        views: &[ShareView<'_>],
        mode: SplitMode,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if views.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 2, got: 0 });
        }

        let data_len = views[0].data.len();

        if !views.iter().all(|v| v.data.len() == data_len) {
            return Err(ShamirError::InconsistentShareLength);
        }

        let lagrange_coefficients = Self::compute_lagrange_coefficients_from_views(views)?;
        let mut output_buffer = Zeroizing::new(vec![0u8; data_len]);

        if mode == SplitMode::Parallel && data_len >= 16384 {
            output_buffer
                .par_chunks_mut(4096)
                .enumerate()
                .for_each(|(chunk_idx, slice)| {
                    let offset = chunk_idx * 4096;
                    for (view, &coeff) in views.iter().zip(&lagrange_coefficients) {
                        for (i, byte) in slice.iter_mut().enumerate() {
                            *byte ^= (coeff * FiniteField::new(view.data[offset + i])).0;
                        }
                    }
                });
        } else {
            for (view, &coeff) in views.iter().zip(&lagrange_coefficients) {
                for (i, byte) in output_buffer.iter_mut().enumerate() {
                    *byte ^= (coeff * FiniteField::new(view.data[i])).0;
                }
            }
        }

        Ok(output_buffer)
    }

    /// Generates share deltas by creating and evaluating a random polynomial whose secret is zero
    ///
    /// This helper method creates a polynomial of degree `k-1` where the constant term
    /// is zero, and evaluates it at the given share indices. The resulting delta values can be
    /// added (XORed) to existing shares for proactive share refreshing.
    ///
    /// # Arguments
    /// * `share_indices` - Slice of share indices (x-coordinates) to evaluate at
    /// * `data_length` - Byte length of the zero secret data
    ///
    /// # Returns
    /// Vector where each element contains the delta data for the corresponding share index, wrapped in [`Zeroizing`]
    ///
    /// # Security
    /// - Constant-time evaluation using Horner's method
    /// - Zero constant term ensures deltas maintain the underlying secret unchanged
    fn generate_zero_polynomial_shares(
        &self,
        share_indices: &[u8],
        data_length: usize,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        let t = self.threshold as usize;
        let _ = data_length.checked_mul(t - 1).ok_or_else(|| {
            ShamirError::InvalidConfig("Data length overflow in zero polynomial".into())
        })?;

        const STRIP_SIZE: usize = 65536;
        let max_strip_coeffs = STRIP_SIZE.checked_mul(t - 1).ok_or_else(|| {
            ShamirError::InvalidConfig("Data length overflow in zero polynomial".into())
        })?;
        let mut strip_coeffs = Zeroizing::new(vec![0u8; max_strip_coeffs]);
        let mut rng = Self::local_rng()?;

        let mut delta_shares: Vec<Zeroizing<Vec<u8>>> = (0..share_indices.len())
            .map(|_| {
                let mut v = Vec::new();
                let _ = v.try_reserve_exact(data_length);
                Zeroizing::new(v)
            })
            .collect();

        let mut offset = 0;
        while offset < data_length {
            let strip_len = (data_length - offset).min(STRIP_SIZE);
            let strip_num_coeffs = strip_len * (t - 1);
            rng.fill_bytes(&mut strip_coeffs[..strip_num_coeffs]);

            for (i, &index) in share_indices.iter().enumerate() {
                let x = FiniteField::new(index);
                for byte_idx in 0..strip_len {
                    let coeff_offset = byte_idx * (t - 1);
                    let mut acc = FiniteField::new(strip_coeffs[coeff_offset + (t - 2)]);
                    for j in (1..t - 1).rev() {
                        let coeff = FiniteField::new(strip_coeffs[coeff_offset + (j - 1)]);
                        acc = acc * x + coeff;
                    }
                    acc = acc * x;
                    delta_shares[i].push(acc.0);
                }
            }
            offset += strip_len;
        }

        Ok(delta_shares)
    }

    /// Generates zero-polynomial delta shares for proactive secret sharing without accessing existing shares
    ///
    /// This method generates evaluation deltas $Q(x)$ where $Q(0) = 0$ for each requested share index.
    /// Coordinators can generate these deltas and distribute $\Delta_i$ to each share holder without ever
    /// gathering secret shares into a single central process memory.
    pub fn generate_refresh_deltas(
        &self,
        share_indices: &[u8],
        data_length: usize,
    ) -> Result<Vec<Share>> {
        if data_length > crate::config::MAX_CONFIG_CHUNK_SIZE + 64 {
            return Err(ShamirError::InvalidConfig(format!(
                "Data length {} exceeds maximum allowed share size",
                data_length
            )));
        }
        if share_indices.is_empty() || share_indices.len() > self.total_shares as usize {
            return Err(ShamirError::InvalidShareFormat);
        }
        for (i, &index) in share_indices.iter().enumerate() {
            if index == 0 || index > self.total_shares {
                return Err(ShamirError::InvalidShareIndex(index));
            }
            if share_indices[i + 1..].contains(&index) {
                return Err(ShamirError::InvalidShareFormat);
            }
        }
        let deltas = self.generate_zero_polynomial_shares(share_indices, data_length)?;
        let result = share_indices
            .iter()
            .zip(deltas)
            .map(|(&index, delta)| Share {
                index,
                data: delta.to_vec(),
                threshold: self.threshold,
                total_shares: self.total_shares,
                integrity_check: self.config.integrity_check(),
                compression: self.config.compression(),
            })
            .collect();
        Ok(result)
    }

    /// Refreshes existing shares by adding zero-polynomial deltas to invalidate old shares
    ///
    /// This method generates new shares that maintain the same secret but have different share data,
    /// effectively invalidating old shares for security purposes (proactive secret sharing).
    ///
    /// # Arguments
    /// * `shares` - Slice of all existing shares to refresh (must provide all `total_shares`)
    ///
    /// # Returns
    /// Vector of refreshed shares with identical indices and metadata but randomized share data
    ///
    /// # Security Purpose
    /// - **Invalidates old shares**: Previous share values become useless after refreshing
    /// - **Prevents share accumulation**: Attackers cannot combine old and new shares across epochs
    /// - **Maintains secret integrity**: The reconstructed secret remains identical
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - Empty slice or fewer shares than `total_shares`
    /// - Any share index is 0 or duplicate indices are provided
    /// - Inconsistent data lengths or metadata across shares
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    ///
    /// let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
    /// let secret = b"sensitive data";
    ///
    /// // Create initial shares
    /// let original_shares = scheme.split(secret).unwrap();
    ///
    /// // Refresh all shares to invalidate the old ones
    /// let refreshed_shares = scheme.refresh_shares(&original_shares).unwrap();
    ///
    /// // Both sets reconstruct to the same secret
    /// let original_secret = ShamirShare::reconstruct(&original_shares[0..3]).unwrap();
    /// let refreshed_secret = ShamirShare::reconstruct(&refreshed_shares[0..3]).unwrap();
    /// assert_eq!(original_secret, refreshed_secret);
    ///
    /// // But share data is completely different
    /// assert_ne!(original_shares[0].data, refreshed_shares[0].data);
    /// ```
    pub fn refresh_shares(&self, shares: &[Share]) -> Result<Vec<Share>> {
        if shares.is_empty() {
            return Err(ShamirError::InsufficientShares {
                needed: self.total_shares,
                got: 0,
            });
        }

        if shares.len() < self.total_shares as usize {
            return Err(ShamirError::InsufficientShares {
                needed: self.total_shares,
                got: u8::try_from(shares.len()).unwrap_or(u8::MAX),
            });
        }
        if shares.len() > self.total_shares as usize {
            return Err(ShamirError::InvalidShareFormat);
        }

        let data_length = shares[0].data.len();

        for s in shares {
            if s.index == 0 || s.index > self.total_shares {
                return Err(ShamirError::InvalidShareIndex(s.index));
            }
            if s.threshold != self.threshold
                || s.total_shares != self.total_shares
                || s.integrity_check != self.config.integrity_check()
                || s.compression != self.config.compression()
            {
                return Err(ShamirError::InvalidShareFormat);
            }
            if s.data.len() != data_length {
                return Err(ShamirError::InconsistentShareLength);
            }
        }

        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                if shares[i].index == shares[j].index {
                    return Err(ShamirError::InvalidShareFormat);
                }
            }
        }

        // Verify share consistency across ALL shares directly in GF(2^8) before refreshing so corrupted shares are not silently masked,
        // without materializing or decompressing the secret into plaintext buffers (MAS-05, MAS-08).
        let views: Vec<ShareView<'_>> = shares.iter().map(|s| s.as_view()).collect();
        let active_views = &views[..self.threshold as usize];
        let base_poly_0 =
            Self::reconstruct_chunk_from_views_with_mode(active_views, self.config.mode())?;

        for excess_view in &views[self.threshold as usize..] {
            let mut alt_views = active_views.to_vec();
            alt_views[0] = *excess_view;
            let alt_poly_0 =
                Self::reconstruct_chunk_from_views_with_mode(&alt_views, self.config.mode())?;
            if !bool::from(alt_poly_0.as_slice().ct_eq(base_poly_0.as_slice())) {
                return Err(ShamirError::IntegrityCheckFailed);
            }
        }

        let indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
        let deltas = self.generate_refresh_deltas(&indices, data_length)?;

        let mut refreshed_shares = shares.to_vec();
        for (share, delta) in refreshed_shares.iter_mut().zip(&deltas) {
            share.apply_refresh_delta(delta)?;
        }

        Ok(refreshed_shares)
    }
}

impl Iterator for Dealer {
    type Item = Share;

    /// Generates the next share by evaluating the polynomial at the current x-coordinate
    ///
    /// Uses constant-time Horner evaluation and stops after reaching `total_shares`.
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_x == 0 || self.current_x > self.total_shares {
            return None;
        }

        let x = FiniteField::new(self.current_x);
        let secret_len = self.data.len();
        let t = self.threshold as usize;

        let share_data: Vec<u8> = (0..secret_len)
            .map(|byte_idx| {
                let mut acc = FiniteField::new(self.coefficients[byte_idx * (t - 1) + (t - 2)]);
                for j in (1..t - 1).rev() {
                    let coeff = FiniteField::new(self.coefficients[byte_idx * (t - 1) + (j - 1)]);
                    acc = acc * x + coeff;
                }
                acc = acc * x + FiniteField::new(self.data[byte_idx]);
                acc.0
            })
            .collect();

        let share = Share {
            index: self.current_x,
            data: share_data,
            threshold: self.threshold,
            total_shares: self.total_shares,
            integrity_check: self.integrity_check,
            compression: self.compression,
        };

        if self.current_x >= self.total_shares {
            self.current_x = 0;
            #[cfg(feature = "zeroize")]
            {
                self.data.zeroize();
                self.coefficients.zeroize();
            }
        } else {
            self.current_x += 1;
        }

        Some(share)
    }

    /// Returns the number of remaining shares that can be generated
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = if self.current_x == 0 || self.current_x > self.total_shares {
            0
        } else {
            (self.total_shares - self.current_x + 1) as usize
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Dealer {
    /// Returns the exact number of remaining shares
    fn len(&self) -> usize {
        self.size_hint().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct() {
        let secret = b"Hello, World!";
        let shamir = ShamirShare::builder(5, 3).build().unwrap();

        // Split the secret into 5 shares
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly threshold (3) shares
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);

        // Reconstruct with more than threshold shares (4 shares)
        let reconstructed = ShamirShare::reconstruct(&shares[1..5]).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_invalid_parameters() {
        // Total shares = 0
        assert!(ShamirShare::builder(0, 1).build().is_err());
        // Threshold = 0
        assert!(ShamirShare::builder(1, 0).build().is_err());
        // Threshold > total shares
        assert!(ShamirShare::builder(3, 4).build().is_err());
        // Threshold = 1 rejected for cryptographic security
        assert!(ShamirShare::builder(3, 1).build().is_err());
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Test";
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();

        // Reconstruct with 2 shares when threshold is 3 should fail
        assert!(ShamirShare::reconstruct(&shares[0..2]).is_err());
    }

    #[test]
    fn test_different_share_combinations() {
        let secret = b"Different combinations test";
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();

        // Try different combinations of 3 shares
        let combinations = vec![vec![0, 1, 2], vec![1, 2, 3], vec![2, 3, 4], vec![0, 2, 4]];

        for combo in combinations {
            let selected_shares: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            let reconstructed = ShamirShare::reconstruct(&selected_shares).unwrap();
            assert_eq!(reconstructed.as_slice(), secret);
        }
    }

    #[test]
    fn test_empty_secret() {
        let secret = b"";
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = b"x";
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_max_shares() {
        let secret = b"Maximum shares test";
        let shamir = ShamirShare::builder(255, 128).build().unwrap();
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 255);

        let reconstructed = ShamirShare::reconstruct(&shares[0..128]).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_duplicate_share_indices() {
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(b"test").unwrap();

        let mut corrupted_shares = shares[0..3].to_vec();
        corrupted_shares[1].index = corrupted_shares[0].index;

        assert!(matches!(
            ShamirShare::reconstruct(&corrupted_shares),
            Err(ShamirError::InvalidShareFormat)
        ));
    }

    #[test]
    fn test_zero_share_index_rejected_in_reconstruct() {
        let shamir = ShamirShare::builder(3, 2).build().unwrap();
        let mut shares = shamir.split(b"test").unwrap();
        shares[0].index = 0;

        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..2]),
            Err(ShamirError::InvalidShareIndex(0))
        ));
    }

    #[test]
    fn test_corrupted_share_data() {
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        let mut shares = shamir.split(b"test").unwrap();

        if shares[0].data[0] == 0 {
            shares[0].data[0] = 1;
        } else {
            shares[0].data[0] = 0;
        }

        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..3]),
            Err(ShamirError::IntegrityCheckFailed)
        ));
    }

    #[test]
    fn test_builder_pattern() {
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        assert_eq!(shamir.total_shares, 5);
        assert_eq!(shamir.threshold, 3);
        assert!(shamir.config.integrity_check());

        let config = Config::new().with_integrity_check(false);
        let shamir = ShamirShare::builder(7, 4)
            .with_config(config)
            .build()
            .unwrap();
        assert_eq!(shamir.total_shares, 7);
        assert_eq!(shamir.threshold, 4);
        assert!(!shamir.config.integrity_check());
    }

    #[test]
    fn test_builder_validation() {
        assert!(ShamirShare::builder(0, 1).build().is_err());
        assert!(ShamirShare::builder(1, 0).build().is_err());
        assert!(ShamirShare::builder(3, 5).build().is_err());
        assert!(ShamirShare::builder(5, 1).build().is_err());

        let invalid_config = Config::new().with_chunk_size(0).unwrap_err();
        assert!(matches!(invalid_config, ShamirError::InvalidConfig(_)));
    }

    #[test]
    fn test_integrity_check_disabled() {
        let config = Config::new().with_integrity_check(false);
        let shamir = ShamirShare::builder(5, 3)
            .with_config(config)
            .build()
            .unwrap();

        let secret = b"test secret without integrity check";
        let shares = shamir.split(secret).unwrap();
        assert!(!shares[0].integrity_check);

        // Parameterless reconstruct rejects shares without integrity check (MAS-02)
        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..3]),
            Err(ShamirError::InvalidShareFormat)
        ));

        // Reconstruct with explicit scheme succeeds
        let reconstructed = shamir.reconstruct_with_scheme(&shares[0..3]).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_mixed_integrity_flags_fail() {
        let shamir_with = ShamirShare::builder(5, 3).build().unwrap();
        let shamir_without = ShamirShare::builder(5, 3)
            .with_config(Config::new().with_integrity_check(false))
            .build()
            .unwrap();

        let secret = b"test secret";
        let shares1 = shamir_with.split(secret).unwrap();
        let shares2 = shamir_without.split(secret).unwrap();

        let mixed = vec![shares1[0].clone(), shares2[1].clone(), shares1[2].clone()];
        assert!(matches!(
            ShamirShare::reconstruct(&mixed),
            Err(ShamirError::InvalidShareFormat)
        ));
    }

    #[test]
    fn test_config_builder_methods() {
        #[allow(unused_mut)]
        let mut config = Config::new()
            .with_chunk_size(2048)
            .unwrap()
            .with_mode(SplitMode::Parallel)
            .with_integrity_check(true);

        #[cfg(feature = "compress")]
        {
            config = config.with_compression(true);
        }

        let shamir = ShamirShare::builder(5, 3)
            .with_config(config.clone())
            .build()
            .unwrap();

        assert_eq!(shamir.config.chunk_size(), 2048);
        assert_eq!(shamir.config.mode(), SplitMode::Parallel);
        assert!(shamir.config.integrity_check());
        #[cfg(feature = "compress")]
        assert!(shamir.config.compression());
    }

    #[test]
    fn test_split_stream_basic() {
        use std::io::Cursor;

        let shamir = ShamirShare::builder(3, 2).build().unwrap();
        let data = b"This is a test message for streaming functionality";
        let mut source = Cursor::new(data);

        let mut destinations = vec![Vec::new(); 3];
        let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();

        shamir.split_stream(&mut source, &mut dest_cursors).unwrap();

        let share_data: Vec<Vec<u8>> = dest_cursors
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();

        for share in &share_data {
            assert!(!share.is_empty());
        }

        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|d| Cursor::new(d.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();
        assert_eq!(&destination, data);
    }

    #[test]
    fn test_split_stream_with_custom_chunk_size() {
        use std::io::Cursor;

        let config = Config::new().with_chunk_size(10).unwrap();
        let shamir = ShamirShare::builder(3, 2)
            .with_config(config)
            .build()
            .unwrap();

        let data = b"This is a longer test message that will be split into multiple chunks";
        let mut source = Cursor::new(data);

        let mut destinations = vec![Vec::new(); 3];
        let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();

        shamir.split_stream(&mut source, &mut dest_cursors).unwrap();

        let share_data: Vec<Vec<u8>> = dest_cursors
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();

        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|d| Cursor::new(d.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();
        assert_eq!(&destination, data);
    }

    #[test]
    fn test_empty_input_streaming() {
        use std::io::Cursor;

        let shamir = ShamirShare::builder(3, 2).build().unwrap();
        let data = b"";
        let mut source = Cursor::new(data);

        let mut destinations = vec![Vec::new(); 3];
        let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();

        shamir.split_stream(&mut source, &mut dest_cursors).unwrap();

        let share_data: Vec<Vec<u8>> = dest_cursors
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();

        // 28 bytes header + 4 bytes chunk length + 49 bytes data (16 salt + 32 hash + 1 is_last) + 4 bytes terminal EOS
        for share in &share_data {
            assert_eq!(share.len(), 85);
        }

        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|d| Cursor::new(d.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();
        assert_eq!(&destination, data);
    }

    #[test]
    fn test_stream_chunk_formatting() {
        use std::io::Cursor;

        let config = Config::new().with_chunk_size(5).unwrap();
        let shamir = ShamirShare::builder(3, 2)
            .with_config(config)
            .build()
            .unwrap();

        let data = b"Hello World!";
        let mut source = Cursor::new(data);

        let mut destinations = vec![Vec::new(); 3];
        let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();

        shamir.split_stream(&mut source, &mut dest_cursors).unwrap();

        let share_data: Vec<Vec<u8>> = dest_cursors
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();

        for share in &share_data {
            let mut cursor = Cursor::new(share);
            let mut total_chunks = 0;

            let mut header = [0u8; 28];
            cursor.read_exact(&mut header).unwrap();

            loop {
                let mut length_bytes = [0u8; 4];
                match cursor.read_exact(&mut length_bytes) {
                    Ok(()) => {
                        let length = u32::from_le_bytes(length_bytes) as usize;
                        if length == 0 {
                            break;
                        }
                        let mut chunk_data = vec![0u8; length];
                        cursor.read_exact(&mut chunk_data).unwrap();
                        total_chunks += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => panic!("Unexpected error: {}", e),
                }
            }

            assert_eq!(total_chunks, 3);
        }

        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|d| Cursor::new(d.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();
        assert_eq!(&destination, data);
    }

    #[test]
    fn test_dealer_basic_functionality() {
        let secret = b"Hello, Dealer!";
        let shamir = ShamirShare::builder(5, 3).build().unwrap();

        let dealer_shares: Vec<Share> = shamir.try_dealer(secret).unwrap().take(5).collect();
        assert_eq!(dealer_shares.len(), 5);

        for (i, share) in dealer_shares.iter().enumerate() {
            assert_eq!(share.index, (i + 1) as u8);
            assert_eq!(share.threshold, 3);
            assert_eq!(share.total_shares, 5);
            assert!(share.integrity_check);
        }

        let reconstructed = ShamirShare::reconstruct(&dealer_shares[0..3]).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_dealer_size_hint() {
        let secret = b"Size hint test";
        let shamir = ShamirShare::builder(10, 5).build().unwrap();

        let mut dealer = shamir.try_dealer(secret).unwrap();

        assert_eq!(dealer.size_hint(), (10, Some(10)));
        assert_eq!(dealer.len(), 10);

        let _share = dealer.next().unwrap();
        assert_eq!(dealer.size_hint(), (9, Some(9)));
        assert_eq!(dealer.len(), 9);
    }

    #[test]
    fn test_dealer_exhaustion() {
        let secret = b"Stop at total shares";
        let shamir = ShamirShare::builder(5, 3).build().unwrap();

        let mut dealer = shamir.try_dealer(secret).unwrap();
        let shares: Vec<Share> = dealer.by_ref().collect();
        assert_eq!(shares.len(), 5);
        assert_eq!(dealer.next(), None);
    }

    #[test]
    fn test_parallel_split_mode() {
        let config = Config::new().with_mode(SplitMode::Parallel);
        let shamir = ShamirShare::builder(5, 3)
            .with_config(config)
            .build()
            .unwrap();

        let secret = b"Parallel split test data";
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed.as_slice(), secret);
    }

    #[test]
    fn test_zero_index_stream_header_rejected() {
        use std::io::Cursor;
        let mut h1 = [0u8; 28];
        h1[0..7].copy_from_slice(b"SHS_STR");
        h1[7] = STREAM_VERSION;
        h1[8..24].copy_from_slice(&[42u8; 16]);
        h1[24] = 1; // flags
        h1[25] = 0; // index 0 (invalid)
        h1[26] = 2; // threshold
        h1[27] = 3; // total_shares

        let mut h2 = h1;
        h2[25] = 2; // index 2

        let mut sources = vec![Cursor::new(h1.to_vec()), Cursor::new(h2.to_vec())];
        let mut dest = Vec::new();
        assert!(matches!(
            ShamirShare::reconstruct_stream(&mut sources, &mut dest),
            Err(ShamirError::InvalidShareIndex(0))
        ));
    }

    #[test]
    fn test_reconstruct_share_index_bounds() {
        let shamir = ShamirShare::builder(3, 2).build().unwrap();
        let secret = b"Index bounds test";
        let mut shares = shamir.split(secret).unwrap();

        // Index 0
        shares[0].index = 0;
        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..2]),
            Err(ShamirError::InvalidShareIndex(0))
        ));

        // Index > total_shares (3)
        shares[0].index = 4;
        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..2]),
            Err(ShamirError::InvalidShareIndex(4))
        ));
    }

    #[test]
    fn test_reconstruct_excess_shares() {
        let shamir = ShamirShare::builder(3, 2).build().unwrap();
        let secret = b"Excess shares test";
        let mut shares = shamir.split(secret).unwrap();
        shares.push(shares[0].clone());

        assert!(matches!(
            ShamirShare::reconstruct(&shares),
            Err(ShamirError::InvalidShareFormat)
        ));
    }
}
