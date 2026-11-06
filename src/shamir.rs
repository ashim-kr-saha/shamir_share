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

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(not(feature = "zeroize"))]
#[derive(Debug, Clone)]
pub struct Zeroizing<T>(pub T);

#[cfg(not(feature = "zeroize"))]
impl<T> Zeroizing<T> {
    pub fn new(val: T) -> Self {
        Self(val)
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T> std::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T> std::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

const HASH_SIZE: usize = 32; // SHA-256 output size
const MAX_STREAM_CHUNK_SIZE: usize = (64 * 1024 * 1024) + (256 * 1024) + 256;
#[cfg(feature = "compress")]
const MAX_DECOMPRESSED_CHUNK_SIZE: u64 = 64 * 1024 * 1024; // 64 MiB cap for decompression

/// Magic bytes for the binary stream framing format ("SHS_STR")
pub const STREAM_MAGIC: &[u8; 7] = b"SHS_STR";
/// Current version of the streaming format
pub const STREAM_VERSION: u8 = 1;
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

impl PartialEq for Share {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
            && self.threshold == other.threshold
            && self.total_shares == other.total_shares
            && self.integrity_check == other.integrity_check
            && self.compression == other.compression
            && bool::from(self.data.ct_eq(&other.data))
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
#[derive(Debug, Clone, Copy)]
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

impl<'a> PartialEq for ShareView<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
            && self.threshold == other.threshold
            && self.total_shares == other.total_shares
            && self.integrity_check == other.integrity_check
            && self.compression == other.compression
            && bool::from(self.data.ct_eq(other.data))
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
/// assert_eq!(reconstructed, secret);
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
/// assert_eq!(reconstructed, secret);
/// ```
pub struct ShamirShare {
    /// Total number of shares to generate
    total_shares: u8,
    /// Minimum number of shares needed for reconstruction
    threshold: u8,
    /// Configuration options for the sharing scheme
    config: Config,
    /// Cryptographically secure random number generator
    rng: ChaCha20Rng,
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
    /// - RNG initialization fails
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

        let rng = ChaCha20Rng::try_from_rng(&mut SysRng)
            .map_err(|e| ShamirError::RngError(e.to_string()))?;

        Ok(ShamirShare {
            total_shares: self.total_shares,
            threshold: self.threshold,
            config: self.config,
            rng,
        })
    }
}

impl ShamirShare {
    #[inline]
    fn reseed_rng(&mut self) -> Result<()> {
        self.rng = ChaCha20Rng::try_from_rng(&mut SysRng)
            .map_err(|e| ShamirError::RngError(e.to_string()))?;
        Ok(())
    }

    #[cfg(feature = "compress")]
    fn decompress_bounded(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let decoder = zstd::Decoder::new(payload)
            .map_err(|e| ShamirError::DecompressionError(e.to_string()))?;
        let mut decompressed = Zeroizing::new(Vec::new());
        decoder
            .take(MAX_DECOMPRESSED_CHUNK_SIZE + 1)
            .read_to_end(&mut decompressed)
            .map_err(|e| ShamirError::DecompressionError(e.to_string()))?;
        if (decompressed.len() as u64) > MAX_DECOMPRESSED_CHUNK_SIZE {
            return Err(ShamirError::DecompressionError(
                "Decompressed payload exceeds 64 MiB limit".into(),
            ));
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
    pub fn try_dealer(&mut self, secret: &[u8]) -> Result<Dealer> {
        self.reseed_rng()?;
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

        let mut data_to_split =
            Zeroizing::new(Vec::with_capacity(if self.config.integrity_check() {
                HASH_SIZE + payload.len()
            } else {
                payload.len()
            }));
        if self.config.integrity_check() {
            let hash = Sha256::digest(&*payload);
            data_to_split.extend_from_slice(&hash);
        }
        data_to_split.extend_from_slice(&payload);

        let secret_len = data_to_split.len();
        let t = self.threshold as usize;
        let num_coeffs = secret_len.checked_mul(t - 1).ok_or_else(|| {
            ShamirError::StorageError("Data length overflow in coefficient generation".into())
        })?;

        let mut coefficients = vec![0u8; num_coeffs];
        self.rng.fill_bytes(&mut coefficients);

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
    pub fn split(&mut self, secret: &[u8]) -> Result<Vec<Share>> {
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
                                let mut acc = FiniteField::new(0);
                                for j in (0..t).rev() {
                                    let coeff = if j == 0 {
                                        FiniteField::new(data[byte_idx])
                                    } else {
                                        FiniteField::new(coefficients[byte_idx * (t - 1) + (j - 1)])
                                    };
                                    acc = acc * x + coeff;
                                }
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
    /// assert_eq!(secret, b"data");
    /// ```
    pub fn reconstruct(shares: &[Share]) -> Result<Vec<u8>> {
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
    pub fn reconstruct_from_views(views: &[ShareView<'_>]) -> Result<Vec<u8>> {
        if views.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
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

        for v in views {
            if v.threshold != threshold
                || v.total_shares != total_shares
                || v.integrity_check != integrity_check
                || v.compression != compression
                || v.data.len() != data_len
            {
                return Err(ShamirError::InvalidShareFormat);
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
        let mut reconstructed_data = Self::reconstruct_chunk_from_views(active_views)?;

        if integrity_check {
            if reconstructed_data.len() < HASH_SIZE {
                return Err(ShamirError::IntegrityCheckFailed);
            }
            let (expected_hash, payload) = reconstructed_data.split_at(HASH_SIZE);
            let calculated_hash = Sha256::digest(payload);

            if !bool::from(calculated_hash.as_slice().ct_eq(expected_hash)) {
                return Err(ShamirError::IntegrityCheckFailed);
            }

            if compression {
                #[cfg(feature = "compress")]
                {
                    let mut decompressed = Self::decompress_bounded(payload)?;
                    Ok(std::mem::take(&mut *decompressed))
                }
                #[cfg(not(feature = "compress"))]
                {
                    Err(ShamirError::InvalidConfig(
                        "Share requires 'compress' feature to decompress".into(),
                    ))
                }
            } else {
                reconstructed_data.drain(..HASH_SIZE);
                Ok(std::mem::take(&mut *reconstructed_data))
            }
        } else if compression {
            #[cfg(feature = "compress")]
            {
                let mut decompressed = Self::decompress_bounded(&reconstructed_data)?;
                Ok(std::mem::take(&mut *decompressed))
            }
            #[cfg(not(feature = "compress"))]
            {
                Err(ShamirError::InvalidConfig(
                    "Share requires 'compress' feature to decompress".into(),
                ))
            }
        } else {
            Ok(std::mem::take(&mut *reconstructed_data))
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
    /// [7-byte magic b"SHS_STR"][1-byte version 1][16-byte random stream_id][1-byte flags][1-byte share index][1-byte threshold][1-byte total_shares]
    /// [4-byte length][share chunk 0 data]
    /// [4-byte length][share chunk 1 data]
    /// ...
    /// [4-byte length = 0] (EOS marker)
    /// ```
    /// - `magic`: ASCII `SHS_STR` (7 bytes)
    /// - `version`: Stream format version (`1`)
    /// - `stream_id`: 16-byte random nonce from `SysRng` binding chunks to this specific stream session
    /// - `flags`: Bit 0 = SHA-256 integrity check enabled; Bit 1 = zstd compression enabled; Bits 2-7 reserved
    /// - `share index`: 1-based index (x-coordinate) of this share stream
    /// - `threshold`: Minimum shares required for reconstruction (>= 2)
    /// - `total_shares`: Total number of shares produced (>= threshold)
    /// - Each chunk is prefixed by a 4-byte little-endian length followed by the share chunk bytes
    /// - The stream concludes with a 4-byte `0u32` length signifying clean completion
    ///
    /// # Security
    /// - Chunks bind the 16-byte `stream_id`, chunk sequence index, and terminal `is_last` flag into the SHA-256 digest
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
        &mut self,
        source: &mut R,
        destinations: &mut [W],
    ) -> Result<()> {
        self.reseed_rng()?;
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

        let mut stream_id = [0u8; STREAM_ID_SIZE];
        SysRng
            .try_fill_bytes(&mut stream_id)
            .map_err(|e| ShamirError::RngError(e.to_string()))?;

        // Write 28-byte stream header to all destinations:
        // [STREAM_MAGIC: 7][STREAM_VERSION: 1][stream_id: 16][flags: 1][share_index: 1][threshold: 1][total_shares: 1]
        for (i, dest) in destinations.iter_mut().enumerate() {
            let mut header = [0u8; 28];
            header[0..7].copy_from_slice(STREAM_MAGIC);
            header[7] = STREAM_VERSION;
            header[8..24].copy_from_slice(&stream_id);
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
                let mut hasher = Sha256::new();
                hasher.update(stream_id);
                hasher.update([is_last]);
                hasher.update(chunk_index.to_le_bytes());
                hasher.update(&*payload);
                let hash = hasher.finalize();

                let mut data = Vec::with_capacity(HASH_SIZE + 1 + payload.len());
                data.extend_from_slice(&hash);
                data.push(is_last);
                data.extend_from_slice(&payload);
                data
            } else {
                let mut data = Vec::with_capacity(1 + payload.len());
                data.push(is_last);
                data.extend_from_slice(&payload);
                data
            });

            self.split_chunk_into(&chunk_with_digest, &mut share_data_buffers)?;

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
    /// - Verifies header consistency across all sources (magic b"SHS_STR", version 1, matching stream_id, threshold >= 2, matching flags, unique non-zero indices)
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
    pub fn reconstruct_stream<R: Read, W: Write>(
        sources: &mut [R],
        destination: &mut W,
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
                return Err(ShamirError::InvalidConfig(
                    "Inconsistent stream headers across sources".to_string(),
                ));
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
        let active_sources = &mut sources[..active_count];
        let share_indices: Vec<u8> = headers[..active_count].iter().map(|h| h[25]).collect();

        // Hoist Lagrange coefficient computation outside the chunk loop
        let lagrange_coefficients =
            Self::compute_lagrange_coefficients_from_indices(&share_indices)?;

        let mut chunk_lengths_buffer = Vec::with_capacity(active_count);
        let mut share_chunk_data_buffers: Vec<Zeroizing<Vec<u8>>> = (0..active_count)
            .map(|_| Zeroizing::new(Vec::new()))
            .collect();
        let mut reconstructed_chunk_buffer = Zeroizing::new(Vec::new());

        let mut chunk_index: u64 = 0;
        let mut stream_finished = false;

        while !stream_finished {
            chunk_lengths_buffer.clear();

            for source in active_sources.iter_mut() {
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

            for (i, source) in active_sources.iter_mut().enumerate() {
                let share_chunk_buffer = &mut share_chunk_data_buffers[i];
                if share_chunk_buffer.len() != first_len {
                    share_chunk_buffer.resize(first_len, 0);
                }
                source
                    .read_exact(share_chunk_buffer)
                    .map_err(ShamirError::IoError)?;
            }

            let reconstructed_chunk = Self::reconstruct_chunk_with_coefficients(
                &share_chunk_data_buffers,
                &lagrange_coefficients,
                &mut reconstructed_chunk_buffer,
            )?;

            let (is_last, payload) = if integrity_check {
                if reconstructed_chunk.len() < HASH_SIZE + 1 {
                    return Err(ShamirError::IntegrityCheckFailed);
                }
                let expected_hash = &reconstructed_chunk[..HASH_SIZE];
                let is_last = reconstructed_chunk[HASH_SIZE];
                let payload = &reconstructed_chunk[HASH_SIZE + 1..];

                let mut hasher = Sha256::new();
                hasher.update(stream_id);
                hasher.update([is_last]);
                hasher.update(chunk_index.to_le_bytes());
                hasher.update(payload);
                let calculated_hash = hasher.finalize();

                if !bool::from(calculated_hash.as_slice().ct_eq(expected_hash)) {
                    return Err(ShamirError::IntegrityCheckFailed);
                }
                (is_last, payload)
            } else {
                if reconstructed_chunk.is_empty() {
                    return Err(ShamirError::InvalidShareFormat);
                }
                let is_last = reconstructed_chunk[0];
                let payload = &reconstructed_chunk[1..];
                (is_last, payload)
            };

            if is_last != 0 && is_last != 1 {
                return Err(ShamirError::InvalidShareFormat);
            }

            if compression {
                #[cfg(feature = "compress")]
                {
                    let decompressed = Self::decompress_bounded(payload)?;
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

        // Verify the terminal EOS marker (0u32) on all active sources
        for source in active_sources.iter_mut() {
            let mut eos_bytes = [0u8; 4];
            source
                .read_exact(&mut eos_bytes)
                .map_err(ShamirError::IoError)?;
            if u32::from_le_bytes(eos_bytes) != 0 {
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
    ///
    /// # Security
    /// - Constant-time polynomial evaluation
    /// - Cryptographically secure randomness for polynomial coefficients
    fn split_chunk_into(
        &mut self,
        data: &[u8],
        destination_buffers: &mut [Zeroizing<Vec<u8>>],
    ) -> Result<()> {
        let secret_len = data.len();
        let t = self.threshold as usize;
        let num_coeffs = secret_len.checked_mul(t - 1).ok_or_else(|| {
            ShamirError::StorageError("Data length overflow in coefficient generation".into())
        })?;

        let mut random_data = Zeroizing::new(vec![0u8; num_coeffs]);
        self.rng.fill_bytes(&mut random_data);

        for (i, dest) in destination_buffers.iter_mut().enumerate() {
            let x_val = (i + 1) as u8;
            let x = FiniteField::new(x_val);
            dest.clear();
            dest.reserve(secret_len);

            for idx in 0..secret_len {
                let mut acc = FiniteField::new(0);
                for j in (0..t).rev() {
                    let coeff = if j == 0 {
                        FiniteField::new(data[idx])
                    } else {
                        FiniteField::new(random_data[idx * (t - 1) + (j - 1)])
                    };
                    acc = acc * x + coeff;
                }
                dest.push(acc.0);
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
    fn reconstruct_chunk_from_views(views: &[ShareView<'_>]) -> Result<Zeroizing<Vec<u8>>> {
        if views.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 2, got: 0 });
        }

        let secret_len = views[0].data.len();

        if !views.iter().all(|v| v.data.len() == secret_len) {
            return Err(ShamirError::InconsistentShareLength);
        }

        let lagrange_coefficients = Self::compute_lagrange_coefficients_from_views(views)?;
        let mut output_buffer = Zeroizing::new(vec![0u8; secret_len]);

        if secret_len >= 16384 {
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

    /// Optimized helper method to reconstruct a single chunk from share buffers with precomputed coefficients
    #[inline]
    fn reconstruct_chunk_with_coefficients<'a>(
        share_chunk_buffers: &[Zeroizing<Vec<u8>>],
        lagrange_coefficients: &[FiniteField],
        output_buffer: &'a mut Zeroizing<Vec<u8>>,
    ) -> Result<&'a [u8]> {
        if share_chunk_buffers.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 2, got: 0 });
        }

        let secret_len = share_chunk_buffers[0].len();

        output_buffer.clear();
        output_buffer.resize(secret_len, 0);

        for (share_idx, &coeff) in lagrange_coefficients.iter().enumerate() {
            let share_data = &share_chunk_buffers[share_idx];
            for byte_idx in 0..secret_len {
                output_buffer[byte_idx] ^= (coeff * FiniteField::new(share_data[byte_idx])).0;
            }
        }

        Ok(output_buffer.as_slice())
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
        &mut self,
        share_indices: &[u8],
        data_length: usize,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        let t = self.threshold as usize;
        let num_coeffs = data_length.checked_mul(t - 1).ok_or_else(|| {
            ShamirError::StorageError("Data length overflow in zero polynomial".into())
        })?;

        let mut random_data = Zeroizing::new(vec![0u8; num_coeffs]);
        self.rng.fill_bytes(&mut random_data);

        let delta_shares: Vec<Zeroizing<Vec<u8>>> = share_indices
            .par_iter()
            .map(|&index| {
                let x = FiniteField::new(index);
                let delta: Vec<u8> = (0..data_length)
                    .map(|byte_idx| {
                        let mut acc = FiniteField::new(0);
                        for j in (1..t).rev() {
                            let coeff = FiniteField::new(random_data[byte_idx * (t - 1) + (j - 1)]);
                            acc = acc * x + coeff;
                        }
                        acc = acc * x;
                        acc.0
                    })
                    .collect();
                Zeroizing::new(delta)
            })
            .collect();

        Ok(delta_shares)
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
    pub fn refresh_shares(&mut self, shares: &[Share]) -> Result<Vec<Share>> {
        self.reseed_rng()?;
        if shares.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
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
        let integrity_check = shares[0].integrity_check;
        let compression = shares[0].compression;

        for s in shares {
            if s.index == 0 || s.index > self.total_shares {
                return Err(ShamirError::InvalidShareIndex(s.index));
            }
            if s.threshold != self.threshold
                || s.total_shares != self.total_shares
                || s.integrity_check != integrity_check
                || s.compression != compression
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

        let indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
        let deltas = self.generate_zero_polynomial_shares(&indices, data_length)?;

        let refreshed_shares: Vec<Share> = shares
            .iter()
            .zip(deltas.iter())
            .map(|(old_share, delta_data)| {
                let new_data: Vec<u8> = old_share
                    .data
                    .iter()
                    .zip(delta_data.iter())
                    .map(|(&old_byte, &delta_byte)| old_byte ^ delta_byte)
                    .collect();

                Share {
                    index: old_share.index,
                    data: new_data,
                    threshold: old_share.threshold,
                    total_shares: old_share.total_shares,
                    integrity_check: old_share.integrity_check,
                    compression: old_share.compression,
                }
            })
            .collect();

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
                let mut acc = FiniteField::new(0);
                for j in (0..t).rev() {
                    let coeff = if j == 0 {
                        FiniteField::new(self.data[byte_idx])
                    } else {
                        FiniteField::new(self.coefficients[byte_idx * (t - 1) + (j - 1)])
                    };
                    acc = acc * x + coeff;
                }
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
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

        // Split the secret into 5 shares
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly threshold (3) shares
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);

        // Reconstruct with more than threshold shares (4 shares)
        let reconstructed = ShamirShare::reconstruct(&shares[1..5]).unwrap();
        assert_eq!(&reconstructed, secret);
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
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();

        // Reconstruct with 2 shares when threshold is 3 should fail
        assert!(ShamirShare::reconstruct(&shares[0..2]).is_err());
    }

    #[test]
    fn test_different_share_combinations() {
        let secret = b"Different combinations test";
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();

        // Try different combinations of 3 shares
        let combinations = vec![vec![0, 1, 2], vec![1, 2, 3], vec![2, 3, 4], vec![0, 2, 4]];

        for combo in combinations {
            let selected_shares: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            let reconstructed = ShamirShare::reconstruct(&selected_shares).unwrap();
            assert_eq!(&reconstructed, secret);
        }
    }

    #[test]
    fn test_empty_secret() {
        let secret = b"";
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = b"x";
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_max_shares() {
        let secret = b"Maximum shares test";
        let mut shamir = ShamirShare::builder(255, 128).build().unwrap();
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 255);

        let reconstructed = ShamirShare::reconstruct(&shares[0..128]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_duplicate_share_indices() {
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
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
        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
        let mut shares = shamir.split(b"test").unwrap();
        shares[0].index = 0;

        assert!(matches!(
            ShamirShare::reconstruct(&shares[0..2]),
            Err(ShamirError::InvalidShareIndex(0))
        ));
    }

    #[test]
    fn test_corrupted_share_data() {
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
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
        let mut shamir = ShamirShare::builder(5, 3)
            .with_config(config)
            .build()
            .unwrap();

        let secret = b"test secret without integrity check";
        let shares = shamir.split(secret).unwrap();
        assert!(!shares[0].integrity_check);

        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_mixed_integrity_flags_fail() {
        let mut shamir_with = ShamirShare::builder(5, 3).build().unwrap();
        let mut shamir_without = ShamirShare::builder(5, 3)
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
            .with_integrity_check(false);

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
        assert!(!shamir.config.integrity_check());
    }

    #[test]
    fn test_split_stream_basic() {
        use std::io::Cursor;

        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
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
        let mut shamir = ShamirShare::builder(3, 2)
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

        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
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

        // 28 bytes header + 4 bytes chunk length + 33 bytes data (32 hash + 1 is_last) + 4 bytes terminal EOS
        for share in &share_data {
            assert_eq!(share.len(), 69);
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
        let mut shamir = ShamirShare::builder(3, 2)
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
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

        let dealer_shares: Vec<Share> = shamir.try_dealer(secret).unwrap().take(5).collect();
        assert_eq!(dealer_shares.len(), 5);

        for (i, share) in dealer_shares.iter().enumerate() {
            assert_eq!(share.index, (i + 1) as u8);
            assert_eq!(share.threshold, 3);
            assert_eq!(share.total_shares, 5);
            assert!(share.integrity_check);
        }

        let reconstructed = ShamirShare::reconstruct(&dealer_shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_dealer_size_hint() {
        let secret = b"Size hint test";
        let mut shamir = ShamirShare::builder(10, 5).build().unwrap();

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
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

        let mut dealer = shamir.try_dealer(secret).unwrap();
        let shares: Vec<Share> = dealer.by_ref().collect();
        assert_eq!(shares.len(), 5);
        assert_eq!(dealer.next(), None);
    }

    #[test]
    fn test_parallel_split_mode() {
        let config = Config::new().with_mode(SplitMode::Parallel);
        let mut shamir = ShamirShare::builder(5, 3)
            .with_config(config)
            .build()
            .unwrap();

        let secret = b"Parallel split test data";
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_zero_index_stream_header_rejected() {
        use std::io::Cursor;
        let mut h1 = [0u8; 28];
        h1[0..7].copy_from_slice(b"SHS_STR");
        h1[7] = 1;
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
        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
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
        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
        let secret = b"Excess shares test";
        let mut shares = shamir.split(secret).unwrap();
        shares.push(shares[0].clone());

        assert!(matches!(
            ShamirShare::reconstruct(&shares),
            Err(ShamirError::InvalidShareFormat)
        ));
    }
}
