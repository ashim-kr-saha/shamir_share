use crate::config::Config;
use crate::error::{Result, ShamirError};
use crate::finite_field::FiniteField;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use rand_core::SeedableRng;
use rayon::iter::ParallelIterator;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

const HASH_SIZE: usize = 32; // SHA-256 output size

/// A share in Shamir's Secret Sharing scheme
///
/// Each share contains a portion of the secret data along with metadata needed for reconstruction.
/// Individual shares reveal no information about the original secret without meeting the threshold.
///
/// # Security
///
/// - Share data is computed using constant-time GF(2^8) arithmetic
/// - Contains integrity metadata to detect tampering during reconstruction
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
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Share {
    /// Index of the share (x-coordinate in the polynomial)
    pub index: u8,
    /// The share data (y-coordinates for each byte of the secret)
    pub data: Vec<u8>,
    /// Minimum number of shares required for reconstruction
    pub threshold: u8,
    /// Total number of shares created
    pub total_shares: u8,
    /// Whether integrity checking was enabled when this share was created
    pub integrity_check: bool,
    /// Whether the data was compressed before splitting
    pub compression: bool,
}

/// A lightweight view into share data for reconstruction without allocation
///
/// This struct provides a borrowed view of share data to avoid cloning during
/// reconstruction operations. It's used internally by `reconstruct_stream` to
/// eliminate allocation pressure in the hot loop.
///
/// # Security
///
/// - Maintains the same security properties as `Share`
/// - Uses borrowed data to avoid unnecessary allocations
/// - Constant-time operations are preserved
#[derive(Debug, Clone, Copy)]
pub struct ShareView<'a> {
    /// Index of the share (x-coordinate in the polynomial)
    pub index: u8,
    /// Borrowed reference to the share data
    pub data: &'a [u8],
}

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
/// - Maximum of 255 shares can be generated (GF(256) field limitation)
///
/// # Example
/// ```
/// use shamir_share::ShamirShare;
///
/// let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
/// let secret = b"secret data";
///
/// // Generate shares lazily
/// let shares: Vec<_> = shamir.dealer(secret).take(3).collect();
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

/// Main implementation of Shamir's Secret Sharing scheme
///
/// This implementation prioritizes security with constant-time operations to prevent
/// side-channel attacks. Uses GF(256) arithmetic for polynomial operations and
/// ChaCha20 CSPRNG for generating polynomial coefficients.
///
/// # Security Features
///
/// - **Constant-time operations**: All GF(2^8) arithmetic uses constant-time algorithms
/// - **Secure random generation**: ChaCha20Rng seeded from OsRng for polynomial coefficients  
/// - **Integrity verification**: SHA-256 hash prepended to secret with constant-time verification
/// - **Side-channel resistance**: No lookup tables or data-dependent branching
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
#[derive(Debug)]
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

/// Builder for creating ShamirShare instances with custom configuration
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
#[derive(Debug)]
pub struct ShamirShareBuilder {
    total_shares: u8,
    threshold: u8,
    config: Config,
}

impl ShamirShareBuilder {
    /// Creates a new builder with the specified parameters and default configuration
    ///
    /// # Arguments
    /// * `total_shares` - Total number of shares to create (1-255)
    /// * `threshold` - Minimum shares required for reconstruction (1-total_shares)
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
    /// - `total_shares` is 0
    /// - `threshold` is 0
    /// - `threshold` > `total_shares`
    /// - Configuration validation fails
    pub fn build(self) -> Result<ShamirShare> {
        // Validate parameters
        if self.total_shares == 0 {
            return Err(ShamirError::InvalidShareCount(self.total_shares));
        }
        if self.threshold == 0 {
            return Err(ShamirError::InvalidThreshold(self.threshold));
        }
        if self.threshold > self.total_shares {
            return Err(ShamirError::ThresholdTooLarge {
                threshold: self.threshold,
                total_shares: self.total_shares,
            });
        }

        // Validate configuration
        self.config.validate()?;

        Ok(ShamirShare {
            total_shares: self.total_shares,
            threshold: self.threshold,
            config: self.config,
            rng: ChaCha20Rng::try_from_rng(&mut OsRng).unwrap(),
        })
    }
}

impl ShamirShare {
    /// Returns the threshold (minimum number of shares needed for reconstruction)
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Returns the total number of shares configured for this scheme
    pub fn total_shares(&self) -> u8 {
        self.total_shares
    }

    /// Creates a builder for configuring a ShamirShare instance
    ///
    /// This is the recommended way to create ShamirShare instances as it allows
    /// for flexible configuration through the builder pattern.
    ///
    /// # Arguments
    /// * `total_shares` - Total number of shares to create (1-255)
    /// * `threshold` - Minimum shares required for reconstruction (1-total_shares)
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
    /// # Arguments
    /// * `secret` - Byte slice to protect
    ///
    /// # Returns
    /// A [`Dealer`] iterator that yields [`Share`] objects on demand
    ///
    /// # Security
    /// - Uses ChaCha20Rng for generating polynomial coefficients
    /// - All operations are constant-time to prevent side-channel attacks
    /// - SHA-256 integrity hash is included if `config.integrity_check` is true
    /// - Maximum of 255 shares can be generated (GF(256) field limitation)
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    ///
    /// let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
    /// let secret = b"secret data";
    ///
    /// // Generate only the shares you need
    /// let shares: Vec<_> = scheme.dealer(secret).take(3).collect();
    /// assert_eq!(shares.len(), 3);
    ///
    /// // Or iterate through all shares
    /// for (i, share) in scheme.dealer(secret).enumerate() {
    ///     println!("Share {}: {:?}", i + 1, share);
    ///     if i >= 2 { break; } // Stop after 3 shares
    /// }
    /// ```
    pub fn dealer(&mut self, secret: &[u8]) -> Dealer {
        // Prepare data to split based on integrity check configuration
        #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
        let mut data_to_split = if self.config.integrity_check {
            // Calculate hash of the secret and prepend it
            let hash = Sha256::digest(secret);
            let mut data = Vec::with_capacity(HASH_SIZE + secret.len());
            data.extend_from_slice(&hash);
            #[cfg(feature = "compress")]
            if self.config.compression {
                let compressed_secret = zstd::encode_all(secret, 0)
                    .map_err(|e| ShamirError::CompressionError(e.to_string()))
                    .unwrap();
                data.extend_from_slice(&compressed_secret);
            } else {
                data.extend_from_slice(secret);
            }
            #[cfg(not(feature = "compress"))]
            data.extend_from_slice(secret);
            data
        } else {
            // Use secret data directly without integrity hash
            #[cfg(feature = "compress")]
            if self.config.compression {
                zstd::encode_all(secret, 0)
                    .map_err(|e| ShamirError::CompressionError(e.to_string()))
                    .unwrap()
            } else {
                secret.to_vec()
            }
            #[cfg(not(feature = "compress"))]
            secret.to_vec()
        };

        let secret_len = data_to_split.len();
        let t = self.threshold as usize;

        // Pre-compute all random polynomial coefficients (for coefficients 1..t)
        let mut coefficients = vec![0u8; secret_len * (t - 1)];
        self.rng.fill_bytes(&mut coefficients);

        let dealer = Dealer {
            data: data_to_split.clone(),
            coefficients: coefficients.clone(),
            current_x: 1,
            threshold: self.threshold,
            total_shares: self.total_shares,
            integrity_check: self.config.integrity_check,
            compression: self.config.compression,
        };

        // Zeroize sensitive buffers before returning
        #[cfg(feature = "zeroize")]
        {
            data_to_split.zeroize();
            coefficients.zeroize();
        }

        dealer
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
    /// - Uses ChaCha20Rng for generating polynomial coefficients
    /// - All operations are constant-time to prevent side-channel attacks
    /// - SHA-256 integrity hash is included if `config.integrity_check` is true
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
        // Use the new dealer for backward compatibility
        Ok(self
            .dealer(secret)
            .take(self.total_shares as usize)
            .collect())
    }

    /// Reconstructs the original secret from shares using Lagrange interpolation
    ///
    /// This method uses constant-time GF(2^8) arithmetic for reconstruction and performs
    /// integrity verification using constant-time hash comparison to detect tampering if
    /// the shares were created with integrity checking enabled.
    ///
    /// # Arguments
    /// * `shares` - Slice of shares to use for reconstruction
    ///
    /// # Returns
    /// The original secret data if reconstruction and integrity verification succeed
    ///
    /// # Security
    /// - All GF(2^8) operations are constant-time
    /// - SHA-256 integrity verification with constant-time comparison (if enabled)
    /// - Parallel processing maintains security guarantees
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - No shares provided
    /// - Insufficient shares for threshold
    /// - Shares have inconsistent lengths or integrity check settings
    /// - Invalid share data
    /// - Integrity check fails (tampering detected)
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
        if shares.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
        }

        let threshold = shares[0].threshold;
        if shares.len() < threshold as usize {
            return Err(ShamirError::InsufficientShares {
                needed: threshold,
                got: shares.len() as u8,
            });
        }

        let integrity_check = shares[0].integrity_check;
        let compression = shares[0].compression;

        // Ensure all shares have consistent properties
        if !shares.iter().all(|s| {
            s.data.len() == shares[0].data.len()
                && s.integrity_check == integrity_check
                && s.compression == compression
        }) {
            return Err(ShamirError::InconsistentShareLength);
        }

        // Use the unified reconstruct_chunk method for the core reconstruction logic
        #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
        let mut reconstructed_data = Self::reconstruct_chunk(shares)?;

        // Handle integrity checking based on share configuration
        let result = if integrity_check {
            // Shares were created with integrity checking - verify hash
            if reconstructed_data.len() < HASH_SIZE {
                return Err(ShamirError::IntegrityCheckFailed);
            }
            let (reconstructed_hash, compressed_secret) = reconstructed_data.split_at(HASH_SIZE);

            let secret = {
                #[cfg(feature = "compress")]
                if compression {
                    zstd::decode_all(compressed_secret)
                        .map_err(|e| ShamirError::DecompressionError(e.to_string()))?
                } else {
                    compressed_secret.to_vec()
                }
                #[cfg(not(feature = "compress"))]
                compressed_secret.to_vec()
            };

            // Verify the integrity of the secret using constant-time comparison
            let calculated_hash = Sha256::digest(&secret);
            let mut hash_match = 0u8;
            for (a, b) in calculated_hash
                .as_slice()
                .iter()
                .zip(reconstructed_hash.iter())
            {
                hash_match |= a ^ b;
            }
            if hash_match != 0 {
                return Err(ShamirError::IntegrityCheckFailed);
            }

            Ok(secret)
        } else {
            // Shares were created without integrity checking - return data directly
            #[cfg(feature = "compress")]
            if compression {
                zstd::decode_all(reconstructed_data.as_slice())
                    .map_err(|e| ShamirError::DecompressionError(e.to_string()))
            } else {
                Ok(reconstructed_data.clone())
            }
            #[cfg(not(feature = "compress"))]
            Ok(reconstructed_data.clone())
        };

        // Zeroize sensitive reconstructed data buffer before returning
        #[cfg(feature = "zeroize")]
        reconstructed_data.zeroize();

        result
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
    /// Each destination stream contains a header followed by a sequence of chunks:
    /// ```text
    /// [1-byte integrity flag][1-byte share index][4-byte length][share data for chunk 1][4-byte length][share data for chunk 2]...
    /// ```
    /// - The integrity flag indicates whether integrity checking was used (1 = enabled, 0 = disabled)
    /// - The share index indicates which share this stream represents (1-based)
    /// - The length is written in little-endian format and represents the size of the following share data
    ///
    /// # Security
    /// - Each chunk is processed independently with its own integrity hash (if enabled)
    /// - Constant-time operations maintain security guarantees
    /// - Chunk-level integrity checking allows for early detection of corruption
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - Number of destinations doesn't match `total_shares`
    /// - I/O errors occur during reading or writing
    /// - Memory allocation fails for large chunks
    ///
    /// # Example
    /// ```
    /// use shamir_share::{ShamirShare, Config};
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
        // Validate that we have the correct number of destinations
        if destinations.len() != self.total_shares as usize {
            return Err(ShamirError::InvalidConfig(format!(
                "Expected {} destinations, got {}",
                self.total_shares,
                destinations.len()
            )));
        }

        // Write header (flags + share index) to all destinations
        let integrity_flag = if self.config.integrity_check { 1 } else { 0 };
        let compression_flag = if self.config.compression { 2 } else { 0 };
        let flags = integrity_flag | compression_flag;

        for (i, dest) in destinations.iter_mut().enumerate() {
            dest.write_all(&[flags, (i + 1) as u8])
                .map_err(ShamirError::IoError)?;
        }

        let chunk_size = self.config.chunk_size;

        // Reuse buffers to avoid allocations in the hot loop
        let mut chunk_read_buffer = vec![0u8; chunk_size];
        let mut chunk_with_hash_buffer = Vec::with_capacity(if self.config.integrity_check {
            HASH_SIZE + chunk_size
        } else {
            chunk_size
        });

        // Pre-allocate share data buffers to reuse across chunks
        let max_chunk_size_with_hash = if self.config.integrity_check {
            HASH_SIZE + chunk_size
        } else {
            chunk_size
        };
        let mut share_data_buffers: Vec<Vec<u8>> = (0..self.total_shares)
            .map(|_| Vec::with_capacity(max_chunk_size_with_hash))
            .collect();

        loop {
            // Read a chunk from the source
            let bytes_read = source
                .read(&mut chunk_read_buffer)
                .map_err(ShamirError::IoError)?;
            if bytes_read == 0 {
                break; // EOF reached
            }

            // Process only the bytes that were actually read
            let chunk = &chunk_read_buffer[..bytes_read];

            // Prepare data for splitting (with or without integrity check)
            // Reuse buffer to avoid allocations in the hot loop
            chunk_with_hash_buffer.clear();
            if self.config.integrity_check {
                let hash = Sha256::digest(chunk);
                chunk_with_hash_buffer.extend_from_slice(&hash);
            }

            #[cfg(feature = "compress")]
            if self.config.compression {
                let compressed_chunk = zstd::encode_all(chunk, 0)
                    .map_err(|e| ShamirError::CompressionError(e.to_string()))?;
                chunk_with_hash_buffer.extend_from_slice(&compressed_chunk);
            } else {
                chunk_with_hash_buffer.extend_from_slice(chunk);
            }
            #[cfg(not(feature = "compress"))]
            chunk_with_hash_buffer.extend_from_slice(chunk);

            // Split the chunk using the unified split_chunk method
            let chunk_share_data = self.split_chunk(&chunk_with_hash_buffer)?;

            // Copy the results into our reusable buffers for writing
            for (share_idx, chunk_data) in chunk_share_data.iter().enumerate() {
                let share_buffer = &mut share_data_buffers[share_idx];
                share_buffer.clear();
                share_buffer.extend_from_slice(chunk_data);
            }

            // Write each share to its corresponding destination with length prefix
            for (i, share_data) in share_data_buffers.iter().enumerate() {
                // Write length prefix (4 bytes, little-endian)
                let length = share_data.len() as u32;
                destinations[i]
                    .write_all(&length.to_le_bytes())
                    .map_err(ShamirError::IoError)?;

                // Write the share data
                destinations[i]
                    .write_all(share_data)
                    .map_err(ShamirError::IoError)?;
            }
        }

        // Zeroize sensitive buffers before returning
        #[cfg(feature = "zeroize")]
        {
            chunk_read_buffer.zeroize();
            chunk_with_hash_buffer.zeroize();
            for buffer in &mut share_data_buffers {
                buffer.zeroize();
            }
        }

        // Flush all destinations
        for dest in destinations.iter_mut() {
            dest.flush().map_err(ShamirError::IoError)?;
        }

        Ok(())
    }

    /// Reconstructs data from multiple share streams using chunk-based processing
    ///
    /// This method reads share data from multiple sources in lock-step, reconstructs each chunk
    /// independently, and writes the original data to the destination. It reads the integrity
    /// checking flag from the stream header to determine how to process the data.
    ///
    /// # Arguments
    /// * `sources` - Array of readers, one for each share (must have at least `threshold` sources)
    /// * `destination` - Writer to write reconstructed data to
    ///
    /// # Data Format
    /// Each source stream must contain chunks in the format written by `split_stream`:
    /// ```text
    /// [1-byte integrity flag][1-byte share index][4-byte length][share data for chunk 1][4-byte length][share data for chunk 2]...
    /// ```
    ///
    /// # Security
    /// - Chunk-level integrity verification (if enabled during splitting)
    /// - Constant-time reconstruction operations
    /// - Early failure on integrity check violations
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - Insufficient sources for reconstruction
    /// - I/O errors occur during reading or writing
    /// - Integrity check fails for any chunk
    /// - Inconsistent chunk sizes across sources
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    /// use std::io::Cursor;
    ///
    /// // First, create some share data using split_stream
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
    /// // Now reconstruct from the first 2 shares
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
        if sources.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
        }

        // Read integrity check flag and share indices from all sources
        let mut headers: Vec<[u8; 2]> = Vec::with_capacity(sources.len());
        for source in sources.iter_mut() {
            let mut header = [0u8; 2];
            source
                .read_exact(&mut header)
                .map_err(ShamirError::IoError)?;
            headers.push(header);
        }

        let first_flags = headers[0][0];
        let integrity_check = (first_flags & 1) != 0;
        let compression = (first_flags & 2) != 0;

        for header in headers.iter().skip(1) {
            if header[0] != first_flags {
                return Err(ShamirError::InvalidConfig(
                    "Inconsistent flags across sources".to_string(),
                ));
            }
        }

        let share_indices: Vec<u8> = headers.iter().map(|h| h[1]).collect();

        // Pre-allocate buffers to reuse across chunks to avoid allocations in hot loop
        let mut chunk_lengths_buffer = Vec::with_capacity(sources.len());
        let mut share_chunk_data_buffers: Vec<Vec<u8>> =
            (0..sources.len()).map(|_| Vec::new()).collect();
        let mut reconstructed_chunk_buffer = Vec::new();

        loop {
            // Read length prefixes from all sources
            // Reuse buffer to avoid allocations in the hot loop
            chunk_lengths_buffer.clear();
            let mut eof_reached = false;

            for source in sources.iter_mut() {
                let mut length_bytes = [0u8; 4];
                match source.read_exact(&mut length_bytes) {
                    Ok(()) => {
                        let length = u32::from_le_bytes(length_bytes) as usize;
                        chunk_lengths_buffer.push(length);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        eof_reached = true;
                        break;
                    }
                    Err(e) => return Err(ShamirError::IoError(e)),
                }
            }

            if eof_reached {
                break; // All sources should reach EOF simultaneously
            }

            // Read share data from all sources
            // Reuse buffers to avoid allocations in the hot loop
            for (i, source) in sources.iter_mut().enumerate() {
                let share_chunk_buffer = &mut share_chunk_data_buffers[i];
                let chunk_length = chunk_lengths_buffer[i];

                // Resize buffer only if needed to avoid unnecessary allocations
                if share_chunk_buffer.len() != chunk_length {
                    share_chunk_buffer.resize(chunk_length, 0);
                }

                source
                    .read_exact(share_chunk_buffer)
                    .map_err(ShamirError::IoError)?;
            }

            // Create temporary ShareView objects for reconstruction without allocation
            // This avoids the expensive clone() operation in the hot loop
            let share_views: Vec<ShareView> = share_chunk_data_buffers
                .iter()
                .enumerate()
                .map(|(i, share_chunk_data)| ShareView {
                    index: share_indices[i], // Use the actual share index from the stream
                    data: share_chunk_data,  // Borrow the data instead of cloning
                })
                .collect();

            // Reconstruct the chunk using optimized reconstruction with borrowed data
            let reconstructed_chunk = Self::reconstruct_chunk_from_views(
                &share_views,
                &mut reconstructed_chunk_buffer,
            )?;

            // Handle integrity checking based on the flag we read
            if integrity_check {
                // Integrity checking was used - verify hash and extract data
                if reconstructed_chunk.len() < HASH_SIZE {
                    return Err(ShamirError::IntegrityCheckFailed);
                }
                let (reconstructed_hash, compressed_data) = reconstructed_chunk.split_at(HASH_SIZE);

                let data = {
                    #[cfg(feature = "compress")]
                    if compression {
                        zstd::decode_all(compressed_data)
                            .map_err(|e| ShamirError::DecompressionError(e.to_string()))?
                    } else {
                        compressed_data.to_vec()
                    }
                    #[cfg(not(feature = "compress"))]
                    compressed_data.to_vec()
                };

                // Verify the integrity of the data using constant-time comparison
                let calculated_hash = Sha256::digest(&data);
                let mut hash_match = 0u8;
                for (a, b) in calculated_hash
                    .as_slice()
                    .iter()
                    .zip(reconstructed_hash.iter())
                {
                    hash_match |= a ^ b;
                }
                if hash_match != 0 {
                    return Err(ShamirError::IntegrityCheckFailed);
                }

                // Write only the data part (without hash) to destination
                destination.write_all(&data).map_err(ShamirError::IoError)?;
            } else {
                // No integrity checking - write data directly
                #[cfg(feature = "compress")]
                if compression {
                    let data = zstd::decode_all(reconstructed_chunk)
                        .map_err(|e| ShamirError::DecompressionError(e.to_string()))?;
                    destination.write_all(&data).map_err(ShamirError::IoError)?;
                } else {
                    destination
                        .write_all(reconstructed_chunk)
                        .map_err(ShamirError::IoError)?;
                }
                #[cfg(not(feature = "compress"))]
                destination
                    .write_all(reconstructed_chunk)
                    .map_err(ShamirError::IoError)?;
            };
        }

        // Zeroize sensitive buffers before returning
        #[cfg(feature = "zeroize")]
        {
            for buffer in &mut share_chunk_data_buffers {
                buffer.zeroize();
            }
            reconstructed_chunk_buffer.zeroize();
        }

        // Flush the destination
        destination.flush().map_err(ShamirError::IoError)?;

        Ok(())
    }

    /// Helper method to split a single chunk of data into share data
    ///
    /// This is the canonical implementation for splitting data using Shamir's Secret Sharing.
    /// It takes a data chunk and returns the raw share data for each share.
    /// Used internally by both `split` and `split_stream` methods to ensure consistency.
    ///
    /// # Arguments
    /// * `data` - The data chunk to split
    ///
    /// # Returns
    /// A vector where each element contains the share data for one share.
    /// The outer vector index corresponds to the share number (0-based).
    ///
    /// # Security
    /// - Uses cryptographically secure random coefficients
    /// - Constant-time polynomial evaluation
    /// - Parallel processing for performance while maintaining security
    #[inline]
    fn split_chunk(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let secret_len = data.len();
        let t = self.threshold as usize;

        // Bulk generate random coefficients for all secret bytes (for coefficients 1..t)
        let mut random_data = vec![0u8; secret_len * (t - 1)];
        self.rng.fill_bytes(&mut random_data);

        // Precompute x values for each share
        let x_values: Vec<FiniteField> = (1..=self.total_shares).map(FiniteField::new).collect();

        // Evaluate the polynomial for each share in parallel
        // For each secret byte at index idx, the polynomial is:
        // P(x) = data[idx] + random_coef1 * x + random_coef2 * x^2 + ... + random_coef_{t-1} * x^(t-1)
        let share_data: Vec<Vec<u8>> = x_values
            .into_par_iter()
            .map(|x| {
                (0..secret_len)
                    .map(|idx| {
                        let mut acc = FiniteField::new(0);
                        // Evaluate polynomial using Horner's method (iterating coefficients in reverse order)
                        for j in (0..t).rev() {
                            let coeff = if j == 0 {
                                FiniteField::new(data[idx])
                            } else {
                                // Random coefficient for x^j is stored in random_data at position idx*(t-1) + (j-1)
                                FiniteField::new(random_data[idx * (t - 1) + (j - 1)])
                            };
                            acc = acc * x + coeff;
                        }
                        acc.0
                    })
                    .collect()
            })
            .collect();

        // Zeroize sensitive random coefficients before returning
        #[cfg(feature = "zeroize")]
        random_data.zeroize();

        Ok(share_data)
    }

    /// Helper method to compute Lagrange coefficients for reconstruction
    ///
    /// This is the shared implementation for computing Lagrange interpolation coefficients.
    /// Used by both reconstruction helper methods to ensure consistency and reduce code duplication.
    ///
    /// # Arguments
    /// * `shares` - Slice of shares to compute coefficients for
    ///
    /// # Returns
    /// Vector of Lagrange coefficients for each share
    ///
    /// # Security
    /// - Constant-time coefficient computation
    /// - Validates share indices for uniqueness
    #[inline]
    fn compute_lagrange_coefficients(shares: &[Share]) -> Result<Vec<FiniteField>> {
        let xs: Vec<FiniteField> = shares
            .iter()
            .map(|share| FiniteField::new(share.index))
            .collect();

        // Check for duplicate share indices
        for i in 0..xs.len() {
            for j in (i + 1)..xs.len() {
                if xs[i] == xs[j] {
                    return Err(ShamirError::InvalidShareFormat);
                }
            }
        }

        let p = xs.iter().fold(FiniteField::new(1), |acc, &x| acc * x);
        let lagrange_coefficients: Result<Vec<FiniteField>> = xs
            .iter()
            .enumerate()
            .map(|(i, &x_i)| {
                // Since x_i != 0, division by x_i is safe via multiplication by its inverse
                let numerator = p * x_i.inverse().unwrap();
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

    /// Helper method to compute Lagrange coefficients for reconstruction using ShareView
    ///
    /// This version works with borrowed share data to avoid allocations in hot paths.
    /// Used internally by `reconstruct_stream` for performance optimization.
    ///
    /// # Arguments
    /// * `share_views` - Slice of share views to compute coefficients for
    ///
    /// # Returns
    /// Vector of Lagrange coefficients for each share
    ///
    /// # Security
    /// - Constant-time coefficient computation
    /// - Validates share indices for uniqueness
    #[inline]
    fn compute_lagrange_coefficients_from_views(share_views: &[ShareView]) -> Result<Vec<FiniteField>> {
        let xs: Vec<FiniteField> = share_views
            .iter()
            .map(|view| FiniteField::new(view.index))
            .collect();

        // Check for duplicate share indices
        for i in 0..xs.len() {
            for j in (i + 1)..xs.len() {
                if xs[i] == xs[j] {
                    return Err(ShamirError::InvalidShareFormat);
                }
            }
        }

        let p = xs.iter().fold(FiniteField::new(1), |acc, &x| acc * x);
        let lagrange_coefficients: Result<Vec<FiniteField>> = xs
            .iter()
            .enumerate()
            .map(|(i, &x_i)| {
                // Since x_i != 0, division by x_i is safe via multiplication by its inverse
                let numerator = p * x_i.inverse().unwrap();
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

    /// Helper method to reconstruct data from shares using Lagrange interpolation
    ///
    /// This is the canonical implementation for reconstructing data using Shamir's Secret Sharing.
    /// It takes a slice of shares and returns the reconstructed data.
    /// Used internally by both `reconstruct` and `reconstruct_stream` methods to ensure consistency.
    ///
    /// # Arguments
    /// * `shares` - Slice of shares to use for reconstruction
    ///
    /// # Returns
    /// The reconstructed data (may include integrity hash if shares were created with integrity checking)
    ///
    /// # Security
    /// - Constant-time Lagrange interpolation
    /// - Parallel processing for performance while maintaining security
    /// - Validates share consistency before processing
    #[inline]
    fn reconstruct_chunk(shares: &[Share]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
        }

        let secret_len = shares[0].data.len();

        // Ensure all shares have consistent length
        if !shares.iter().all(|s| s.data.len() == secret_len) {
            return Err(ShamirError::InconsistentShareLength);
        }

        // Use shared Lagrange coefficient computation
        let lagrange_coefficients = Self::compute_lagrange_coefficients(shares)?;

        // Parallelize reconstruction across bytes for performance
        let reconstructed_data = (0..secret_len)
            .into_par_iter()
            .map(|byte_idx| {
                shares
                    .iter()
                    .zip(&lagrange_coefficients)
                    .fold(FiniteField::new(0), |acc, (share, &coeff)| {
                        acc + coeff * FiniteField::new(share.data[byte_idx])
                    })
                    .0
            })
            .collect::<Vec<u8>>();

        Ok(reconstructed_data)
    }


    /// Optimized helper method to reconstruct a single chunk from share views with buffer reuse
    ///
    /// This version uses borrowed share data to eliminate allocations in hot paths.
    /// Used internally by `reconstruct_stream` for maximum performance optimization.
    ///
    /// # Arguments
    /// * `share_views` - Slice of share views to use for reconstruction
    /// * `output_buffer` - Reusable buffer for the reconstructed data
    ///
    /// # Returns
    /// Slice reference to the reconstructed data in the output buffer
    ///
    /// # Security
    /// - Constant-time Lagrange interpolation
    /// - Uses borrowed data to avoid allocations
    /// - Validates share consistency before processing
    #[inline]
    fn reconstruct_chunk_from_views<'a>(
        share_views: &[ShareView],
        output_buffer: &'a mut Vec<u8>,
    ) -> Result<&'a [u8]> {
        if share_views.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
        }

        let secret_len = share_views[0].data.len();

        // Ensure all share views have consistent length
        if !share_views.iter().all(|v| v.data.len() == secret_len) {
            return Err(ShamirError::InconsistentShareLength);
        }

        // Use shared Lagrange coefficient computation for views
        let lagrange_coefficients = Self::compute_lagrange_coefficients_from_views(share_views)?;

        // Reuse output buffer to avoid allocations in the hot loop
        output_buffer.clear();
        output_buffer.reserve(secret_len);

        // Reconstruct each byte directly into the output buffer
        for byte_idx in 0..secret_len {
            let reconstructed_byte = share_views
                .iter()
                .zip(&lagrange_coefficients)
                .fold(FiniteField::new(0), |acc, (view, &coeff)| {
                    acc + coeff * FiniteField::new(view.data[byte_idx])
                })
                .0;
            output_buffer.push(reconstructed_byte);
        }

        Ok(output_buffer)
    }

    /// Generates share deltas by creating and evaluating a random polynomial whose secret is zero
    ///
    /// This private helper method creates a polynomial of degree `k-1` where the constant term
    /// (the "secret") is zero, and evaluates it at the given share indices. The resulting
    /// delta values can be added to existing shares for share refreshing.
    ///
    /// # Arguments
    /// * `share_indices` - Slice of x-coordinates (share indices) to evaluate the polynomial at
    /// * `data_length` - Length of the zero secret data to generate deltas for
    ///
    /// # Returns
    /// Vector where each element contains the delta data for the corresponding share index
    ///
    /// # Security
    /// - Uses cryptographically secure random coefficients
    /// - Constant-time polynomial evaluation using Horner's method
    /// - Zero constant term ensures deltas maintain the secret sharing property
    fn generate_zero_polynomial_shares(
        &mut self,
        share_indices: &[u8],
        data_length: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let t = self.threshold as usize;

        // Generate random coefficients for all data bytes (for coefficients 1..t)
        // The constant term (coefficient 0) is always zero for all bytes
        let mut random_data = vec![0u8; data_length * (t - 1)];
        self.rng.fill_bytes(&mut random_data);

        // Evaluate the polynomial for each share index
        let delta_shares: Vec<Vec<u8>> = share_indices
            .par_iter()
            .map(|&index| {
                let x = FiniteField::new(index);

                // For each byte position, evaluate the polynomial at x
                (0..data_length)
                    .map(|byte_idx| {
                        let mut acc = FiniteField::new(0);

                        // Evaluate polynomial using Horner's method (iterating coefficients in reverse order)
                        // P(x) = 0 + random_coef1 * x + random_coef2 * x^2 + ... + random_coef_{t-1} * x^(t-1)
                        for j in (1..t).rev() {
                            // Random coefficient for x^j is stored in random_data at position byte_idx*(t-1) + (j-1)
                            let coeff = FiniteField::new(random_data[byte_idx * (t - 1) + (j - 1)]);
                            acc = acc * x + coeff;
                        }

                        // Note: We skip j=0 because the constant term is always FiniteField(0)
                        // The final multiplication by x handles the last coefficient
                        acc = acc * x;

                        acc.0
                    })
                    .collect()
            })
            .collect();

        // Zeroize sensitive random coefficients before returning
        #[cfg(feature = "zeroize")]
        random_data.zeroize();

        Ok(delta_shares)
    }

    /// Refreshes existing shares by adding zero-polynomial deltas to invalidate old shares
    ///
    /// This method generates new shares that maintain the same secret but have different share data,
    /// effectively invalidating the old shares for security purposes. The refreshing process uses
    /// additive sharing of a zero-secret polynomial, ensuring that the underlying secret remains
    /// unchanged while the share values are completely refreshed.
    ///
    /// # Arguments
    /// * `shares` - Slice of existing shares to refresh (must have at least `threshold` shares)
    ///
    /// # Returns
    /// Vector of refreshed shares with the same indices and metadata but new share data
    ///
    /// # Security Purpose
    /// Share refreshing is a critical security operation that:
    /// - **Invalidates old shares**: Previous share values become useless after refreshing
    /// - **Maintains secret integrity**: The underlying secret remains exactly the same
    /// - **Prevents share accumulation**: Attackers cannot combine old and new shares
    /// - **Enables proactive security**: Regular refreshing limits exposure windows
    ///
    /// # Mechanism
    /// The refreshing process works by:
    /// 1. Generating a random polynomial with zero constant term (zero-secret)
    /// 2. Evaluating this polynomial at the same x-coordinates as the input shares
    /// 3. Adding (XOR) the resulting deltas to the original share data
    /// 4. Since the polynomial has zero secret, the refreshed shares reconstruct to the same value
    ///
    /// # Input Validation
    /// This method performs comprehensive validation:
    /// - Ensures the shares slice is not empty
    /// - Verifies sufficient shares (at least `threshold` shares required)
    /// - Checks that all shares have consistent data length
    /// - Validates that all shares have the same integrity check setting
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - No shares provided (empty slice)
    /// - Insufficient shares for the threshold requirement
    /// - Shares have inconsistent data lengths
    /// - Shares have different integrity check settings
    /// - Internal polynomial generation fails
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
    /// // Refresh the shares to invalidate old ones
    /// let refreshed_shares = scheme.refresh_shares(&original_shares[0..3]).unwrap();
    ///
    /// // Both sets reconstruct to the same secret
    /// let original_secret = ShamirShare::reconstruct(&original_shares[0..3]).unwrap();
    /// let refreshed_secret = ShamirShare::reconstruct(&refreshed_shares).unwrap();
    /// assert_eq!(original_secret, refreshed_secret);
    ///
    /// // But the share data is completely different
    /// assert_ne!(original_shares[0].data, refreshed_shares[0].data);
    /// ```
    ///
    /// # Performance
    /// - Time complexity: O(n * m * k) where n = number of shares, m = data length, k = threshold
    /// - Space complexity: O(n * m) for the output shares
    /// - Uses constant-time operations to prevent side-channel attacks
    pub fn refresh_shares(&mut self, shares: &[Share]) -> Result<Vec<Share>> {
        // Input validation: Check if shares slice is empty
        if shares.is_empty() {
            return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
        }

        // Input validation: Check if we have sufficient shares for the threshold
        if shares.len() < self.threshold as usize {
            return Err(ShamirError::InsufficientShares {
                needed: self.threshold,
                got: shares.len() as u8,
            });
        }

        // Extract reference values from the first share for consistency checking
        let data_length = shares[0].data.len();
        let integrity_check = shares[0].integrity_check;

        // Input validation: Check that all shares have consistent data length and integrity check setting
        if !shares
            .iter()
            .all(|s| s.data.len() == data_length && s.integrity_check == integrity_check)
        {
            return Err(ShamirError::InconsistentShareLength);
        }

        // Extract the indices from the input shares
        let indices: Vec<u8> = shares.iter().map(|s| s.index).collect();

        // Generate zero-polynomial deltas using the private helper
        let deltas = self.generate_zero_polynomial_shares(&indices, data_length)?;

        // Create refreshed shares by XORing original data with deltas
        let refreshed_shares: Vec<Share> = shares
            .iter()
            .zip(deltas.iter())
            .map(|(old_share, delta_data)| {
                // XOR the original share data with the delta to create new share data
                let new_data: Vec<u8> = old_share
                    .data
                    .iter()
                    .zip(delta_data.iter())
                    .map(|(&old_byte, &delta_byte)| old_byte ^ delta_byte)
                    .collect();

                // Create new share with refreshed data but same metadata
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
    /// This method uses constant-time polynomial evaluation with Horner's method to compute
    /// the share data. It automatically stops after 255 shares (GF(256) field limitation).
    ///
    /// # Returns
    /// - `Some(Share)` - The next share in the sequence
    /// - `None` - When all possible shares have been generated (x > 255)
    ///
    /// # Security
    /// - Constant-time polynomial evaluation using Horner's method
    /// - No data-dependent branching or memory access patterns
    fn next(&mut self) -> Option<Self::Item> {
        // Stop after 255 shares (GF(256) field limitation - x=0 is not used)
        if self.current_x == 0 {
            return None;
        }

        let x = FiniteField::new(self.current_x);
        let secret_len = self.data.len();
        let t = self.threshold as usize;

        // Evaluate polynomial for each byte at the current x-coordinate
        let share_data: Vec<u8> = (0..secret_len)
            .map(|byte_idx| {
                let mut acc = FiniteField::new(0);
                // Evaluate polynomial using Horner's method (iterating coefficients in reverse order)
                for j in (0..t).rev() {
                    let coeff = if j == 0 {
                        FiniteField::new(self.data[byte_idx])
                    } else {
                        // Random coefficient for x^j is stored in coefficients at position byte_idx*(t-1) + (j-1)
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

        // Increment x for next share, wrapping to 0 when we reach 256 (which stops iteration)
        self.current_x = self.current_x.wrapping_add(1);

        Some(share)
    }

    /// Returns the number of remaining shares that can be generated
    ///
    /// This provides a size hint for the iterator, which can be useful for
    /// pre-allocating collections or progress tracking.
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = if self.current_x == 0 {
            0
        } else {
            256 - self.current_x as usize
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

        // Split the secret
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly threshold shares
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);

        // Reconstruct with more than threshold shares
        let reconstructed = ShamirShare::reconstruct(&shares[1..5]).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_invalid_parameters() {
        assert!(ShamirShare::builder(0, 1).build().is_err());
        assert!(ShamirShare::builder(1, 0).build().is_err());
        assert!(ShamirShare::builder(3, 4).build().is_err());
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Test";
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
        let shares = shamir.split(secret).unwrap();

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
        corrupted_shares[1].index = corrupted_shares[0].index; // Duplicate index

        assert!(matches!(
            ShamirShare::reconstruct(&corrupted_shares),
            Err(ShamirError::InvalidShareFormat)
        ));
    }

    #[test]
    fn test_corrupted_share_data() {
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
        let mut shares = shamir.split(b"test").unwrap();

        // Corrupt one byte in a share
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
        // Test basic builder usage
        let shamir = ShamirShare::builder(5, 3).build().unwrap();
        assert_eq!(shamir.total_shares, 5);
        assert_eq!(shamir.threshold, 3);
        assert!(shamir.config.integrity_check); // Default should be true

        // Test builder with custom config
        let config = Config::new().with_integrity_check(false);
        let shamir = ShamirShare::builder(7, 4)
            .with_config(config)
            .build()
            .unwrap();
        assert_eq!(shamir.total_shares, 7);
        assert_eq!(shamir.threshold, 4);
        assert!(!shamir.config.integrity_check);
    }

    #[test]
    fn test_builder_validation() {
        // Test invalid parameters through builder
        assert!(ShamirShare::builder(0, 1).build().is_err());
        assert!(ShamirShare::builder(1, 0).build().is_err());
        assert!(ShamirShare::builder(3, 5).build().is_err());

        // Test invalid config
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

        // Verify shares have integrity_check = false
        assert!(!shares[0].integrity_check);

        // Reconstruct should work
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);

        // Data should be smaller since no hash is prepended
        let mut shamir_with_integrity = ShamirShare::builder(5, 3).build().unwrap();
        let shares_with_integrity = shamir_with_integrity.split(secret).unwrap();

        // Shares without integrity check should be smaller
        assert!(shares[0].data.len() < shares_with_integrity[0].data.len());
        assert_eq!(
            shares_with_integrity[0].data.len() - shares[0].data.len(),
            HASH_SIZE
        );
    }

    #[test]
    fn test_integrity_check_enabled() {
        let config = Config::new().with_integrity_check(true);
        let mut shamir = ShamirShare::builder(5, 3)
            .with_config(config)
            .build()
            .unwrap();

        let secret = b"test secret with integrity check";
        let shares = shamir.split(secret).unwrap();

        // Verify shares have integrity_check = true
        assert!(shares[0].integrity_check);

        // Reconstruct should work
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);

        // Corruption should be detected
        let mut corrupted_shares = shares[0..3].to_vec();
        if corrupted_shares[0].data[0] == 0 {
            corrupted_shares[0].data[0] = 1;
        } else {
            corrupted_shares[0].data[0] = 0;
        }

        assert!(matches!(
            ShamirShare::reconstruct(&corrupted_shares),
            Err(ShamirError::IntegrityCheckFailed)
        ));
    }

    #[test]
    fn test_mixed_integrity_check_shares() {
        // Create shares with integrity check enabled
        let config_with_integrity = Config::new().with_integrity_check(true);
        let mut shamir_with_integrity = ShamirShare::builder(5, 3)
            .with_config(config_with_integrity)
            .build()
            .unwrap();

        // Create shares with integrity check disabled
        let config_without_integrity = Config::new().with_integrity_check(false);
        let mut shamir_without_integrity = ShamirShare::builder(5, 3)
            .with_config(config_without_integrity)
            .build()
            .unwrap();

        let secret = b"test secret";
        let shares_with_integrity = shamir_with_integrity.split(secret).unwrap();
        let shares_without_integrity = shamir_without_integrity.split(secret).unwrap();

        // Mixing shares with different integrity check settings should fail
        let mixed_shares = vec![
            shares_with_integrity[0].clone(),
            shares_without_integrity[1].clone(),
            shares_with_integrity[2].clone(),
        ];

        assert!(matches!(
            ShamirShare::reconstruct(&mixed_shares),
            Err(ShamirError::InconsistentShareLength)
        ));
    }

    #[test]
    fn test_config_builder_methods() {
        use crate::config::SplitMode;

        let config = Config::new()
            .with_chunk_size(2048)
            .unwrap()
            .with_mode(SplitMode::Parallel)
            .with_compression(true)
            .with_integrity_check(false);

        let shamir = ShamirShare::builder(5, 3)
            .with_config(config.clone())
            .build()
            .unwrap();

        assert_eq!(shamir.config.chunk_size, 2048);
        assert_eq!(shamir.config.mode, SplitMode::Parallel);
        assert!(shamir.config.compression);
        assert!(!shamir.config.integrity_check);
    }

    #[test]
    fn test_split_stream_basic() {
        use std::io::Cursor;

        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
        let data = b"This is a test message for streaming functionality";
        let mut source = Cursor::new(data);

        // Create destination buffers
        let mut destinations = vec![Vec::new(); 3];
        let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();

        // Split the stream
        shamir.split_stream(&mut source, &mut dest_cursors).unwrap();

        // Extract the written data
        let share_data: Vec<Vec<u8>> = dest_cursors
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();

        // Verify that all shares have data
        for share in &share_data {
            assert!(!share.is_empty());
        }

        // Reconstruct using the first 2 shares (threshold = 2)
        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|data| Cursor::new(data.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();

        assert_eq!(&destination, data);
    }

    #[test]
    fn test_split_stream_with_custom_chunk_size() {
        use std::io::Cursor;

        let config = Config::new().with_chunk_size(10).unwrap(); // Small chunks for testing
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

        // Reconstruct
        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|data| Cursor::new(data.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();

        assert_eq!(&destination, data);
    }

    #[test]
    fn test_split_stream_without_integrity_check() {
        use std::io::Cursor;

        let config = Config::new()
            .with_integrity_check(false)
            .with_chunk_size(20)
            .unwrap();
        let mut shamir = ShamirShare::builder(3, 2)
            .with_config(config)
            .build()
            .unwrap();

        let data = b"Test message without integrity checking";
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

        // Reconstruct
        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|data| Cursor::new(data.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();

        assert_eq!(&destination, data);
    }

    #[test]
    fn test_split_stream_empty_data() {
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

        // All shares should contain only the header (2 bytes: flags + share index) for empty input
        for share in &share_data {
            assert_eq!(share.len(), 2); // Only header, no chunk data
        }

        // Reconstruct should also produce empty data
        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|data| Cursor::new(data.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();

        assert_eq!(&destination, data);
    }

    #[test]
    fn test_split_stream_wrong_destination_count() {
        use std::io::Cursor;

        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();
        let data = b"test";
        let mut source = Cursor::new(data);

        // Wrong number of destinations (2 instead of 3)
        let mut destinations = vec![Vec::new(); 2];
        let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();

        let result = shamir.split_stream(&mut source, &mut dest_cursors);
        assert!(matches!(result, Err(ShamirError::InvalidConfig(_))));
    }

    #[test]
    fn test_reconstruct_stream_insufficient_sources() {
        use std::io::Cursor;

        let mut sources: Vec<Cursor<Vec<u8>>> = vec![];
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        let result = ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor);
        assert!(matches!(
            result,
            Err(ShamirError::InsufficientShares { .. })
        ));
    }

    #[test]
    fn test_stream_data_format() {
        use std::io::Cursor;

        let config = Config::new().with_chunk_size(5).unwrap(); // Very small chunks
        let mut shamir = ShamirShare::builder(3, 2)
            .with_config(config)
            .build()
            .unwrap();

        let data = b"Hello World!"; // 12 bytes, will create 3 chunks (5, 5, 2)
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

        // Verify the data format: each share should have length prefixes after the header
        for share in &share_data {
            let mut cursor = Cursor::new(share);
            let mut total_chunks = 0;

            // Skip header (flags + share index)
            let mut header = [0u8; 2];
            cursor.read_exact(&mut header).unwrap();

            // Read chunks until EOF
            loop {
                let mut length_bytes = [0u8; 4];
                match cursor.read_exact(&mut length_bytes) {
                    Ok(()) => {
                        let length = u32::from_le_bytes(length_bytes) as usize;
                        let mut chunk_data = vec![0u8; length];
                        cursor.read_exact(&mut chunk_data).unwrap();
                        total_chunks += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => panic!("Unexpected error: {}", e),
                }
            }

            // Should have 3 chunks (5 + 5 + 2 bytes)
            assert_eq!(total_chunks, 3);
        }

        // Reconstruct and verify
        let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
            .iter()
            .map(|data| Cursor::new(data.clone()))
            .collect();
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();

        assert_eq!(&destination, data);
    }

    #[test]
    fn test_stream_integrity_check_detection() {
        use std::io::Cursor;

        // Test with integrity check enabled
        let config_with_integrity = Config::new()
            .with_integrity_check(true)
            .with_chunk_size(10)
            .unwrap();
        let mut shamir_with_integrity = ShamirShare::builder(3, 2)
            .with_config(config_with_integrity)
            .build()
            .unwrap();

        // Test with integrity check disabled
        let config_without_integrity = Config::new()
            .with_integrity_check(false)
            .with_chunk_size(10)
            .unwrap();
        let mut shamir_without_integrity = ShamirShare::builder(3, 2)
            .with_config(config_without_integrity)
            .build()
            .unwrap();

        let data = b"Test data for integrity checking";

        // Split with integrity check
        let mut source1 = Cursor::new(data);
        let mut destinations1 = vec![Vec::new(); 3];
        let mut dest_cursors1: Vec<Cursor<Vec<u8>>> = destinations1
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();
        shamir_with_integrity
            .split_stream(&mut source1, &mut dest_cursors1)
            .unwrap();
        let share_data_with_integrity: Vec<Vec<u8>> = dest_cursors1
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();

        // Split without integrity check
        let mut source2 = Cursor::new(data);
        let mut destinations2 = vec![Vec::new(); 3];
        let mut dest_cursors2: Vec<Cursor<Vec<u8>>> = destinations2
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();
        shamir_without_integrity
            .split_stream(&mut source2, &mut dest_cursors2)
            .unwrap();
        let share_data_without_integrity: Vec<Vec<u8>> = dest_cursors2
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();

        // Shares with integrity check should be larger
        assert!(share_data_with_integrity[0].len() > share_data_without_integrity[0].len());

        // Both should reconstruct correctly
        let mut sources1: Vec<Cursor<Vec<u8>>> = share_data_with_integrity[0..2]
            .iter()
            .map(|data| Cursor::new(data.clone()))
            .collect();
        let mut destination1 = Vec::new();
        let mut dest_cursor1 = Cursor::new(&mut destination1);
        ShamirShare::reconstruct_stream(&mut sources1, &mut dest_cursor1).unwrap();

        let mut sources2: Vec<Cursor<Vec<u8>>> = share_data_without_integrity[0..2]
            .iter()
            .map(|data| Cursor::new(data.clone()))
            .collect();
        let mut destination2 = Vec::new();
        let mut dest_cursor2 = Cursor::new(&mut destination2);
        ShamirShare::reconstruct_stream(&mut sources2, &mut dest_cursor2).unwrap();

        assert_eq!(&destination1, data);
        assert_eq!(&destination2, data);
    }

    #[test]
    fn test_stream_large_data() {
        use std::io::Cursor;

        let config = Config::new().with_chunk_size(1024).unwrap();
        let mut shamir = ShamirShare::builder(5, 3)
            .with_config(config)
            .build()
            .unwrap();

        // Create a large test dataset
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let mut source = Cursor::new(&data);

        let mut destinations = vec![Vec::new(); 5];
        let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();

        shamir.split_stream(&mut source, &mut dest_cursors).unwrap();

        let share_data: Vec<Vec<u8>> = dest_cursors
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();

        // Reconstruct using shares 0, 2, 4 (threshold = 3)
        let mut sources: Vec<Cursor<Vec<u8>>> = vec![
            Cursor::new(share_data[0].clone()),
            Cursor::new(share_data[2].clone()),
            Cursor::new(share_data[4].clone()),
        ];
        let mut destination = Vec::new();
        let mut dest_cursor = Cursor::new(&mut destination);

        ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();

        assert_eq!(&destination, &data);
    }

    #[test]
    fn test_dealer_basic_functionality() {
        let secret = b"Hello, Dealer!";
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

        // Generate shares using dealer
        let dealer_shares: Vec<Share> = shamir.dealer(secret).take(5).collect();
        assert_eq!(dealer_shares.len(), 5);

        // Verify share properties
        for (i, share) in dealer_shares.iter().enumerate() {
            assert_eq!(share.index, (i + 1) as u8);
            assert_eq!(share.threshold, 3);
            assert_eq!(share.total_shares, 5);
            assert!(share.integrity_check); // Default is true
        }

        // Reconstruct with threshold shares
        let reconstructed = ShamirShare::reconstruct(&dealer_shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);

        // Reconstruct with more than threshold shares
        let reconstructed = ShamirShare::reconstruct(&dealer_shares[1..5]).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_dealer_vs_split_equivalence() {
        let secret = b"Test equivalence between dealer and split";
        let mut shamir = ShamirShare::builder(7, 4).build().unwrap();

        // Generate shares using split
        let split_shares = shamir.split(secret).unwrap();

        // Generate shares using dealer
        let dealer_shares: Vec<Share> = shamir.dealer(secret).take(7).collect();

        // Both should produce the same number of shares
        assert_eq!(split_shares.len(), dealer_shares.len());

        // Both should be reconstructable
        let reconstructed_split = ShamirShare::reconstruct(&split_shares[0..4]).unwrap();
        let reconstructed_dealer = ShamirShare::reconstruct(&dealer_shares[0..4]).unwrap();

        assert_eq!(&reconstructed_split, secret);
        assert_eq!(&reconstructed_dealer, secret);
        assert_eq!(reconstructed_split, reconstructed_dealer);
    }

    #[test]
    fn test_dealer_lazy_evaluation() {
        let secret = b"Lazy evaluation test";
        let mut shamir = ShamirShare::builder(10, 5).build().unwrap();

        // Create dealer but don't consume all shares
        let mut dealer = shamir.dealer(secret);

        // Take only first 3 shares
        let first_three: Vec<Share> = dealer.by_ref().take(3).collect();
        assert_eq!(first_three.len(), 3);
        assert_eq!(first_three[0].index, 1);
        assert_eq!(first_three[1].index, 2);
        assert_eq!(first_three[2].index, 3);

        // Take next 2 shares from the same dealer
        let next_two: Vec<Share> = dealer.by_ref().take(2).collect();
        assert_eq!(next_two.len(), 2);
        assert_eq!(next_two[0].index, 4);
        assert_eq!(next_two[1].index, 5);

        // Combine shares and reconstruct
        let mut combined_shares = first_three;
        combined_shares.extend(next_two);

        let reconstructed = ShamirShare::reconstruct(&combined_shares).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_dealer_max_shares_limit() {
        let secret = b"Max shares test";
        let mut shamir = ShamirShare::builder(255, 128).build().unwrap();

        let dealer = shamir.dealer(secret);

        // Count all shares generated
        let all_shares: Vec<Share> = dealer.collect();
        assert_eq!(all_shares.len(), 255);

        // Verify indices are correct (1 to 255)
        for (i, share) in all_shares.iter().enumerate() {
            assert_eq!(share.index, (i + 1) as u8);
        }

        // Verify reconstruction works with threshold shares
        let reconstructed = ShamirShare::reconstruct(&all_shares[0..128]).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_dealer_stops_at_255() {
        let secret = b"Stop at 255 test";
        let mut shamir = ShamirShare::builder(255, 128).build().unwrap();

        let mut dealer = shamir.dealer(secret);

        // Consume all 255 shares
        let shares: Vec<Share> = dealer.by_ref().collect();
        assert_eq!(shares.len(), 255);

        // Dealer should be exhausted
        assert_eq!(dealer.next(), None);
        assert_eq!(dealer.next(), None); // Should remain None
    }

    #[test]
    fn test_dealer_size_hint() {
        let secret = b"Size hint test";
        let mut shamir = ShamirShare::builder(10, 5).build().unwrap();

        let mut dealer = shamir.dealer(secret);

        // Initial size hint should be 255 (max possible shares)
        assert_eq!(dealer.size_hint(), (255, Some(255)));
        assert_eq!(dealer.len(), 255);

        // Take one share
        let _share = dealer.next().unwrap();
        assert_eq!(dealer.size_hint(), (254, Some(254)));
        assert_eq!(dealer.len(), 254);

        // Take several more
        let _shares: Vec<_> = dealer.by_ref().take(10).collect();
        assert_eq!(dealer.size_hint(), (244, Some(244)));
        assert_eq!(dealer.len(), 244);
    }

    #[test]
    fn test_dealer_with_integrity_check_disabled() {
        let config = Config::new().with_integrity_check(false);
        let mut shamir = ShamirShare::builder(5, 3)
            .with_config(config)
            .build()
            .unwrap();

        let secret = b"No integrity check";

        // Generate shares using dealer
        let dealer_shares: Vec<Share> = shamir.dealer(secret).take(5).collect();

        // Verify integrity_check is false
        for share in &dealer_shares {
            assert!(!share.integrity_check);
        }

        // Should still reconstruct correctly
        let reconstructed = ShamirShare::reconstruct(&dealer_shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);

        // Compare with split method
        let split_shares = shamir.split(secret).unwrap();
        let reconstructed_split = ShamirShare::reconstruct(&split_shares[0..3]).unwrap();
        assert_eq!(reconstructed, reconstructed_split);
    }

    #[test]
    fn test_dealer_empty_secret() {
        let secret = b"";
        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();

        let dealer_shares: Vec<Share> = shamir.dealer(secret).take(3).collect();
        assert_eq!(dealer_shares.len(), 3);

        let reconstructed = ShamirShare::reconstruct(&dealer_shares[0..2]).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_dealer_single_byte_secret() {
        let secret = b"x";
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

        let dealer_shares: Vec<Share> = shamir.dealer(secret).take(5).collect();
        assert_eq!(dealer_shares.len(), 5);

        let reconstructed = ShamirShare::reconstruct(&dealer_shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    fn test_dealer_different_share_combinations() {
        let secret = b"Different dealer combinations test";
        let mut shamir = ShamirShare::builder(7, 4).build().unwrap();

        let dealer_shares: Vec<Share> = shamir.dealer(secret).take(7).collect();

        // Try different combinations of 4 shares
        let combinations = vec![
            vec![0, 1, 2, 3],
            vec![1, 2, 3, 4],
            vec![2, 3, 4, 5],
            vec![0, 2, 4, 6],
            vec![1, 3, 5, 6],
        ];

        for combo in combinations {
            let selected_shares: Vec<Share> =
                combo.iter().map(|&i| dealer_shares[i].clone()).collect();
            let reconstructed = ShamirShare::reconstruct(&selected_shares).unwrap();
            assert_eq!(&reconstructed, secret);
        }
    }

    #[test]
    fn test_dealer_iterator_chain() {
        let secret = b"Iterator chain test";
        let mut shamir = ShamirShare::builder(10, 5).build().unwrap();

        // Use iterator methods to filter and collect shares
        let even_indexed_shares: Vec<Share> = shamir
            .dealer(secret)
            .filter(|share| share.index % 2 == 0)
            .take(5)
            .collect();

        assert_eq!(even_indexed_shares.len(), 5);
        for share in &even_indexed_shares {
            assert_eq!(share.index % 2, 0);
        }

        // Should still be able to reconstruct
        let reconstructed = ShamirShare::reconstruct(&even_indexed_shares).unwrap();
        assert_eq!(&reconstructed, secret);
    }

    #[test]
    #[cfg(feature = "zeroize")]
    fn test_zeroize_feature_compilation() {
        // This test ensures that the zeroize feature compiles correctly
        // and that the derives are applied properly

        let secret = b"test secret for zeroize";
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

        // Test that Share struct has Zeroize and ZeroizeOnDrop derives
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        // Test that Dealer struct has Zeroize and ZeroizeOnDrop derives
        let dealer_shares: Vec<Share> = shamir.dealer(secret).take(3).collect();
        assert_eq!(dealer_shares.len(), 3);

        // Test reconstruction still works
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);

        // Test that FiniteField has Zeroize derive
        let mut field = crate::FiniteField::new(42);
        field.zeroize();
        assert_eq!(field.0, 0);
    }

    #[test]
    #[cfg(feature = "zeroize")]
    fn test_share_zeroize_on_drop() {
        use zeroize::Zeroize;

        let secret = b"test secret for drop";
        let mut shamir = ShamirShare::builder(3, 2).build().unwrap();

        // Create a share in a limited scope
        let share_data = {
            let shares = shamir.split(secret).unwrap();
            shares[0].data.clone()
        }; // Share is dropped here, should be zeroized automatically

        // Verify we can still use the cloned data
        assert!(!share_data.is_empty());

        // Test manual zeroization
        let mut shares = shamir.split(secret).unwrap();
        let original_data = shares[0].data.clone();
        shares[0].zeroize();

        // After zeroization, the share data should be zeroed
        assert!(shares[0].data.iter().all(|&b| b == 0));
        assert_ne!(original_data, shares[0].data);
    }
}
