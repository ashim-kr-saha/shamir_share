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
#[derive(Debug, Clone)]
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
        // Prepare data to split based on integrity check configuration
        let data_to_split = if self.config.integrity_check {
            // Calculate hash of the secret and prepend it
            let hash = Sha256::digest(secret);
            let mut data = Vec::with_capacity(HASH_SIZE + secret.len());
            data.extend_from_slice(&hash);
            data.extend_from_slice(secret);
            data
        } else {
            // Use secret data directly without integrity hash
            secret.to_vec()
        };

        // Use the unified split_chunk method for the core splitting logic
        let share_data = self.split_chunk(&data_to_split)?;

        // Create Share objects with metadata
        let shares: Vec<Share> = share_data
            .into_iter()
            .enumerate()
            .map(|(i, data)| Share {
                index: (i + 1) as u8,
                data,
                threshold: self.threshold,
                total_shares: self.total_shares,
                integrity_check: self.config.integrity_check,
            })
            .collect();

        Ok(shares)
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

        // Ensure all shares have consistent properties
        if !shares
            .iter()
            .all(|s| s.data.len() == shares[0].data.len() && s.integrity_check == integrity_check)
        {
            return Err(ShamirError::InconsistentShareLength);
        }

        // Use the unified reconstruct_chunk method for the core reconstruction logic
        let reconstructed_data = Self::reconstruct_chunk(shares)?;

        // Handle integrity checking based on share configuration
        if integrity_check {
            // Shares were created with integrity checking - verify hash
            if reconstructed_data.len() < HASH_SIZE {
                return Err(ShamirError::IntegrityCheckFailed);
            }
            let (reconstructed_hash, secret) = reconstructed_data.split_at(HASH_SIZE);

            // Verify the integrity of the secret using constant-time comparison
            let calculated_hash = Sha256::digest(secret);
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

            Ok(secret.to_vec())
        } else {
            // Shares were created without integrity checking - return data directly
            Ok(reconstructed_data)
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

        // Write integrity check flag and share index to all destinations as a header
        let integrity_flag = if self.config.integrity_check {
            1u8
        } else {
            0u8
        };
        for (i, dest) in destinations.iter_mut().enumerate() {
            dest.write_all(&[integrity_flag])
                .map_err(ShamirError::IoError)?;
            dest.write_all(&[(i + 1) as u8]) // Share index (1-based)
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
                // Calculate hash of the chunk and prepend it for integrity verification
                let hash = Sha256::digest(chunk);
                chunk_with_hash_buffer.extend_from_slice(&hash);
                chunk_with_hash_buffer.extend_from_slice(chunk);
            } else {
                // Use chunk data directly without integrity hash
                chunk_with_hash_buffer.extend_from_slice(chunk);
            };

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
        let mut integrity_flag = [0u8; 1];
        sources[0]
            .read_exact(&mut integrity_flag)
            .map_err(ShamirError::IoError)?;
        let integrity_check = integrity_flag[0] != 0;

        let mut share_indices = Vec::with_capacity(sources.len());

        // Read share index from first source
        let mut share_index = [0u8; 1];
        sources[0]
            .read_exact(&mut share_index)
            .map_err(ShamirError::IoError)?;
        share_indices.push(share_index[0]);

        // Read integrity flags and share indices from other sources
        for source in sources.iter_mut().skip(1) {
            let mut flag = [0u8; 1];
            source.read_exact(&mut flag).map_err(ShamirError::IoError)?;
            if flag[0] != integrity_flag[0] {
                return Err(ShamirError::InvalidConfig(
                    "Inconsistent integrity check flags across sources".to_string(),
                ));
            }

            let mut index = [0u8; 1];
            source
                .read_exact(&mut index)
                .map_err(ShamirError::IoError)?;
            share_indices.push(index[0]);
        }

        // Pre-allocate buffers to reuse across chunks to avoid allocations in hot loop
        let mut chunk_lengths_buffer = Vec::with_capacity(sources.len());
        let mut share_chunk_data_buffers: Vec<Vec<u8>> =
            (0..sources.len()).map(|_| Vec::new()).collect();
        let mut temp_shares_for_reconstruction: Vec<Share> = Vec::with_capacity(sources.len());
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

            // Create temporary Share objects for reconstruction
            // Reuse buffer to avoid allocations in the hot loop
            temp_shares_for_reconstruction.clear();
            let threshold = sources.len() as u8;
            let total_shares = sources.len() as u8;

            for (i, share_chunk_data) in share_chunk_data_buffers.iter().enumerate() {
                temp_shares_for_reconstruction.push(Share {
                    index: share_indices[i],        // Use the actual share index from the stream
                    data: share_chunk_data.clone(), // Unfortunately we need to clone here for the Share struct
                    threshold,
                    total_shares,
                    integrity_check,
                });
            }

            // Reconstruct the chunk using optimized reconstruction with buffer reuse
            let reconstructed_chunk = Self::reconstruct_chunk_optimized(
                &temp_shares_for_reconstruction,
                &mut reconstructed_chunk_buffer,
            )?;

            // Handle integrity checking based on the flag we read
            if integrity_check {
                // Integrity checking was used - verify hash and extract data
                if reconstructed_chunk.len() < HASH_SIZE {
                    return Err(ShamirError::IntegrityCheckFailed);
                }
                let (reconstructed_hash, data) = reconstructed_chunk.split_at(HASH_SIZE);

                // Verify the integrity of the data using constant-time comparison
                let calculated_hash = Sha256::digest(data);
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
                destination.write_all(data).map_err(ShamirError::IoError)?;
            } else {
                // No integrity checking - write data directly
                destination
                    .write_all(reconstructed_chunk)
                    .map_err(ShamirError::IoError)?;
            };
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

    /// Optimized helper method to reconstruct a single chunk from shares with buffer reuse
    ///
    /// This version reuses a provided buffer to avoid allocations in hot paths.
    /// Used internally by `reconstruct_stream` for performance optimization.
    /// Shares the same core logic as `reconstruct_chunk` but optimizes for memory allocation.
    ///
    /// # Arguments
    /// * `shares` - Slice of shares to use for reconstruction
    /// * `output_buffer` - Reusable buffer for the reconstructed data
    ///
    /// # Returns
    /// Slice reference to the reconstructed data in the output buffer
    #[inline]
    fn reconstruct_chunk_optimized<'a>(
        shares: &[Share],
        output_buffer: &'a mut Vec<u8>,
    ) -> Result<&'a [u8]> {
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

        // Reuse output buffer to avoid allocations in the hot loop
        output_buffer.clear();
        output_buffer.reserve(secret_len);

        // Reconstruct each byte directly into the output buffer
        for byte_idx in 0..secret_len {
            let reconstructed_byte = shares
                .iter()
                .zip(&lagrange_coefficients)
                .fold(FiniteField::new(0), |acc, (share, &coeff)| {
                    acc + coeff * FiniteField::new(share.data[byte_idx])
                })
                .0;
            output_buffer.push(reconstructed_byte);
        }

        Ok(output_buffer)
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

        // All shares should contain only the header (2 bytes: integrity flag + share index) for empty input
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

            // Skip header (integrity flag + share index)
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
}
