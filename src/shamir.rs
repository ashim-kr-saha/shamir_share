use crate::error::{Result, ShamirError};
use crate::finite_field::FiniteField;
use rand::rngs::OsRng;
use rand_chacha::rand_core::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rayon::iter::ParallelIterator;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

const HASH_SIZE: usize = 32; // SHA-256 output size

/// A share in Shamir's Secret Sharing scheme
///
/// # Example
/// ```
/// use shamir_share::{Share, ShamirShare};
///
/// let mut shamir = ShamirShare::new(5, 3).unwrap();
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
}

/// Main implementation of Shamir's Secret Sharing scheme
///
/// Uses GF(256) arithmetic for polynomial operations and
/// ChaCha20 CSPRNG for generating polynomial coefficients
///
/// # Example
/// ```
/// use shamir_share::ShamirShare;
///
/// // Create a scheme with 5 total shares and threshold of 3
/// let mut scheme = ShamirShare::new(5, 3).unwrap();
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
    /// Cryptographically secure random number generator
    rng: ChaCha20Rng,
}

impl ShamirShare {
    /// Creates a new ShamirShare instance with specified parameters
    ///
    /// # Arguments
    /// * `total_shares` - Total number of shares to create (1-255)
    /// * `threshold` - Minimum shares required for reconstruction (1-total_shares)
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - `total_shares` is 0
    /// - `threshold` is 0
    /// - `threshold` > `total_shares`
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    ///
    /// let valid = ShamirShare::new(5, 3);
    /// assert!(valid.is_ok());
    ///
    /// let invalid = ShamirShare::new(3, 5);
    /// assert!(invalid.is_err());
    /// ```
    pub fn new(total_shares: u8, threshold: u8) -> Result<Self> {
        if total_shares == 0 {
            return Err(ShamirError::InvalidShareCount(total_shares));
        }
        if threshold == 0 {
            return Err(ShamirError::InvalidThreshold(threshold));
        }
        if threshold > total_shares {
            return Err(ShamirError::ThresholdTooLarge {
                threshold,
                total_shares,
            });
        }

        Ok(Self {
            total_shares,
            threshold,
            rng: ChaCha20Rng::try_from_rng(&mut OsRng).unwrap(),
        })
    }

    /// Splits a secret into multiple shares using polynomial interpolation
    ///
    /// # Arguments
    /// * `secret` - Byte slice to protect
    ///
    /// # Returns
    /// Vector of [`Share`] objects containing the split data
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    ///
    /// let mut scheme = ShamirShare::new(5, 3).unwrap();
    /// let shares = scheme.split(b"secret data").unwrap();
    /// assert_eq!(shares.len(), 5);
    /// ```
    pub fn split(&mut self, secret: &[u8]) -> Result<Vec<Share>> {
        // 1. Calculate hash of the secret
        let hash = Sha256::digest(secret);

        // 2. Prepend hash to the secret
        let mut data_to_split = Vec::with_capacity(HASH_SIZE + secret.len());
        data_to_split.extend_from_slice(&hash);
        data_to_split.extend_from_slice(secret);

        let secret_len = data_to_split.len();
        let t = self.threshold as usize;
        // Bulk generate random coefficients for all secret bytes (for coefficients 1..t)
        let mut random_data = vec![0u8; secret_len * (t - 1)];
        self.rng.fill_bytes(&mut random_data);

        // Precompute x values for each share
        let x_values: Vec<FiniteField> = (1..=self.total_shares).map(FiniteField::new).collect();

        // Evaluate the polynomial for each share in parallel. For each secret byte at index idx, the polynomial is
        // P(x) = secret[idx] + random_coef1 * x + random_coef2 * x^2 + ... + random_coef_{t-1} * x^(t-1).
        let shares: Vec<Share> = x_values
            .into_par_iter()
            .enumerate()
            .map(|(i, x)| {
                let data: Vec<u8> = (0..secret_len)
                    .map(|idx| {
                        let mut acc = FiniteField::new(0);
                        // Evaluate polynomial using Horner's method (iterating coefficients in reverse order)
                        for j in (0..t).rev() {
                            let coeff = if j == 0 {
                                FiniteField::new(data_to_split[idx])
                            } else {
                                // Random coefficient for x^j is stored in random_data at position idx*(t-1) + (j-1)
                                FiniteField::new(random_data[idx * (t - 1) + (j - 1)])
                            };
                            acc = acc * x + coeff;
                        }
                        acc.0
                    })
                    .collect();
                Share {
                    index: (i + 1) as u8,
                    data,
                    threshold: self.threshold,
                    total_shares: self.total_shares,
                }
            })
            .collect();

        Ok(shares)
    }

    /// Reconstructs the original secret from shares using Lagrange interpolation
    ///
    /// # Arguments
    /// * `shares` - Slice of shares to use for reconstruction
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - No shares provided
    /// - Insufficient shares for threshold
    /// - Shares have inconsistent lengths
    /// - Invalid share data
    ///
    /// # Example
    /// ```
    /// use shamir_share::ShamirShare;
    ///
    /// let mut scheme = ShamirShare::new(5, 3).unwrap();
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

        let secret_len = shares[0].data.len();
        if !shares.iter().all(|s| s.data.len() == secret_len) {
            return Err(ShamirError::InconsistentShareLength);
        }

        // Optimized computation of Lagrange coefficients
        let xs: Vec<FiniteField> = shares
            .iter()
            .map(|share| FiniteField::new(share.index))
            .collect();
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
        let lagrange_coefficients = lagrange_coefficients?;

        // Parallelize across bytes
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

        // 3. Split the reconstructed data into hash and secret
        if reconstructed_data.len() < HASH_SIZE {
            return Err(ShamirError::IntegrityCheckFailed);
        }
        let (reconstructed_hash, secret) = reconstructed_data.split_at(HASH_SIZE);

        // 4. Verify the integrity of the secret using constant-time comparison
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct() {
        let secret = b"Hello, World!";
        let mut shamir = ShamirShare::new(5, 3).unwrap();

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
        assert!(ShamirShare::new(0, 1).is_err());
        assert!(ShamirShare::new(1, 0).is_err());
        assert!(ShamirShare::new(3, 4).is_err());
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Test";
        let mut shamir = ShamirShare::new(5, 3).unwrap();
        let shares = shamir.split(secret).unwrap();

        assert!(ShamirShare::reconstruct(&shares[0..2]).is_err());
    }

    #[test]
    fn test_different_share_combinations() {
        let secret = b"Different combinations test";
        let mut shamir = ShamirShare::new(5, 3).unwrap();
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
        let mut shamir = ShamirShare::new(5, 3).unwrap();
        let shares = shamir.split(secret).unwrap();
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = b"x";
        let mut shamir = ShamirShare::new(5, 3).unwrap();
        let shares = shamir.split(secret).unwrap();
        let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_max_shares() {
        let secret = b"Maximum shares test";
        let mut shamir = ShamirShare::new(255, 128).unwrap();
        let shares = shamir.split(secret).unwrap();
        assert_eq!(shares.len(), 255);

        let reconstructed = ShamirShare::reconstruct(&shares[0..128]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_duplicate_share_indices() {
        let mut shamir = ShamirShare::new(5, 3).unwrap();
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
        let mut shamir = ShamirShare::new(5, 3).unwrap();
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
}
