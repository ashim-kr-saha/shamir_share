//! Hierarchical Secret Sharing Scheme (HSSS) implementation
//!
//! This module provides a hierarchical approach to Shamir's Secret Sharing where different
//! participants can be assigned different numbers of shares based on their access level or role.
//! The core concept uses a single "master" scheme with a threshold and distributes varying
//! numbers of shares to participants based on their hierarchical level.
//!
//! # Concept
//!
//! The HSSS implementation uses a single, powerful "master" scheme (k_master, n_master) and
//! distributes different numbers of shares to participants based on their role. For example,
//! with a master scheme of (k=5, n=50):
//! - A President might get 5 shares (and can reconstruct alone)
//! - A VP might get 3 shares
//! - An Executive might get 2 shares
//!
//! A combination like a VP (3 shares) and an Executive (2 shares) would meet the threshold of 5.
//!
//! # Example
//! ```
//! use shamir_share::hsss::{Hsss, AccessLevel, HierarchicalShare};
//!
//! // Create an HSSS scheme with master threshold of 5
//! let hsss = Hsss::builder(5)
//!     .add_level("President", 5)
//!     .add_level("VP", 3)
//!     .add_level("Executive", 2)
//!     .build()
//!     .unwrap();
//! ```

use crate::error::{Result, ShamirError};
use crate::shamir::{ShamirShare, Share};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Represents an access level in the hierarchical secret sharing scheme
///
/// An access level defines a role or position in the hierarchy and specifies
/// how many shares participants at that level should receive. This allows
/// for flexible access control where higher-level participants receive more
/// shares and can potentially reconstruct the secret with fewer collaborators.
///
/// # Example
/// ```
/// use shamir_share::hsss::AccessLevel;
///
/// let president_level = AccessLevel {
///     name: "President".to_string(),
///     shares_count: 5,
/// };
///
/// let vp_level = AccessLevel {
///     name: "VP".to_string(),
///     shares_count: 3,
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct AccessLevel {
    /// Human-readable name for this access level (e.g., "President", "VP", "Executive")
    pub name: String,
    /// Number of shares that participants at this level should receive
    pub shares_count: u8,
}

/// Represents the actual shares assigned to a participant in the hierarchical scheme
///
/// This struct contains the access level name and the actual cryptographic shares
/// that were generated for a participant at that level. The number of shares
/// should match the `shares_count` specified in the corresponding `AccessLevel`.
///
/// # Example
/// ```
/// use shamir_share::hsss::HierarchicalShare;
/// use shamir_share::Share;
///
/// // This would typically be created by the HSSS system
/// let hierarchical_share = HierarchicalShare {
///     level_name: "President".to_string(),
///     shares: vec![], // Would contain actual Share objects
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct HierarchicalShare {
    /// Name of the access level this share set belongs to
    pub level_name: String,
    /// The actual cryptographic shares for this participant
    pub shares: Vec<Share>,
}

/// Main Hierarchical Secret Sharing Scheme implementation
///
/// The `Hsss` struct represents a configured hierarchical secret sharing scheme
/// that can split secrets according to the defined access levels. It maintains
/// the underlying Shamir scheme and the hierarchy definition.
///
/// # Security
///
/// The HSSS inherits all security properties from the underlying Shamir's Secret
/// Sharing implementation, including:
/// - Constant-time operations to prevent side-channel attacks
/// - Cryptographically secure random number generation
/// - Integrity verification capabilities
///
/// # Example
/// ```
/// use shamir_share::hsss::Hsss;
///
/// let hsss = Hsss::builder(5)
///     .add_level("President", 5)
///     .add_level("VP", 3)
///     .add_level("Executive", 2)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct Hsss {
    /// The underlying Shamir's Secret Sharing scheme
    master_scheme: ShamirShare,
    /// Defined access levels in the hierarchy
    levels: Vec<AccessLevel>,
}

/// Builder for creating HSSS instances with hierarchical access levels
///
/// The `HsssBuilder` provides a fluent interface for defining the hierarchical
/// structure of the secret sharing scheme. It automatically calculates the
/// total number of shares needed based on the defined access levels.
///
/// # Example
/// ```
/// use shamir_share::hsss::Hsss;
///
/// let hsss = Hsss::builder(5)  // Master threshold of 5
///     .add_level("President", 5)    // President gets 5 shares
///     .add_level("VP", 3)           // VP gets 3 shares  
///     .add_level("Executive", 2)    // Executive gets 2 shares
///     .build()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct HsssBuilder {
    /// The master threshold for reconstruction
    master_threshold: u8,
    /// Access levels being defined
    levels: Vec<AccessLevel>,
}

impl HsssBuilder {
    /// Creates a new HSSS builder with the specified master threshold
    ///
    /// The master threshold determines how many shares are needed to reconstruct
    /// the secret. Participants can combine their shares to meet this threshold.
    ///
    /// # Arguments
    /// * `master_threshold` - Minimum number of shares required for reconstruction (1-255)
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let builder = Hsss::builder(5);
    /// ```
    pub fn new(master_threshold: u8) -> Self {
        Self {
            master_threshold,
            levels: Vec::new(),
        }
    }

    /// Adds a new access level to the hierarchical scheme
    ///
    /// This method defines a new role or level in the hierarchy and specifies
    /// how many shares participants at that level should receive. Access levels
    /// can be added in any order.
    ///
    /// # Arguments
    /// * `name` - Human-readable name for the access level
    /// * `shares_count` - Number of shares for participants at this level (1-255)
    ///
    /// # Returns
    /// The builder instance for method chaining
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let hsss = Hsss::builder(5)
    ///     .add_level("President", 5)
    ///     .add_level("VP", 3)
    ///     .add_level("Manager", 2)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn add_level(mut self, name: &str, shares_count: u8) -> Self {
        self.levels.push(AccessLevel {
            name: name.to_string(),
            shares_count,
        });
        self
    }

    /// Builds the HSSS instance with validation
    ///
    /// This method validates the configuration and creates the underlying
    /// Shamir's Secret Sharing scheme. It calculates the total number of
    /// shares needed (n_master) by summing the shares_count of all levels.
    ///
    /// # Returns
    /// A configured `Hsss` instance ready for use
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - `master_threshold` is 0
    /// - No access levels have been defined
    /// - Total shares count is 0 or exceeds 255
    /// - `master_threshold` exceeds the total shares count
    /// - Any individual `shares_count` is 0
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let result = Hsss::builder(5)
    ///     .add_level("President", 5)
    ///     .add_level("VP", 3)
    ///     .build();
    ///
    /// assert!(result.is_ok());
    /// ```
    pub fn build(self) -> Result<Hsss> {
        // Validate master threshold
        if self.master_threshold == 0 {
            return Err(ShamirError::InvalidThreshold(self.master_threshold));
        }

        // Validate that at least one level is defined
        if self.levels.is_empty() {
            return Err(ShamirError::InvalidConfig(
                "At least one access level must be defined".to_string(),
            ));
        }

        // Validate that all levels have non-zero share counts
        for level in &self.levels {
            if level.shares_count == 0 {
                return Err(ShamirError::InvalidShareCount(level.shares_count));
            }
        }

        // Calculate total number of shares needed (n_master)
        let total_shares: u32 = self.levels.iter().map(|level| level.shares_count as u32).sum();

        // Validate total shares count
        if total_shares == 0 {
            return Err(ShamirError::InvalidShareCount(0));
        }
        if total_shares > 255 {
            return Err(ShamirError::InvalidConfig(format!(
                "Total shares count {} exceeds maximum of 255",
                total_shares
            )));
        }

        let n_master = total_shares as u8;

        // Validate that master threshold doesn't exceed total shares
        if self.master_threshold > n_master {
            return Err(ShamirError::ThresholdTooLarge {
                threshold: self.master_threshold,
                total_shares: n_master,
            });
        }

        // Create the underlying Shamir scheme
        let master_scheme = ShamirShare::builder(n_master, self.master_threshold).build()?;

        Ok(Hsss {
            master_scheme,
            levels: self.levels,
        })
    }
}

impl Hsss {
    /// Creates a builder for configuring an HSSS instance
    ///
    /// This is the recommended way to create HSSS instances as it provides
    /// a fluent interface for defining the hierarchical structure.
    ///
    /// # Arguments
    /// * `master_threshold` - Minimum number of shares required for reconstruction (1-255)
    ///
    /// # Returns
    /// An `HsssBuilder` instance for configuring the hierarchy
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let hsss = Hsss::builder(5)
    ///     .add_level("President", 5)
    ///     .add_level("VP", 3)
    ///     .add_level("Executive", 2)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder(master_threshold: u8) -> HsssBuilder {
        HsssBuilder::new(master_threshold)
    }

    /// Returns a reference to the defined access levels
    ///
    /// This method provides read-only access to the hierarchy definition,
    /// allowing inspection of the configured access levels and their
    /// associated share counts.
    ///
    /// # Returns
    /// A slice containing all defined access levels
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let hsss = Hsss::builder(5)
    ///     .add_level("President", 5)
    ///     .add_level("VP", 3)
    ///     .build()
    ///     .unwrap();
    ///
    /// let levels = hsss.levels();
    /// assert_eq!(levels.len(), 2);
    /// assert_eq!(levels[0].name, "President");
    /// assert_eq!(levels[0].shares_count, 5);
    /// ```
    pub fn levels(&self) -> &[AccessLevel] {
        &self.levels
    }

    /// Returns the master threshold for this HSSS scheme
    ///
    /// The master threshold is the minimum number of shares required to
    /// reconstruct the secret, regardless of how they are distributed
    /// among participants.
    ///
    /// # Returns
    /// The master threshold value
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let hsss = Hsss::builder(5)
    ///     .add_level("President", 5)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(hsss.master_threshold(), 5);
    /// ```
    pub fn master_threshold(&self) -> u8 {
        self.master_scheme.threshold()
    }

    /// Returns the total number of shares in the master scheme
    ///
    /// This is the sum of all shares_count values across all defined
    /// access levels, representing the total number of shares that
    /// will be generated.
    ///
    /// # Returns
    /// The total number of shares (n_master)
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let hsss = Hsss::builder(5)
    ///     .add_level("President", 5)
    ///     .add_level("VP", 3)
    ///     .add_level("Executive", 2)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(hsss.total_shares(), 10); // 5 + 3 + 2
    /// ```
    pub fn total_shares(&self) -> u8 {
        self.master_scheme.total_shares()
    }

    /// Splits a secret into hierarchical shares according to the defined access levels
    ///
    /// This method uses the underlying master Shamir scheme to generate a pool of shares
    /// and then distributes them to the different hierarchical levels according to their
    /// configured share counts. Each level receives the specified number of shares.
    ///
    /// # Arguments
    /// * `secret` - The secret data to be split and distributed
    ///
    /// # Returns
    /// A vector of `HierarchicalShare` instances, one for each defined access level.
    /// Each `HierarchicalShare` contains the level name and the shares allocated to that level.
    ///
    /// # Process
    /// 1. Creates a dealer iterator from the master Shamir scheme
    /// 2. For each access level in order:
    ///    - Takes the required number of shares from the dealer
    ///    - Creates a `HierarchicalShare` with the level name and collected shares
    /// 3. Returns all hierarchical shares
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - The dealer runs out of shares before all levels are satisfied (logic bug in builder)
    /// - The underlying Shamir scheme encounters an error
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let mut hsss = Hsss::builder(5)
    ///     .add_level("President", 5)
    ///     .add_level("VP", 3)
    ///     .add_level("Executive", 2)
    ///     .build()
    ///     .unwrap();
    ///
    /// let secret = b"top secret data";
    /// let hierarchical_shares = hsss.split_secret(secret).unwrap();
    ///
    /// assert_eq!(hierarchical_shares.len(), 3);
    /// assert_eq!(hierarchical_shares[0].level_name, "President");
    /// assert_eq!(hierarchical_shares[0].shares.len(), 5);
    /// assert_eq!(hierarchical_shares[1].level_name, "VP");
    /// assert_eq!(hierarchical_shares[1].shares.len(), 3);
    /// assert_eq!(hierarchical_shares[2].level_name, "Executive");
    /// assert_eq!(hierarchical_shares[2].shares.len(), 2);
    /// ```
    ///
    /// # Security
    /// - Inherits all security properties from the underlying Shamir scheme
    /// - Uses cryptographically secure random number generation
    /// - Constant-time operations prevent side-channel attacks
    /// - Each share reveals no information about the secret without meeting the threshold
    pub fn split_secret(&mut self, secret: &[u8]) -> Result<Vec<HierarchicalShare>> {
        // Create a dealer iterator from the master scheme
        let mut dealer = self.master_scheme.dealer(secret);
        
        // Initialize the result vector
        let mut hierarchical_shares = Vec::with_capacity(self.levels.len());
        
        // Iterate through each access level and allocate shares
        for level in &self.levels {
            // Take the required number of shares for this level
            let shares: Vec<Share> = dealer.by_ref().take(level.shares_count as usize).collect();
            
            // Verify we got the expected number of shares
            if shares.len() != level.shares_count as usize {
                return Err(ShamirError::InvalidConfig(format!(
                    "Insufficient shares available for level '{}': expected {}, got {}",
                    level.name, level.shares_count, shares.len()
                )));
            }
            
            // Create the hierarchical share for this level
            let hierarchical_share = HierarchicalShare {
                level_name: level.name.clone(),
                shares,
            };
            
            hierarchical_shares.push(hierarchical_share);
        }
        
        Ok(hierarchical_shares)
    }

    /// Reconstructs the original secret from hierarchical shares
    ///
    /// This method provides a convenient way to reconstruct the secret from one or more
    /// `HierarchicalShare` instances. It flattens all the individual shares from the
    /// hierarchical shares and uses the standard Shamir reconstruction algorithm.
    ///
    /// # Arguments
    /// * `hierarchical_shares` - Slice of hierarchical shares to use for reconstruction
    ///
    /// # Returns
    /// The original secret data if reconstruction succeeds
    ///
    /// # Process
    /// 1. Flattens all `Share` objects from all provided `HierarchicalShare` instances
    /// 2. Calls the standard `ShamirShare::reconstruct()` method on the flattened shares
    /// 3. Returns the reconstructed secret
    ///
    /// # Threshold Requirements
    /// The total number of individual shares across all provided hierarchical shares
    /// must meet or exceed the master threshold. For example, with a master threshold of 5:
    /// - A President with 5 shares can reconstruct alone
    /// - A VP (3 shares) + Executive (2 shares) can reconstruct together
    /// - Any combination totaling 5 or more shares can reconstruct
    ///
    /// # Errors
    /// Returns `ShamirError` if:
    /// - No hierarchical shares provided
    /// - Insufficient total shares to meet the master threshold
    /// - Shares have inconsistent properties (length, integrity settings, etc.)
    /// - Integrity check fails (if enabled)
    /// - Invalid share data or corruption detected
    ///
    /// # Example
    /// ```
    /// use shamir_share::hsss::Hsss;
    ///
    /// let mut hsss = Hsss::builder(5)
    ///     .add_level("President", 5)
    ///     .add_level("VP", 3)
    ///     .add_level("Executive", 2)
    ///     .build()
    ///     .unwrap();
    ///
    /// let secret = b"confidential information";
    /// let hierarchical_shares = hsss.split_secret(secret).unwrap();
    ///
    /// // President can reconstruct alone (5 shares >= threshold of 5)
    /// let reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap();
    /// assert_eq!(reconstructed, secret);
    ///
    /// // VP + Executive can reconstruct together (3 + 2 = 5 shares >= threshold of 5)
    /// let reconstructed = hsss.reconstruct(&hierarchical_shares[1..3]).unwrap();
    /// assert_eq!(reconstructed, secret);
    /// ```
    ///
    /// # Security
    /// - Inherits all security properties from the underlying Shamir reconstruction
    /// - Constant-time operations prevent side-channel attacks
    /// - Integrity verification (if enabled during splitting)
    /// - No information leakage about the secret with insufficient shares
    pub fn reconstruct(&self, hierarchical_shares: &[HierarchicalShare]) -> Result<Vec<u8>> {
        // Flatten all shares from all hierarchical shares into a single vector
        let mut all_shares = Vec::new();
        
        for hierarchical_share in hierarchical_shares {
            all_shares.extend_from_slice(&hierarchical_share.shares);
        }
        
        // Use the standard Shamir reconstruction method
        ShamirShare::reconstruct(&all_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_level_creation() {
        let level = AccessLevel {
            name: "President".to_string(),
            shares_count: 5,
        };

        assert_eq!(level.name, "President");
        assert_eq!(level.shares_count, 5);
    }

    #[test]
    fn test_hierarchical_share_creation() {
        let share = HierarchicalShare {
            level_name: "VP".to_string(),
            shares: vec![],
        };

        assert_eq!(share.level_name, "VP");
        assert_eq!(share.shares.len(), 0);
    }

    #[test]
    fn test_hsss_builder_basic() {
        let hsss = Hsss::builder(5)
            .add_level("President", 5)
            .add_level("VP", 3)
            .add_level("Executive", 2)
            .build()
            .unwrap();

        assert_eq!(hsss.master_threshold(), 5);
        assert_eq!(hsss.total_shares(), 10); // 5 + 3 + 2
        assert_eq!(hsss.levels().len(), 3);

        let levels = hsss.levels();
        assert_eq!(levels[0].name, "President");
        assert_eq!(levels[0].shares_count, 5);
        assert_eq!(levels[1].name, "VP");
        assert_eq!(levels[1].shares_count, 3);
        assert_eq!(levels[2].name, "Executive");
        assert_eq!(levels[2].shares_count, 2);
    }

    #[test]
    fn test_hsss_builder_single_level() {
        let hsss = Hsss::builder(3)
            .add_level("Admin", 5)
            .build()
            .unwrap();

        assert_eq!(hsss.master_threshold(), 3);
        assert_eq!(hsss.total_shares(), 5);
        assert_eq!(hsss.levels().len(), 1);
        assert_eq!(hsss.levels()[0].name, "Admin");
        assert_eq!(hsss.levels()[0].shares_count, 5);
    }

    #[test]
    fn test_hsss_builder_validation_zero_threshold() {
        let result = Hsss::builder(0)
            .add_level("President", 5)
            .build();

        assert!(matches!(result, Err(ShamirError::InvalidThreshold(0))));
    }

    #[test]
    fn test_hsss_builder_validation_no_levels() {
        let result = Hsss::builder(5).build();

        assert!(matches!(result, Err(ShamirError::InvalidConfig(_))));
    }

    #[test]
    fn test_hsss_builder_validation_zero_shares() {
        let result = Hsss::builder(5)
            .add_level("President", 0)
            .build();

        assert!(matches!(result, Err(ShamirError::InvalidShareCount(0))));
    }

    #[test]
    fn test_hsss_builder_validation_threshold_too_large() {
        let result = Hsss::builder(10)
            .add_level("President", 5)
            .add_level("VP", 3)
            .build();

        assert!(matches!(
            result,
            Err(ShamirError::ThresholdTooLarge { threshold: 10, total_shares: 8 })
        ));
    }

    #[test]
    fn test_hsss_builder_validation_too_many_shares() {
        let result = Hsss::builder(5)
            .add_level("Level1", 200)
            .add_level("Level2", 100)
            .build();

        assert!(matches!(result, Err(ShamirError::InvalidConfig(_))));
    }

    #[test]
    fn test_hsss_builder_method_chaining() {
        let hsss = Hsss::builder(7)
            .add_level("CEO", 7)
            .add_level("CTO", 5)
            .add_level("Manager", 3)
            .add_level("Employee", 1)
            .build()
            .unwrap();

        assert_eq!(hsss.master_threshold(), 7);
        assert_eq!(hsss.total_shares(), 16); // 7 + 5 + 3 + 1
        assert_eq!(hsss.levels().len(), 4);
    }

    #[test]
    fn test_hsss_builder_edge_case_threshold_equals_total() {
        let hsss = Hsss::builder(10)
            .add_level("President", 5)
            .add_level("VP", 5)
            .build()
            .unwrap();

        assert_eq!(hsss.master_threshold(), 10);
        assert_eq!(hsss.total_shares(), 10);
    }

    #[test]
    fn test_hsss_builder_max_shares() {
        let hsss = Hsss::builder(255)
            .add_level("Level1", 255)
            .build()
            .unwrap();

        assert_eq!(hsss.master_threshold(), 255);
        assert_eq!(hsss.total_shares(), 255);
    }

    #[test]
    fn test_access_level_clone() {
        let level1 = AccessLevel {
            name: "President".to_string(),
            shares_count: 5,
        };

        let level2 = level1.clone();
        assert_eq!(level1, level2);
        assert_eq!(level1.name, level2.name);
        assert_eq!(level1.shares_count, level2.shares_count);
    }

    #[test]
    fn test_hierarchical_share_clone() {
        let share1 = HierarchicalShare {
            level_name: "VP".to_string(),
            shares: vec![],
        };

        let share2 = share1.clone();
        assert_eq!(share1, share2);
        assert_eq!(share1.level_name, share2.level_name);
        assert_eq!(share1.shares.len(), share2.shares.len());
    }

    #[test]
    #[cfg(feature = "zeroize")]
    fn test_zeroize_derives() {
        use zeroize::Zeroize;

        let mut level = AccessLevel {
            name: "Secret".to_string(),
            shares_count: 5,
        };

        level.zeroize();
        // After zeroization, the name should be empty and shares_count should be 0
        assert_eq!(level.name, "");
        assert_eq!(level.shares_count, 0);

        let mut hierarchical_share = HierarchicalShare {
            level_name: "Secret".to_string(),
            shares: vec![],
        };

        hierarchical_share.zeroize();
        // After zeroization, the level_name should be empty and shares should be empty
        assert_eq!(hierarchical_share.level_name, "");
        assert_eq!(hierarchical_share.shares.len(), 0);
    }

    #[test]
    fn test_split_secret_basic() {
        let mut hsss = Hsss::builder(5)
            .add_level("President", 5)
            .add_level("VP", 3)
            .add_level("Executive", 2)
            .build()
            .unwrap();

        let secret = b"top secret information";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        // Verify we got the expected number of hierarchical shares
        assert_eq!(hierarchical_shares.len(), 3);

        // Verify President level
        assert_eq!(hierarchical_shares[0].level_name, "President");
        assert_eq!(hierarchical_shares[0].shares.len(), 5);

        // Verify VP level
        assert_eq!(hierarchical_shares[1].level_name, "VP");
        assert_eq!(hierarchical_shares[1].shares.len(), 3);

        // Verify Executive level
        assert_eq!(hierarchical_shares[2].level_name, "Executive");
        assert_eq!(hierarchical_shares[2].shares.len(), 2);

        // Verify share properties
        for hierarchical_share in &hierarchical_shares {
            for share in &hierarchical_share.shares {
                assert_eq!(share.threshold, 5); // Master threshold
                assert_eq!(share.total_shares, 10); // Total shares (5+3+2)
                assert!(share.integrity_check); // Default is true
            }
        }
    }

    #[test]
    fn test_reconstruct_president_alone() {
        let mut hsss = Hsss::builder(5)
            .add_level("President", 5)
            .add_level("VP", 3)
            .add_level("Executive", 2)
            .build()
            .unwrap();

        let secret = b"classified data";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        // President should be able to reconstruct alone (5 shares >= threshold of 5)
        let reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_reconstruct_vp_and_executive() {
        let mut hsss = Hsss::builder(5)
            .add_level("President", 5)
            .add_level("VP", 3)
            .add_level("Executive", 2)
            .build()
            .unwrap();

        let secret = b"sensitive information";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        // VP + Executive should be able to reconstruct together (3 + 2 = 5 shares >= threshold of 5)
        let reconstructed = hsss.reconstruct(&hierarchical_shares[1..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_reconstruct_all_levels() {
        let mut hsss = Hsss::builder(5)
            .add_level("President", 5)
            .add_level("VP", 3)
            .add_level("Executive", 2)
            .build()
            .unwrap();

        let secret = b"multi-level secret";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        // All levels together should also work (5 + 3 + 2 = 10 shares >= threshold of 5)
        let reconstructed = hsss.reconstruct(&hierarchical_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_reconstruct_insufficient_shares() {
        let mut hsss = Hsss::builder(5)
            .add_level("President", 5)
            .add_level("VP", 3)
            .add_level("Executive", 2)
            .build()
            .unwrap();

        let secret = b"protected data";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        // VP alone should not be able to reconstruct (3 shares < threshold of 5)
        let result = hsss.reconstruct(&hierarchical_shares[1..2]);
        assert!(matches!(result, Err(ShamirError::InsufficientShares { needed: 5, got: 3 })));

        // Executive alone should not be able to reconstruct (2 shares < threshold of 5)
        let result = hsss.reconstruct(&hierarchical_shares[2..3]);
        assert!(matches!(result, Err(ShamirError::InsufficientShares { needed: 5, got: 2 })));
    }

    #[test]
    fn test_split_secret_single_level() {
        let mut hsss = Hsss::builder(3)
            .add_level("Admin", 5)
            .build()
            .unwrap();

        let secret = b"admin secret";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        assert_eq!(hierarchical_shares.len(), 1);
        assert_eq!(hierarchical_shares[0].level_name, "Admin");
        assert_eq!(hierarchical_shares[0].shares.len(), 5);

        // Should be able to reconstruct with any 3 shares
        let reconstructed = hsss.reconstruct(&hierarchical_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_split_secret_empty_secret() {
        let mut hsss = Hsss::builder(2)
            .add_level("Level1", 3)
            .add_level("Level2", 2)
            .build()
            .unwrap();

        let secret = b"";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        assert_eq!(hierarchical_shares.len(), 2);
        
        // Should be able to reconstruct empty secret
        let reconstructed = hsss.reconstruct(&hierarchical_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_split_secret_large_secret() {
        let mut hsss = Hsss::builder(10)
            .add_level("CEO", 10)
            .add_level("CTO", 7)
            .add_level("Manager", 5)
            .add_level("Employee", 3)
            .build()
            .unwrap();

        // Create a larger secret
        let secret: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let hierarchical_shares = hsss.split_secret(&secret).unwrap();

        assert_eq!(hierarchical_shares.len(), 4);
        assert_eq!(hierarchical_shares[0].shares.len(), 10); // CEO
        assert_eq!(hierarchical_shares[1].shares.len(), 7);  // CTO
        assert_eq!(hierarchical_shares[2].shares.len(), 5);  // Manager
        assert_eq!(hierarchical_shares[3].shares.len(), 3);  // Employee

        // CEO should be able to reconstruct alone
        let reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap();
        assert_eq!(reconstructed, secret);

        // CTO + Manager should be able to reconstruct (7 + 5 = 12 >= 10)
        let reconstructed = hsss.reconstruct(&hierarchical_shares[1..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_split_secret_different_combinations() {
        let mut hsss = Hsss::builder(7)
            .add_level("Level1", 7)
            .add_level("Level2", 4)
            .add_level("Level3", 3)
            .add_level("Level4", 2)
            .build()
            .unwrap();

        let secret = b"combination test secret";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        // Test various combinations that should work
        let valid_combinations = vec![
            vec![0],       // Level1 alone (7 shares >= 7)
            vec![1, 2],    // Level2 + Level3 (4 + 3 = 7 shares >= 7)
            vec![0, 1],    // Level1 + Level2 (7 + 4 = 11 shares >= 7)
            vec![1, 2, 3], // Level2 + Level3 + Level4 (4 + 3 + 2 = 9 shares >= 7)
        ];

        for combo in valid_combinations {
            let mut selected_shares = Vec::new();
            for &level_idx in &combo {
                if level_idx < hierarchical_shares.len() {
                    selected_shares.push(hierarchical_shares[level_idx].clone());
                }
            }
            
            let reconstructed = hsss.reconstruct(&selected_shares).unwrap();
            assert_eq!(reconstructed, secret);
        }
    }

    #[test]
    fn test_reconstruct_no_hierarchical_shares() {
        let hsss = Hsss::builder(5)
            .add_level("President", 5)
            .build()
            .unwrap();

        // Empty slice should fail
        let result = hsss.reconstruct(&[]);
        assert!(matches!(result, Err(ShamirError::InsufficientShares { needed: 1, got: 0 })));
    }

    #[test]
    fn test_share_indices_are_unique() {
        let mut hsss = Hsss::builder(5)
            .add_level("Level1", 3)
            .add_level("Level2", 4)
            .add_level("Level3", 2)
            .build()
            .unwrap();

        let secret = b"unique indices test";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        // Collect all share indices
        let mut all_indices = Vec::new();
        for hierarchical_share in &hierarchical_shares {
            for share in &hierarchical_share.shares {
                all_indices.push(share.index);
            }
        }

        // Verify all indices are unique
        all_indices.sort();
        for i in 1..all_indices.len() {
            assert_ne!(all_indices[i-1], all_indices[i], "Found duplicate share index: {}", all_indices[i]);
        }

        // Verify indices are in expected range (1 to total_shares)
        assert_eq!(all_indices[0], 1);
        assert_eq!(all_indices[all_indices.len() - 1], hsss.total_shares());
    }

    #[test]
    fn test_split_secret_with_integrity_disabled() {
        use crate::config::Config;

        // Create HSSS with integrity check disabled
        let config = Config::new().with_integrity_check(false);
        let master_scheme = ShamirShare::builder(10, 5)
            .with_config(config)
            .build()
            .unwrap();

        let mut hsss = Hsss {
            master_scheme,
            levels: vec![
                AccessLevel { name: "Admin".to_string(), shares_count: 6 },
                AccessLevel { name: "User".to_string(), shares_count: 4 },
            ],
        };

        let secret = b"no integrity check";
        let hierarchical_shares = hsss.split_secret(secret).unwrap();

        // Verify shares have integrity_check = false
        for hierarchical_share in &hierarchical_shares {
            for share in &hierarchical_share.shares {
                assert!(!share.integrity_check);
            }
        }

        // Should still reconstruct correctly
        let reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_hsss_integration_example() {
        // This test demonstrates the full HSSS workflow as described in the prompt
        let mut hsss = Hsss::builder(5)
            .add_level("President", 5)    // President gets 5 shares (can reconstruct alone)
            .add_level("VP", 3)           // VP gets 3 shares
            .add_level("Executive", 2)    // Executive gets 2 shares
            .build()
            .unwrap();

        let secret = b"Top secret company information";

        // Split the secret into hierarchical shares
        let hierarchical_shares = hsss.split_secret(secret).unwrap();
        
        // Verify the structure
        assert_eq!(hierarchical_shares.len(), 3);
        assert_eq!(hierarchical_shares[0].level_name, "President");
        assert_eq!(hierarchical_shares[0].shares.len(), 5);
        assert_eq!(hierarchical_shares[1].level_name, "VP");
        assert_eq!(hierarchical_shares[1].shares.len(), 3);
        assert_eq!(hierarchical_shares[2].level_name, "Executive");
        assert_eq!(hierarchical_shares[2].shares.len(), 2);

        // Scenario 1: President reconstructs alone (5 shares >= threshold of 5)
        let reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap();
        assert_eq!(reconstructed, secret);

        // Scenario 2: VP and Executive collaborate (3 + 2 = 5 shares >= threshold of 5)
        let reconstructed = hsss.reconstruct(&hierarchical_shares[1..3]).unwrap();
        assert_eq!(reconstructed, secret);

        // Scenario 3: VP alone should fail (3 shares < threshold of 5)
        let result = hsss.reconstruct(&hierarchical_shares[1..2]);
        assert!(matches!(result, Err(ShamirError::InsufficientShares { needed: 5, got: 3 })));

        // Scenario 4: Executive alone should fail (2 shares < threshold of 5)
        let result = hsss.reconstruct(&hierarchical_shares[2..3]);
        assert!(matches!(result, Err(ShamirError::InsufficientShares { needed: 5, got: 2 })));

        // Scenario 5: All levels together should work (5 + 3 + 2 = 10 shares >= threshold of 5)
        let reconstructed = hsss.reconstruct(&hierarchical_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }
}