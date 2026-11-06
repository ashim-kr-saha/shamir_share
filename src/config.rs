use crate::Zeroizing;
use crate::error::{Result, ShamirError};

/// Processing mode for share operations
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplitMode {
    /// Process data sequentially
    #[default]
    Sequential,
    /// Process data in parallel
    Parallel,
}

/// Configuration options for splitting and reconstruction
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Config {
    /// Size of chunks to process at once
    chunk_size: usize,
    /// Processing mode
    mode: SplitMode,
    /// Whether to compress data
    compression: bool,
    /// Whether to perform integrity checks
    integrity_check: bool,
    /// Maximum cumulative decompressed bytes allowed for a stream
    max_decompressed_stream_size: Option<u64>,
    /// Optional 256-bit authentication key for HMAC-based share authentication
    authentication_key: Option<Zeroizing<[u8; 32]>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024, // 1MB default chunk size
            mode: SplitMode::default(),
            compression: false,
            integrity_check: true,
            max_decompressed_stream_size: None,
            authentication_key: None,
        }
    }
}

/// Maximum allowed chunk size for streaming and configuration (64 MiB)
pub const MAX_CONFIG_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// Default maximum cumulative decompressed bytes allowed during streaming reconstruction (1 GiB)
pub const MAX_DEFAULT_STREAM_DECOMPRESSED_SIZE: u64 = 1024 * 1024 * 1024;

impl Config {
    /// Creates a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the configured chunk size
    #[inline]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Returns the configured split mode
    #[inline]
    pub fn mode(&self) -> SplitMode {
        self.mode
    }

    /// Returns whether compression is enabled
    #[inline]
    pub fn compression(&self) -> bool {
        self.compression
    }

    /// Returns whether integrity checking is enabled
    #[inline]
    pub fn integrity_check(&self) -> bool {
        self.integrity_check
    }

    /// Returns the maximum allowed cumulative decompressed bytes for streams, if configured
    #[inline]
    pub fn max_decompressed_stream_size(&self) -> Option<u64> {
        self.max_decompressed_stream_size
    }

    /// Returns the configured authentication key, if set
    #[inline]
    pub fn authentication_key(&self) -> Option<&[u8; 32]> {
        self.authentication_key.as_deref()
    }

    /// Sets the chunk size
    pub fn with_chunk_size(mut self, size: usize) -> Result<Self> {
        if size == 0 || size > MAX_CONFIG_CHUNK_SIZE {
            return Err(ShamirError::InvalidConfig(format!(
                "Chunk size must be between 1 and {MAX_CONFIG_CHUNK_SIZE} bytes"
            )));
        }
        self.chunk_size = size;
        Ok(self)
    }

    /// Sets the processing mode
    pub fn with_mode(mut self, mode: SplitMode) -> Self {
        self.mode = mode;
        self
    }

    /// Enables or disables compression
    ///
    /// # Security Warning
    /// Compression is **not** constant-time. Compressed size and execution time depend directly
    /// on secret entropy and repeated patterns, which can leak information about the secret
    /// through side channels (e.g. CRIME/BREACH style length leaks). Do not enable compression
    /// for secrets where length or entropy leaks pose a security risk.
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }

    /// Enables or disables integrity checking
    pub fn with_integrity_check(mut self, enabled: bool) -> Self {
        self.integrity_check = enabled;
        self
    }

    /// Sets the maximum allowed cumulative decompressed bytes for streaming reconstruction
    pub fn with_max_decompressed_stream_size(mut self, max_size: u64) -> Self {
        self.max_decompressed_stream_size = Some(max_size);
        self
    }

    /// Configures an optional caller-held 256-bit authentication key
    ///
    /// When set, shares and stream chunks are authenticated with HMAC-SHA256
    /// using this key, preventing any adversary who accesses $k$ shares from
    /// substituting secrets or truncating streams without possessing the key.
    pub fn with_authentication_key(mut self, key: [u8; 32]) -> Self {
        self.authentication_key = Some(Zeroizing::new(key));
        self
    }

    /// Validates the configuration
    pub fn validate(&self) -> Result<()> {
        if self.chunk_size == 0 || self.chunk_size > MAX_CONFIG_CHUNK_SIZE {
            return Err(ShamirError::InvalidConfig(format!(
                "Chunk size must be between 1 and {MAX_CONFIG_CHUNK_SIZE} bytes"
            )));
        }

        if self.compression && !self.integrity_check {
            return Err(ShamirError::InvalidConfig(
                "Compression cannot be enabled without integrity checking".into(),
            ));
        }

        #[cfg(not(feature = "compress"))]
        if self.compression {
            return Err(ShamirError::InvalidConfig(
                "Compression requested but crate was compiled without 'compress' feature".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.mode(), SplitMode::Sequential);
        assert_eq!(config.chunk_size(), 1024 * 1024);
        assert!(!config.compression());
        assert!(config.integrity_check());
    }

    #[test]
    fn test_config_builder() {
        let config = Config::new()
            .with_chunk_size(4096)
            .unwrap()
            .with_mode(SplitMode::Parallel)
            .with_compression(true)
            .with_integrity_check(false);

        assert_eq!(config.chunk_size(), 4096);
        assert_eq!(config.mode(), SplitMode::Parallel);
        assert!(config.compression());
        assert!(!config.integrity_check());
    }

    #[test]
    fn test_invalid_config() {
        assert!(Config::new().with_chunk_size(0).is_err());
        let bad_compression = Config::new()
            .with_compression(true)
            .with_integrity_check(false);
        assert!(bad_compression.validate().is_err());
    }

    #[test]
    fn test_authentication_key_config() {
        let key = [42u8; 32];
        let config = Config::new().with_authentication_key(key);
        assert_eq!(config.authentication_key(), Some(&key));
    }
}
