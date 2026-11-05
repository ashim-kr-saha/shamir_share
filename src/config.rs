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
    /// Process data in streaming mode
    Streaming,
}

/// Configuration options for splitting and reconstruction
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Config {
    /// Size of chunks to process at once
    pub chunk_size: usize,
    /// Processing mode
    pub mode: SplitMode,
    /// Whether to compress data
    pub compression: bool,
    /// Whether to perform integrity checks
    pub integrity_check: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024, // 1MB default chunk size
            mode: SplitMode::default(),
            compression: false,
            integrity_check: true,
        }
    }
}

/// Maximum allowed chunk size for streaming and configuration (64 MiB)
pub const MAX_CONFIG_CHUNK_SIZE: usize = 64 * 1024 * 1024;

impl Config {
    /// Creates a new configuration with default values
    pub fn new() -> Self {
        Self::default()
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
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }

    /// Enables or disables integrity checking
    pub fn with_integrity_check(mut self, enabled: bool) -> Self {
        self.integrity_check = enabled;
        self
    }

    /// Validates the configuration
    pub fn validate(&self) -> Result<()> {
        if self.chunk_size == 0 || self.chunk_size > MAX_CONFIG_CHUNK_SIZE {
            return Err(ShamirError::InvalidConfig(format!(
                "Chunk size must be between 1 and {MAX_CONFIG_CHUNK_SIZE} bytes"
            )));
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
        assert_eq!(config.mode, SplitMode::Sequential);
        assert_eq!(config.chunk_size, 1024 * 1024);
        assert!(!config.compression);
        assert!(config.integrity_check);
    }

    #[test]
    fn test_config_builder() {
        let config = Config::new()
            .with_chunk_size(4096)
            .unwrap()
            .with_mode(SplitMode::Parallel)
            .with_compression(true)
            .with_integrity_check(false);

        assert_eq!(config.chunk_size, 4096);
        assert_eq!(config.mode, SplitMode::Parallel);
        assert!(config.compression);
        assert!(!config.integrity_check);
    }

    #[test]
    fn test_invalid_config() {
        assert!(Config::new().with_chunk_size(0).is_err());
    }
}
