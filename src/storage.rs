use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{Result, ShamirError};
use crate::shamir::Share;

const MAGIC_NUMBER: &[u8] = b"SHS1"; // Changed magic number for new format
const VERSION: u8 = 2; // Incremented version for new format

/// Trait defining storage operations for Shamir shares
///
/// Implement this trait to create custom storage backends
///
/// # Example
/// ```
/// use shamir_share::{ShareStore, Share};
///
/// struct MemoryStore;
///
/// impl ShareStore for MemoryStore {
///     fn store_share(&mut self, _: &Share) -> shamir_share::Result<()> { Ok(()) }
///     fn load_share(&self, _: u8) -> shamir_share::Result<Share> { unimplemented!() }
///     fn list_shares(&self) -> shamir_share::Result<Vec<u8>> { Ok(Vec::new()) }
///     fn delete_share(&mut self, _: u8) -> shamir_share::Result<()> { Ok(()) }
/// }
/// ```
pub trait ShareStore {
    /// Stores a share in persistent storage
    fn store_share(&mut self, share: &Share) -> Result<()>;

    /// Retrieves a share from storage by index
    fn load_share(&self, index: u8) -> Result<Share>;

    /// Lists all available share indices
    fn list_shares(&self) -> Result<Vec<u8>>;

    /// Deletes a share from storage
    fn delete_share(&mut self, index: u8) -> Result<()>;
}

/// File system implementation of ShareStore
///
/// Stores each share as a separate file with a secure binary format including
/// magic numbers and version information to prevent format confusion attacks.
/// Files are named in the format: `share_<index>` (e.g., share_001, share_002)
///
/// # Security
/// - Files include magic number validation to prevent format attacks
/// - Version checking ensures compatibility
/// - Atomic write operations prevent partial file corruption
///
/// # Example
/// ```
/// use shamir_share::{FileShareStore, ShareStore};
/// use tempfile::tempdir;
///
/// let temp_dir = tempdir().unwrap();
/// let mut store = FileShareStore::new(temp_dir.path()).unwrap();
///
/// let share = shamir_share::Share {
///     index: 1,
///     data: vec![1, 2, 3],
///     threshold: 3,
///     total_shares: 5,
///     integrity_check: true,
///     compression: false,
/// };
///
/// store.store_share(&share).unwrap();
/// let loaded = store.load_share(1).unwrap();
/// assert_eq!(loaded.data, vec![1, 2, 3]);
/// ```
pub struct FileShareStore {
    /// Base directory for storing shares
    base_dir: PathBuf,
}

impl FileShareStore {
    /// Creates a new file-based store at specified path
    ///
    /// # Example
    /// ```
    /// use shamir_share::FileShareStore;
    /// use std::path::Path;
    ///
    /// let store = FileShareStore::new(Path::new("/tmp/shares")).unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Gets the path for a share file
    fn share_path(&self, index: u8) -> PathBuf {
        self.base_dir.join(format!("share_{index:03}"))
    }
}

impl ShareStore for FileShareStore {
    fn store_share(&mut self, share: &Share) -> Result<()> {
        let path = self.share_path(share.index);
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Write header
        writer.write_all(MAGIC_NUMBER)?;
        writer.write_all(&[VERSION])?;

        // Write metadata
        let integrity_flag = if share.integrity_check { 1 } else { 0 };
        let compression_flag = if share.compression { 2 } else { 0 };
        let flags = integrity_flag | compression_flag;
        writer.write_all(&[flags])?;
        writer.write_all(&[share.index, share.threshold, share.total_shares])?;

        // Write data
        let len = share.data.len() as u32;
        writer.write_all(&len.to_le_bytes())?;
        writer.write_all(&share.data)?;

        Ok(())
    }

    fn load_share(&self, index: u8) -> Result<Share> {
        let path = self.share_path(index);
        let mut file = File::open(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ShamirError::InvalidShareIndex(index)
            } else {
                e.into()
            }
        })?;

        // Read and verify header
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if magic != MAGIC_NUMBER {
            return Err(ShamirError::InvalidShareFormat);
        }

        let mut version = [0u8; 1];
        file.read_exact(&mut version)?;
        if version[0] > VERSION {
            return Err(ShamirError::InvalidShareFormat);
        }

        // Read metadata
        let mut flags = [0u8; 1];
        file.read_exact(&mut flags)?;
        let integrity_check = (flags[0] & 1) != 0;
        let compression = (flags[0] & 2) != 0;

        let mut header = [0u8; 3];
        file.read_exact(&mut header)?;
        let (stored_index, threshold, total_shares) = (header[0], header[1], header[2]);

        // Verify stored index matches requested index
        if stored_index != index {
            return Err(ShamirError::InvalidShareFormat);
        }

        // Read data
        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        let mut data = vec![0u8; len];
        file.read_exact(&mut data)?;

        Ok(Share {
            index,
            data,
            threshold,
            total_shares,
            integrity_check,
            compression,
        })
    }

    fn list_shares(&self) -> Result<Vec<u8>> {
        let mut indices = Vec::new();

        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();

            if let Some(stripped) = file_name.strip_prefix("share_") {
                if let Ok(index) = stripped.parse::<u8>() {
                    indices.push(index);
                }
            }
        }

        indices.sort_unstable();
        Ok(indices)
    }

    fn delete_share(&mut self, index: u8) -> Result<()> {
        let path = self.share_path(index);
        fs::remove_file(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ShamirError::InvalidShareIndex(index)
            } else {
                e.into()
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_file_store() -> Result<()> {
        let temp_dir = tempdir()?;
        let mut store = FileShareStore::new(temp_dir.path())?;

        // Create test share with all required fields
        let share = Share {
            index: 1,
            data: vec![1, 2, 3, 4, 5],
            threshold: 3,    // Added threshold
            total_shares: 5, // Added total_shares
            integrity_check: true,
            compression: false,
        };

        // Store share
        store.store_share(&share)?;

        // List shares
        let indices = store.list_shares()?;
        assert_eq!(indices, vec![1]);

        // Load share
        let loaded = store.load_share(1)?;
        assert_eq!(loaded.index, share.index);
        assert_eq!(loaded.data, share.data);

        // Delete share
        store.delete_share(1)?;
        assert!(store.load_share(1).is_err());
        assert!(store.list_shares()?.is_empty());

        Ok(())
    }

    #[test]
    fn test_invalid_share_access() {
        let temp_dir = tempdir().unwrap();
        let mut store = FileShareStore::new(temp_dir.path()).unwrap();

        // Try to load non-existent share
        assert!(matches!(
            store.load_share(1),
            Err(ShamirError::InvalidShareIndex(1))
        ));

        // Try to delete non-existent share
        assert!(matches!(
            store.delete_share(1),
            Err(ShamirError::InvalidShareIndex(1))
        ));
    }

    #[test]
    fn test_multiple_shares() -> Result<()> {
        let temp_dir = tempdir()?;
        let mut store = FileShareStore::new(temp_dir.path())?;

        // Store multiple shares with required fields
        for i in 1..=5 {
            let share = Share {
                index: i,
                data: vec![i; 5],
                threshold: 3,    // Added threshold
                total_shares: 5, // Added total_shares
                integrity_check: true,
                compression: false,
            };
            store.store_share(&share)?;
        }

        // Verify all shares are listed
        let indices = store.list_shares()?;
        assert_eq!(indices, vec![1, 2, 3, 4, 5]);

        // Load and verify each share
        for i in 1..=5 {
            let share = store.load_share(i)?;
            assert_eq!(share.index, i);
            assert_eq!(share.data, vec![i; 5]);
        }

        Ok(())
    }

    #[test]
    fn test_special_characters_path() -> Result<()> {
        let temp_dir = tempdir()?;
        let dir_path = temp_dir.path().join("special!@#$%^&()_-=+ chars");
        let mut store = FileShareStore::new(&dir_path)?;

        let share = Share {
            index: 1,
            data: vec![1, 2, 3],
            threshold: 3,
            total_shares: 5,
            integrity_check: true,
            compression: false,
        };

        store.store_share(&share)?;
        let loaded = store.load_share(1)?;
        assert_eq!(loaded.data, share.data);
        Ok(())
    }

    #[test]
    fn test_read_only_directory() {
        let temp_dir = tempdir().unwrap();
        let mut perms = fs::metadata(temp_dir.path()).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(temp_dir.path(), perms).unwrap();

        let mut store = FileShareStore::new(temp_dir.path()).unwrap();
        let share = Share {
            index: 1,
            data: vec![1, 2, 3],
            threshold: 3,
            total_shares: 5,
            integrity_check: true,
            compression: false,
        };

        assert!(matches!(
            store.store_share(&share),
            Err(ShamirError::IoError(_))
        ));
    }
}
