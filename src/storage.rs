use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{Result, ShamirError};
use crate::shamir::Share;

const MAGIC_NUMBER: &[u8] = b"SHS1"; // Magic number for binary share format
const VERSION: u8 = 2; // Version of the share format
const HEADER_SIZE: u64 = 4 + 1 + 1 + 3 + 4; // magic(4) + ver(1) + flags(1) + meta(3) + len(4) = 13 bytes
const MAX_SHARE_DATA_LEN: usize = 64 * 1024 * 1024; // 64 MiB limit for share data allocation

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
/// - Exact version checking ensures compatibility
/// - Atomic write operations (write-to-temp + flush + sync + rename) prevent partial file corruption
///
/// # Example
/// ```
/// use shamir_share::{FileShareStore, ShareStore};
/// use tempfile::tempdir;
///
/// let temp_dir = tempdir().unwrap();
/// let mut store = FileShareStore::new(temp_dir.path()).unwrap();
///
/// let mut shamir = shamir_share::ShamirShare::builder(5, 3).build().unwrap();
/// let shares = shamir.split(b"test data").unwrap();
///
/// store.store_share(&shares[0]).unwrap();
/// let loaded = store.load_share(1).unwrap();
/// assert_eq!(loaded.data, shares[0].data);
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
        if share.index == 0 {
            return Err(ShamirError::InvalidShareIndex(0));
        }
        if share.threshold < 2 || share.threshold > share.total_shares {
            return Err(ShamirError::InvalidThreshold(share.threshold));
        }

        let len = u32::try_from(share.data.len())
            .map_err(|_| ShamirError::StorageError("Share data exceeds u32::MAX".into()))?;

        let target_path = self.share_path(share.index);
        let tmp_path = self.base_dir.join(format!(".share_{:03}.tmp", share.index));

        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(&tmp_path)?;
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
            writer.write_all(&len.to_le_bytes())?;
            writer.write_all(&share.data)?;

            writer.flush()?;
            let inner_file = writer
                .into_inner()
                .map_err(|e| ShamirError::IoError(e.into_error()))?;
            inner_file.sync_all()?;
        }

        fs::rename(&tmp_path, target_path)?;
        Ok(())
    }

    fn load_share(&self, index: u8) -> Result<Share> {
        if index == 0 {
            return Err(ShamirError::InvalidShareIndex(0));
        }

        let path = self.share_path(index);
        let mut file = File::open(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ShamirError::InvalidShareIndex(index)
            } else {
                e.into()
            }
        })?;

        let file_len = file.metadata()?.len();
        if file_len < HEADER_SIZE {
            return Err(ShamirError::InvalidShareFormat);
        }

        // Read and verify header
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if magic != MAGIC_NUMBER {
            return Err(ShamirError::InvalidShareFormat);
        }

        let mut version = [0u8; 1];
        file.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(ShamirError::InvalidShareFormat);
        }

        // Read metadata
        let mut flags = [0u8; 1];
        file.read_exact(&mut flags)?;
        if (flags[0] & !0b11) != 0 {
            return Err(ShamirError::InvalidShareFormat);
        }
        let integrity_check = (flags[0] & 1) != 0;
        let compression = (flags[0] & 2) != 0;

        let mut header = [0u8; 3];
        file.read_exact(&mut header)?;
        let (stored_index, threshold, total_shares) = (header[0], header[1], header[2]);

        // Verify stored index matches requested index and invariants hold
        if stored_index != index || stored_index == 0 || threshold < 2 || threshold > total_shares {
            return Err(ShamirError::InvalidShareFormat);
        }

        // Read data length
        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        let remaining_file_len = file_len - HEADER_SIZE;
        if (len as u64) != remaining_file_len || len > MAX_SHARE_DATA_LEN {
            return Err(ShamirError::InvalidShareFormat);
        }

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

            if let Some(stripped) = file_name.strip_prefix("share_")
                && stripped.len() == 3
                && stripped.chars().all(|c| c.is_ascii_digit())
                && let Ok(index) = stripped.parse::<u8>()
                && index > 0
            {
                indices.push(index);
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
            threshold: 3,
            total_shares: 5,
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
                threshold: 3,
                total_shares: 5,
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

    #[test]
    fn test_corrupted_or_malicious_share_formats() -> Result<()> {
        let temp_dir = tempdir()?;
        let store = FileShareStore::new(temp_dir.path())?;

        // 1. Crafted 14-byte file claiming 4 GiB allocation
        let fake_path = temp_dir.path().join("share_001");
        {
            let mut file = File::create(&fake_path)?;
            file.write_all(b"SHS1\x02\x01\x01\x03\x05\xff\xff\xff\xff")?;
        }
        assert!(matches!(
            store.load_share(1),
            Err(ShamirError::InvalidShareFormat)
        ));

        // 2. Outdated version (version 1)
        {
            let mut file = File::create(&fake_path)?;
            file.write_all(b"SHS1\x01\x00\x01\x03\x05\x01\x00\x00\x00\xaa")?;
        }
        assert!(matches!(
            store.load_share(1),
            Err(ShamirError::InvalidShareFormat)
        ));

        // 3. Zero index
        {
            let mut file = File::create(&fake_path)?;
            file.write_all(b"SHS1\x02\x00\x00\x03\x05\x01\x00\x00\x00\xaa")?;
        }
        assert!(matches!(
            store.load_share(1),
            Err(ShamirError::InvalidShareFormat)
        ));

        // 4. Threshold < 2
        {
            let mut file = File::create(&fake_path)?;
            file.write_all(b"SHS1\x02\x00\x01\x01\x05\x01\x00\x00\x00\xaa")?;
        }
        assert!(matches!(
            store.load_share(1),
            Err(ShamirError::InvalidShareFormat)
        ));

        // 5. Trailing garbage bytes
        {
            let mut file = File::create(&fake_path)?;
            file.write_all(b"SHS1\x02\x00\x01\x02\x05\x01\x00\x00\x00\xaaEXTRA_GARBAGE")?;
        }
        assert!(matches!(
            store.load_share(1),
            Err(ShamirError::InvalidShareFormat)
        ));

        Ok(())
    }
}
