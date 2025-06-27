#![no_main]

use libfuzzer_sys::fuzz_target;
use shamir_share::{FileShareStore, ShareStore};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

// Fuzzing target for FileShareStore::load_share method
//
// This fuzzer generates arbitrary byte sequences and writes them to temporary files,
// then attempts to load them as shares using FileShareStore. It tests the parsing
// logic to ensure it never panics with malformed input. Edge cases tested include:
// - Invalid magic numbers
// - Wrong version numbers
// - Truncated files
// - Invalid metadata (index, threshold, total_shares)
// - Invalid data length fields
// - Corrupted share data
// - Files with extra trailing data
// - Empty files
// - Files with partial headers
//
// The goal is to ensure the load_share method always returns a proper Result
// and never panics, even with completely malformed file content.
fuzz_target!(|data: &[u8]| {
    // Create temporary directory for fuzzing
    let temp_dir = match tempdir() {
        Ok(dir) => dir,
        Err(_) => return, // Skip if we can't create temp dir
    };

    let store = match FileShareStore::new(temp_dir.path()) {
        Ok(store) => store,
        Err(_) => return, // Skip if we can't create store
    };

    // Test with various share indices (1-255, plus some edge cases)
    let test_indices = [1, 2, 3, 127, 128, 254, 255];

    for &index in &test_indices {
        // Create a temporary file with fuzzer data
        let share_path = temp_dir.path().join(format!("share_{index:03}"));
        
        // Write fuzzer data to file
        if let Ok(mut file) = File::create(&share_path) {
            let _ = file.write_all(data);
            let _ = file.sync_all();
        }

        // Attempt to load the share - this should never panic
        let _result = store.load_share(index);

        // Clean up the file for next iteration
        let _ = std::fs::remove_file(&share_path);
    }

    // Test with empty file
    let empty_path = temp_dir.path().join("share_001");
    if let Ok(_) = File::create(&empty_path) {
        let _result = store.load_share(1);
        let _ = std::fs::remove_file(&empty_path);
    }

    // Test with file containing only magic number
    if data.len() >= 4 {
        let magic_path = temp_dir.path().join("share_002");
        if let Ok(mut file) = File::create(&magic_path) {
            let _ = file.write_all(&data[0..4]);
            let _ = file.sync_all();
        }
        let _result = store.load_share(2);
        let _ = std::fs::remove_file(&magic_path);
    }

    // Test with file containing magic + version only
    if data.len() >= 5 {
        let version_path = temp_dir.path().join("share_003");
        if let Ok(mut file) = File::create(&version_path) {
            let _ = file.write_all(&data[0..5]);
            let _ = file.sync_all();
        }
        let _result = store.load_share(3);
        let _ = std::fs::remove_file(&version_path);
    }

    // Test with file containing header but no data length
    if data.len() >= 8 {
        let header_path = temp_dir.path().join("share_004");
        if let Ok(mut file) = File::create(&header_path) {
            let _ = file.write_all(&data[0..8]);
            let _ = file.sync_all();
        }
        let _result = store.load_share(4);
        let _ = std::fs::remove_file(&header_path);
    }

    // Test with valid header but truncated data
    if data.len() >= 12 {
        let truncated_path = temp_dir.path().join("share_005");
        if let Ok(mut file) = File::create(&truncated_path) {
            // Write a header that claims more data than we provide
            let _ = file.write_all(b"SHR1"); // Magic
            let _ = file.write_all(&[1]); // Version
            let _ = file.write_all(&[5, 3, 5]); // index=5, threshold=3, total_shares=5
            let _ = file.write_all(&[255u8, 255u8, 255u8, 255u8]); // Large data length
            let _ = file.write_all(&data[0..data.len().min(100)]); // Limited actual data
            let _ = file.sync_all();
        }
        let _result = store.load_share(5);
        let _ = std::fs::remove_file(&truncated_path);
    }

    // Test with corrupted magic number
    if data.len() >= 12 {
        let corrupted_path = temp_dir.path().join("share_006");
        if let Ok(mut file) = File::create(&corrupted_path) {
            let _ = file.write_all(&data[0..4]); // Corrupted magic
            let _ = file.write_all(&[1]); // Version
            let _ = file.write_all(&[6, 3, 5]); // index=6, threshold=3, total_shares=5
            let _ = file.write_all(&[5u8, 0u8, 0u8, 0u8]); // Data length = 5
            let _ = file.write_all(&data[4..data.len().min(9)]); // Some data
            let _ = file.sync_all();
        }
        let _result = store.load_share(6);
        let _ = std::fs::remove_file(&corrupted_path);
    }

    // Test with wrong version
    if data.len() >= 12 {
        let wrong_version_path = temp_dir.path().join("share_007");
        if let Ok(mut file) = File::create(&wrong_version_path) {
            let _ = file.write_all(b"SHR1"); // Correct magic
            let _ = file.write_all(&[data[0]]); // Random version
            let _ = file.write_all(&[7, 3, 5]); // index=7, threshold=3, total_shares=5
            let _ = file.write_all(&[5u8, 0u8, 0u8, 0u8]); // Data length = 5
            let _ = file.write_all(&data[1..data.len().min(6)]); // Some data
            let _ = file.sync_all();
        }
        let _result = store.load_share(7);
        let _ = std::fs::remove_file(&wrong_version_path);
    }

    // Test with mismatched index
    if data.len() >= 12 {
        let mismatched_path = temp_dir.path().join("share_008");
        if let Ok(mut file) = File::create(&mismatched_path) {
            let _ = file.write_all(b"SHR1"); // Correct magic
            let _ = file.write_all(&[1]); // Correct version
            let _ = file.write_all(&[99, 3, 5]); // index=99 (doesn't match filename), threshold=3, total_shares=5
            let _ = file.write_all(&[5u8, 0u8, 0u8, 0u8]); // Data length = 5
            let _ = file.write_all(&data[0..data.len().min(5)]); // Some data
            let _ = file.sync_all();
        }
        let _result = store.load_share(8); // Requesting index 8 but file contains index 99
        let _ = std::fs::remove_file(&mismatched_path);
    }

    // Test with extremely large data length claim
    if data.len() >= 12 {
        let large_length_path = temp_dir.path().join("share_009");
        if let Ok(mut file) = File::create(&large_length_path) {
            let _ = file.write_all(b"SHR1"); // Correct magic
            let _ = file.write_all(&[1]); // Correct version
            let _ = file.write_all(&[9, 3, 5]); // index=9, threshold=3, total_shares=5
            let _ = file.write_all(&[255u8, 255u8, 255u8, 255u8]); // Maximum u32 data length
            let _ = file.write_all(&data[0..data.len().min(100)]); // Limited actual data
            let _ = file.sync_all();
        }
        let _result = store.load_share(9);
        let _ = std::fs::remove_file(&large_length_path);
    }

    // Test with zero data length but some data present
    if data.len() >= 12 {
        let zero_length_path = temp_dir.path().join("share_010");
        if let Ok(mut file) = File::create(&zero_length_path) {
            let _ = file.write_all(b"SHR1"); // Correct magic
            let _ = file.write_all(&[1]); // Correct version
            let _ = file.write_all(&[10, 3, 5]); // index=10, threshold=3, total_shares=5
            let _ = file.write_all(&[0u8, 0u8, 0u8, 0u8]); // Data length = 0
            let _ = file.write_all(&data[0..data.len().min(10)]); // Extra data that shouldn't be there
            let _ = file.sync_all();
        }
        let _result = store.load_share(10);
        let _ = std::fs::remove_file(&zero_length_path);
    }
});