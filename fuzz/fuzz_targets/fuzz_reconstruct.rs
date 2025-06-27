#![no_main]

use libfuzzer_sys::fuzz_target;
use shamir_share::{Share, ShamirShare};

// Fuzzing target for ShamirShare::reconstruct method
//
// This fuzzer generates arbitrary Share objects and tests the reconstruction logic
// to ensure it never panics regardless of the input. It tests various edge cases:
// - Invalid share indices (0, duplicates, out of range)
// - Inconsistent share metadata (threshold, total_shares, integrity_check)
// - Malformed share data (empty, inconsistent lengths)
// - Invalid threshold values
// - Corrupted share data
//
// The goal is to ensure the reconstruct method always returns a proper Result
// and never panics, even with completely malformed input.
fuzz_target!(|data: &[u8]| {
    // Skip if we don't have enough data to work with
    if data.len() < 10 {
        return;
    }

    // Parse fuzzer input to create arbitrary shares
    let mut shares = Vec::new();
    let mut offset = 0;

    // Extract number of shares to generate (1-20 to keep fuzzing efficient)
    let num_shares = (data[offset] % 20).max(1);
    offset += 1;

    // Generate shares from fuzzer data
    for _i in 0..num_shares {
        if offset + 8 >= data.len() {
            break;
        }

        // Extract share parameters from fuzzer data
        let index = data[offset];
        let threshold = data[offset + 1];
        let total_shares = data[offset + 2];
        let integrity_check = data[offset + 3] & 1 == 1;
        
        // Extract data length (limit to reasonable size for fuzzing performance)
        let data_len = ((data[offset + 4] as usize) << 8 | data[offset + 5] as usize).min(1000);
        offset += 6;

        // Extract share data
        let mut share_data = Vec::new();
        for j in 0..data_len {
            if offset + j < data.len() {
                share_data.push(data[offset + j]);
            } else {
                share_data.push(0); // Pad with zeros if not enough data
            }
        }
        offset += data_len;

        // Create share with potentially invalid parameters
        let share = Share {
            index,
            data: share_data,
            threshold,
            total_shares,
            integrity_check,
        };

        shares.push(share);
    }

    // Test reconstruction with the generated shares
    // This should never panic, only return Ok or Err
    let _result = ShamirShare::reconstruct(&shares);

    // Test with empty shares vector
    let _result = ShamirShare::reconstruct(&[]);

    // Test with single share
    if !shares.is_empty() {
        let _result = ShamirShare::reconstruct(&shares[0..1]);
    }

    // Test with duplicate shares (same index)
    if shares.len() >= 2 {
        let duplicate_shares = vec![shares[0].clone(), shares[0].clone()];
        let _result = ShamirShare::reconstruct(&duplicate_shares);
    }

    // Test with shares having inconsistent data lengths
    if shares.len() >= 2 {
        let mut inconsistent_shares = shares.clone();
        if inconsistent_shares.len() >= 2 {
            // Make second share have different data length
            inconsistent_shares[1].data = vec![0u8; inconsistent_shares[0].data.len() + 1];
            let _result = ShamirShare::reconstruct(&inconsistent_shares);
        }
    }

    // Test with shares having inconsistent integrity check settings
    if shares.len() >= 2 {
        let mut inconsistent_shares = shares.clone();
        if inconsistent_shares.len() >= 2 {
            inconsistent_shares[1].integrity_check = !inconsistent_shares[0].integrity_check;
            let _result = ShamirShare::reconstruct(&inconsistent_shares);
        }
    }

    // Test with zero-index shares (invalid in GF(256))
    if !shares.is_empty() {
        let mut zero_index_shares = shares.clone();
        zero_index_shares[0].index = 0;
        let _result = ShamirShare::reconstruct(&zero_index_shares);
    }

    // Test with very large threshold values
    if !shares.is_empty() {
        let mut large_threshold_shares = shares.clone();
        large_threshold_shares[0].threshold = 255;
        let _result = ShamirShare::reconstruct(&large_threshold_shares);
    }
});