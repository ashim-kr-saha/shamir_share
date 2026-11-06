#![no_main]

use libfuzzer_sys::fuzz_target;
use shamir_share::{Config, ShamirShare, Share};

// Fuzzing target for ShamirShare::reconstruct and reconstruct_with_scheme methods
//
// This fuzzer generates both structured shares (consistent metadata to penetrate into
// Lagrange interpolation, SHA-256 integrity verification, and decompression) and
// arbitrary/mutated shares to test validator resilience.
//
// The goal is to ensure reconstruct methods always return a proper Result and never panic.
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        let _ = ShamirShare::reconstruct(&[]);
        return;
    }

    let mut offset = 0;
    let mode = data[offset];
    offset += 1;

    let threshold = (data[offset] % 8).max(2);
    let total_shares = threshold.max((data[offset + 1] % 16).max(threshold));
    let integrity_check = (data[offset + 2] & 1) != 0;
    let compression = (data[offset + 2] & 2) != 0;
    offset += 3;

    let num_shares = ((data[offset] as usize % (total_shares as usize + 2))).max(1);
    offset += 1;

    if mode % 2 == 0 {
        // Mode 0: Consistent metadata across shares to exercise interpolation,
        // hash checks, and decompression.
        let data_len = if offset + 2 <= data.len() {
            let len = ((data[offset] as usize) << 8 | (data[offset + 1] as usize)) % 512;
            offset += 2;
            len
        } else {
            32
        };

        let mut shares = Vec::with_capacity(num_shares);
        for i in 0..num_shares {
            let index = ((i % (total_shares as usize)) + 1) as u8;
            let mut share_data = vec![0u8; data_len];
            for b in 0..data_len {
                if offset < data.len() {
                    share_data[b] = data[offset];
                    offset += 1;
                }
            }
            shares.push(Share::new(
                index,
                share_data,
                threshold,
                total_shares,
                integrity_check,
                compression,
            ));
        }

        let _ = ShamirShare::reconstruct(&shares);

        let config = Config::new()
            .with_integrity_check(integrity_check)
            .with_compression(compression);
        if let Ok(scheme) = ShamirShare::builder(total_shares, threshold)
            .with_config(config)
            .build()
        {
            let _ = scheme.reconstruct_with_scheme(&shares);
        }

        if shares.len() >= 2 {
            let duplicate_shares = vec![shares[0].clone(), shares[0].clone()];
            let _ = ShamirShare::reconstruct(&duplicate_shares);
        }
    } else {
        // Mode 1: Arbitrary random metadata per share to test validator robustness
        let mut shares = Vec::with_capacity(num_shares);
        for _ in 0..num_shares {
            if offset + 6 >= data.len() {
                break;
            }
            let index = data[offset];
            let th = data[offset + 1];
            let tot = data[offset + 2];
            let ic = data[offset + 3] & 1 == 1;
            let comp = (data[offset + 3] & 2) != 0;
            let dlen = (data[offset + 4] as usize) % 256;
            offset += 5;

            let mut share_data = Vec::with_capacity(dlen);
            for _ in 0..dlen {
                if offset < data.len() {
                    share_data.push(data[offset]);
                    offset += 1;
                } else {
                    share_data.push(0);
                }
            }

            shares.push(Share::new(index, share_data, th, tot, ic, comp));
        }

        let _ = ShamirShare::reconstruct(&shares);
    }

    // Always test empty input
    let _ = ShamirShare::reconstruct(&[]);
});
