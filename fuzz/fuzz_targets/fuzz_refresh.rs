#![no_main]

use libfuzzer_sys::fuzz_target;
use shamir_share::{Config, ShamirShare};

// Fuzz target for proactive share refreshing and zero-polynomial delta generation.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let threshold = 2 + (data[0] % 4);
    let extra = data[1] % 4;
    let total_shares = threshold + extra;
    let secret = &data[2..];

    if let Ok(scheme) = ShamirShare::builder(total_shares, threshold)
        .with_config(Config::new().with_integrity_check(true))
        .build()
    {
        if let Ok(shares) = scheme.split(secret) {
            if let Ok(refreshed) = scheme.refresh_shares(&shares) {
                assert_eq!(refreshed.len(), shares.len());
                let reconstructed = ShamirShare::reconstruct(&refreshed[..threshold as usize]).unwrap();
                assert_eq!(reconstructed.as_slice(), secret);
            }
        }
    }
});
