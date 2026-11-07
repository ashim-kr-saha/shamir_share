#![no_main]

use libfuzzer_sys::fuzz_target;
use shamir_share::Share;

// Fuzzing target for Share::from_bytes canonical binary deserialization.
//
// Ensures that arbitrary, truncated, corrupted, and edge-case byte sequences
// never trigger panics, unbounded allocations, or invariant violations.
fuzz_target!(|data: &[u8]| {
    if let Ok(share) = Share::from_bytes(data) {
        // Invariants must hold for any successfully parsed share
        assert!(share.index > 0);
        assert!(share.index <= share.total_shares);
        assert!(share.threshold >= 2);
        assert!(share.threshold <= share.total_shares);

        // Re-serializing and de-serializing must be identical (round-trip idempotence)
        let bytes = share.to_bytes();
        let re_parsed = Share::from_bytes(&bytes).expect("Valid share must re-serialize cleanly");
        assert_eq!(re_parsed, share);
    }
});
