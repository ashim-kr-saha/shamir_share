#![no_main]

use libfuzzer_sys::fuzz_target;
use shamir_share::Share;

// Fuzz target for serde deserialization of Share structs.
//
// Ensures bounded memory allocations and enforces invariants regardless of hostile JSON inputs.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(share) = serde_json::from_str::<Share>(s) {
            assert!(share.index() > 0);
            assert!(share.index() <= share.total_shares());
            assert!(share.threshold() >= 2);
            assert!(share.threshold() <= share.total_shares());
            assert!(!share.data().is_empty());
            assert!(share.data().len() <= shamir_share::MAX_SHARE_DATA_LEN);
        }
    }
});
