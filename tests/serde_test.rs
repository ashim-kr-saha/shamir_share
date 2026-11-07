#![cfg(all(feature = "serde", feature = "std"))]

use shamir_share::{ShamirShare, Share};

#[test]
fn test_serde_json_roundtrip() {
    let shamir = ShamirShare::builder(5, 3).build().unwrap();
    let secret = b"super secret serde test";
    let shares = shamir.split(secret).unwrap();

    for share in &shares {
        let serialized = serde_json::to_string(&share).unwrap();
        let deserialized: Share = serde_json::from_str(&serialized).unwrap();
        assert_eq!(&deserialized, share);
    }

    let serialized_all = serde_json::to_string(&shares).unwrap();
    let deserialized_all: Vec<Share> = serde_json::from_str(&serialized_all).unwrap();
    let reconstructed = ShamirShare::reconstruct(&deserialized_all[0..3]).unwrap();
    assert_eq!(reconstructed.as_slice(), secret);
}
