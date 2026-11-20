#![cfg(feature = "std")]

use shamir_share::{ShamirError, ShamirShare, Share};

#[test]
fn test_wire_format_roundtrip_all_shares() {
    let shamir = ShamirShare::builder(7, 4).build().unwrap();
    let secret = b"canonical binary wire format test payload";
    let shares = shamir.split(secret).unwrap();

    let mut encoded = Vec::new();
    for share in &shares {
        encoded.push(share.to_bytes().unwrap());
    }

    let mut decoded = Vec::new();
    for bytes in &encoded {
        decoded.push(Share::from_bytes(bytes).unwrap());
    }

    assert_eq!(decoded, shares);

    let reconstructed = ShamirShare::reconstruct(&decoded[0..4]).unwrap();
    assert_eq!(reconstructed.as_slice(), secret);
}

#[test]
fn test_wire_format_framing_details() {
    let share = Share::new(2, vec![1, 2, 3, 4], 3, 5, true, false).unwrap();
    let bytes = share.to_bytes().unwrap();

    // Magic: b"SHS1"
    assert_eq!(&bytes[0..4], b"SHS1");
    // Version: 3
    assert_eq!(bytes[4], 3);
    // Flags: integrity_check=1, compression=0 -> 1
    assert_eq!(bytes[5], 1);
    // Index: 2
    assert_eq!(bytes[6], 2);
    // Threshold: 3
    assert_eq!(bytes[7], 3);
    // Total shares: 5
    assert_eq!(bytes[8], 5);
    // Length: 4 (LE u32)
    assert_eq!(&bytes[9..13], &[4, 0, 0, 0]);
    // Data
    assert_eq!(&bytes[13..17], &[1, 2, 3, 4]);
    assert_eq!(bytes.len(), 17);
}

#[test]
fn test_wire_format_tamper_rejections() {
    let share = Share::new(1, vec![42; 64], 2, 3, true, false).unwrap();
    let bytes = share.to_bytes().unwrap();

    // Valid parses fine
    assert!(Share::from_bytes(&bytes).is_ok());

    // Truncated header (< 13 bytes)
    for i in 0..13 {
        assert!(matches!(
            Share::from_bytes(&bytes[..i]),
            Err(ShamirError::InvalidShareFormat)
        ));
    }

    // Truncated payload
    assert!(matches!(
        Share::from_bytes(&bytes[..bytes.len() - 1]),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Trailing bytes
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert!(matches!(
        Share::from_bytes(&trailing),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Invalid magic
    let mut bad_magic = bytes.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        Share::from_bytes(&bad_magic),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Invalid version
    let mut bad_ver = bytes.clone();
    bad_ver[4] = 4;
    assert!(matches!(
        Share::from_bytes(&bad_ver),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Reserved flags bit set
    let mut bad_flags = bytes.clone();
    bad_flags[5] |= 0b100;
    assert!(matches!(
        Share::from_bytes(&bad_flags),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Invalid index 0
    let mut bad_idx0 = bytes.clone();
    bad_idx0[6] = 0;
    assert!(matches!(
        Share::from_bytes(&bad_idx0),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Index exceeds total_shares
    let mut bad_idx_excess = bytes.clone();
    bad_idx_excess[6] = 4; // total_shares is 3
    assert!(matches!(
        Share::from_bytes(&bad_idx_excess),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Threshold < 2
    let mut bad_thresh = bytes.clone();
    bad_thresh[7] = 1;
    assert!(matches!(
        Share::from_bytes(&bad_thresh),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Threshold > total_shares
    let mut bad_thresh_excess = bytes.clone();
    bad_thresh_excess[7] = 4; // total_shares is 3
    assert!(matches!(
        Share::from_bytes(&bad_thresh_excess),
        Err(ShamirError::InvalidShareFormat)
    ));
}

#[test]
fn test_to_bytes_validates_invariants() {
    let mut bad_share = Share::new(1, vec![1, 2, 3], 2, 3, true, false).unwrap();

    // Invalid index 0
    bad_share.index = 0;
    assert!(matches!(
        bad_share.to_bytes(),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Index > total_shares
    bad_share.index = 4;
    assert!(matches!(
        bad_share.to_bytes(),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Restore index, invalidate threshold (< 2)
    bad_share.index = 1;
    bad_share.threshold = 1;
    assert!(matches!(
        bad_share.to_bytes(),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Threshold > total_shares
    bad_share.threshold = 4;
    assert!(matches!(
        bad_share.to_bytes(),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Invalidate compression without integrity
    bad_share.threshold = 2;
    bad_share.integrity_check = false;
    bad_share.compression = true;
    assert!(matches!(
        bad_share.to_bytes(),
        Err(ShamirError::InvalidShareFormat)
    ));
}

#[test]
fn test_compression_without_integrity_rejected_in_share_new_and_from_bytes() {
    // Share::new rejects compression: true, integrity_check: false
    assert!(matches!(
        Share::new(1, vec![1, 2, 3], 2, 3, false, true),
        Err(ShamirError::InvalidShareFormat)
    ));

    // from_bytes rejects flags = 2 (compression without integrity)
    let valid_share = Share::new(1, vec![1, 2, 3], 2, 3, true, false).unwrap();
    let mut raw_bytes = valid_share.to_bytes().unwrap();
    raw_bytes[5] = 2; // flags: compression=true, integrity=false
    assert!(matches!(
        Share::from_bytes(&raw_bytes),
        Err(ShamirError::InvalidShareFormat)
    ));
}

