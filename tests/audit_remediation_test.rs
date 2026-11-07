#![cfg(all(
    feature = "std",
    feature = "hsss",
    feature = "refresh",
    feature = "streaming"
))]

use shamir_share::{
    Config, FiniteField, HierarchicalShare, Hsss, MAX_CONFIG_CHUNK_SIZE, ShamirError, ShamirShare,
    Share,
};
use std::io::Cursor;
use subtle::ConstantTimeEq;

#[test]
fn test_f01_hsss_rejects_forged_metadata() {
    let hsss = Hsss::builder(5).add_level("President", 5).build().unwrap();

    let attacker_scheme = ShamirShare::builder(2, 2).build().unwrap();
    let forged_shares = attacker_scheme.split(b"attacker secret").unwrap();
    let forged = HierarchicalShare::new("Contractor", forged_shares);

    // Previously succeeded with 2 shares even though master_threshold is 5!
    let result = hsss.reconstruct(&[forged]);
    assert!(result.is_err());
    match result.unwrap_err() {
        ShamirError::InvalidShareFormat | ShamirError::InsufficientShares { .. } => {}
        other => panic!(
            "Expected InvalidShareFormat or InsufficientShares, got {:?}",
            other
        ),
    }
}

#[test]
fn test_f02_reconstruct_with_scheme_enforces_policy() {
    let scheme = ShamirShare::builder(5, 3)
        .with_config(Config::new().with_integrity_check(true))
        .build()
        .unwrap();

    let shares = scheme.split(b"sensitive payload").unwrap();

    // 1. Tampering with threshold in share header
    let mut forged_threshold_shares = shares.clone();
    for s in &mut forged_threshold_shares {
        s.threshold = 2;
    }
    assert!(matches!(
        scheme.reconstruct_with_scheme(&forged_threshold_shares[0..3]),
        Err(ShamirError::InvalidShareFormat)
    ));

    // 2. Tampering with integrity flag in share header
    let mut stripped_integrity_shares = shares.clone();
    for s in &mut stripped_integrity_shares {
        s.integrity_check = false;
    }
    assert!(matches!(
        scheme.reconstruct_with_scheme(&stripped_integrity_shares[0..3]),
        Err(ShamirError::InvalidShareFormat)
    ));

    // 3. Valid reconstruction with scheme
    let reconstructed = scheme.reconstruct_with_scheme(&shares[0..3]).unwrap();
    assert_eq!(reconstructed.as_slice(), b"sensitive payload");
}

#[test]
fn test_f02_reconstruct_stream_with_scheme_enforces_policy() {
    let scheme = ShamirShare::builder(3, 2)
        .with_config(Config::new().with_integrity_check(true))
        .build()
        .unwrap();

    let secret = b"streaming payload data";
    let mut writers = vec![
        Cursor::new(Vec::new()),
        Cursor::new(Vec::new()),
        Cursor::new(Vec::new()),
    ];
    scheme
        .split_stream(&mut Cursor::new(secret), &mut writers)
        .unwrap();

    let other_scheme = ShamirShare::builder(5, 3)
        .with_config(Config::new().with_integrity_check(true))
        .build()
        .unwrap();

    let mut readers: Vec<Cursor<Vec<u8>>> = writers
        .into_iter()
        .map(|w| Cursor::new(w.into_inner()))
        .collect();
    let mut out = Cursor::new(Vec::new());

    // Trying to reconstruct 3-of-2 stream with 5-of-3 scheme must fail
    let err = other_scheme.reconstruct_stream_with_scheme(&mut readers[0..3], &mut out);
    assert!(matches!(err, Err(ShamirError::InvalidShareFormat)));
}

#[cfg(feature = "compress")]
#[test]
fn test_f03_stream_decompression_total_limit() {
    // Configure limit to 100 bytes
    let config = Config::new()
        .with_compression(true)
        .with_max_decompressed_stream_size(100);

    let scheme = ShamirShare::builder(3, 2)
        .with_config(config)
        .build()
        .unwrap();

    let secret = vec![b'A'; 200];
    let mut writers = vec![
        Cursor::new(Vec::new()),
        Cursor::new(Vec::new()),
        Cursor::new(Vec::new()),
    ];
    scheme
        .split_stream(&mut Cursor::new(&secret), &mut writers)
        .unwrap();

    let mut readers: Vec<Cursor<Vec<u8>>> = writers
        .into_iter()
        .map(|w| Cursor::new(w.into_inner()))
        .collect();
    let mut out = Cursor::new(Vec::new());

    let err = scheme.reconstruct_stream_with_scheme(&mut readers[0..2], &mut out);
    assert!(matches!(err, Err(ShamirError::DecompressionError(_))));
}

#[test]
fn test_f04_reconstruct_spare_capacity_zero() {
    let scheme = ShamirShare::builder(5, 3)
        .with_config(Config::new().with_integrity_check(true))
        .build()
        .unwrap();

    let secret = b"exact capacity test secret";
    let shares = scheme.split(secret).unwrap();
    let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();

    assert_eq!(&reconstructed[..], secret);
    // Ensure no spare heap capacity leaks plaintext remnants
    assert_eq!(reconstructed.len(), reconstructed.capacity());
}

#[test]
fn test_f06_decentralized_refresh_deltas() {
    let scheme = ShamirShare::builder(5, 3)
        .with_config(Config::new().with_integrity_check(true))
        .build()
        .unwrap();

    let secret = b"confidential cluster secret";
    let mut shares = scheme.split(secret).unwrap();
    let data_len = shares[0].data.len();

    // Coordinator generates zero-sum deltas knowing only indices and length
    let deltas = scheme
        .generate_refresh_deltas(&[1, 2, 3, 4, 5], data_len)
        .unwrap();
    assert_eq!(deltas.len(), 5);

    // Each participant applies its delta locally
    for (share, delta) in shares.iter_mut().zip(deltas.iter()) {
        assert_eq!(share.index, delta.index);
        share.apply_refresh_delta(delta).unwrap();
    }

    // Reconstruct with refreshed shares
    let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
    assert_eq!(&reconstructed[..], secret);

    // Reconstruct with different subset
    let reconstructed_alt = ShamirShare::reconstruct(&shares[2..5]).unwrap();
    assert_eq!(&reconstructed_alt[..], secret);
}

#[test]
fn test_f07_split_rejects_oversized_secret() {
    let oversized_len = MAX_CONFIG_CHUNK_SIZE + 1;
    let config_res = Config::new().with_chunk_size(oversized_len);
    assert!(matches!(config_res, Err(ShamirError::InvalidConfig(_))));
}

#[test]
fn test_f08_constant_time_traits() {
    let a = FiniteField::new(42);
    let b = FiniteField::new(42);
    let c = FiniteField::new(43);

    assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
    assert_eq!(a.ct_eq(&c).unwrap_u8(), 0);

    let inv = a.ct_inverse();
    assert!(bool::from(inv.is_some()));
    assert_eq!(a * inv.unwrap(), FiniteField::new(1));

    let zero = FiniteField::new(0);
    assert!(bool::from(zero.ct_inverse().is_none()));
}

#[test]
fn test_f11_wire_format_trailing_bytes_rejected() {
    let share = Share::new(1, vec![10, 20, 30], 3, 5, false, false);
    let mut bytes = share.to_bytes();
    assert_eq!(Share::from_bytes(&bytes).unwrap(), share);

    // Append malicious trailing byte to share bytes
    bytes.push(0xFF);
    let load_res = Share::from_bytes(&bytes);
    assert!(matches!(load_res, Err(ShamirError::InvalidShareFormat)));
}

#[test]
fn test_f13_error_needed_on_empty_reconstruct() {
    let err = ShamirShare::reconstruct(&[]).unwrap_err();
    assert!(matches!(
        err,
        ShamirError::InsufficientShares { needed: 2, got: 0 }
    ));

    let scheme = ShamirShare::builder(5, 3).build().unwrap();
    let err_scheme = scheme.reconstruct_with_scheme(&[]).unwrap_err();
    assert!(matches!(
        err_scheme,
        ShamirError::InsufficientShares { needed: 3, got: 0 }
    ));
}

#[test]
fn test_sec02_refresh_budget_overflow_rejected() {
    let scheme = ShamirShare::builder(255, 3).build().unwrap();
    // 255 shares * 2 MiB = 510 MiB, which exceeds 256 MiB budget
    let indices: Vec<u8> = (1..=255).collect();
    let err = scheme.generate_refresh_deltas(&indices, 2 * 1024 * 1024);
    assert!(matches!(err, Err(ShamirError::InvalidConfig(_))));
}

#[test]
fn test_sec06_reconstruct_oversized_share_rejected() {
    let oversized_data = vec![0u8; shamir_share::MAX_SHARE_DATA_LEN + 1];
    let share1 = Share::new(1, oversized_data.clone(), 2, 3, false, false);
    let share2 = Share::new(2, oversized_data, 2, 3, false, false);
    let err = ShamirShare::reconstruct(&[share1, share2]);
    assert!(matches!(err, Err(ShamirError::InvalidShareFormat)));
}

#[cfg(feature = "serde")]
#[test]
fn test_sec07_serde_invariant_validation() {
    // 1. Zero index rejected
    let json_zero_idx = r#"{"index":0,"data":[1,2,3],"threshold":2,"total_shares":3,"integrity_check":false,"compression":false}"#;
    assert!(serde_json::from_str::<Share>(json_zero_idx).is_err());

    // 2. Index > total_shares rejected
    let json_high_idx = r#"{"index":4,"data":[1,2,3],"threshold":2,"total_shares":3,"integrity_check":false,"compression":false}"#;
    assert!(serde_json::from_str::<Share>(json_high_idx).is_err());

    // 3. Threshold < 2 rejected
    let json_low_thresh = r#"{"index":1,"data":[1,2,3],"threshold":1,"total_shares":3,"integrity_check":false,"compression":false}"#;
    assert!(serde_json::from_str::<Share>(json_low_thresh).is_err());

    // 4. Threshold > total_shares rejected
    let json_high_thresh = r#"{"index":1,"data":[1,2,3],"threshold":4,"total_shares":3,"integrity_check":false,"compression":false}"#;
    assert!(serde_json::from_str::<Share>(json_high_thresh).is_err());

    // 5. Valid share deserializes properly
    let json_valid = r#"{"index":1,"data":[1,2,3],"threshold":2,"total_shares":3,"integrity_check":false,"compression":false}"#;
    let s: Share = serde_json::from_str(json_valid).unwrap();
    assert_eq!(s.index, 1);
    assert_eq!(s.threshold, 2);
    assert_eq!(s.total_shares, 3);
}

#[test]
fn test_sec03_stream_early_eof_fails_before_amplification() {
    let stream_id = [0x55u8; 16];
    let mut header = Vec::new();
    header.extend_from_slice(b"SHS_STR");
    header.push(2); // version
    header.extend_from_slice(&stream_id);
    header.push(1); // flags (integrity_check = true)
    header.push(1); // index
    header.push(2); // threshold
    header.push(2); // total_shares

    let mut stream1 = header.clone();
    // Chunk length claiming 64 MiB (64 * 1024 * 1024 = 67108864)
    let claimed_len = 64u32 * 1024 * 1024;
    stream1.extend_from_slice(&claimed_len.to_le_bytes());
    // Only supply 10 bytes instead of 64 MiB
    stream1.extend_from_slice(&[0xAA; 10]);

    let mut stream2 = header;
    stream2[25] = 2; // index = 2
    stream2.extend_from_slice(&claimed_len.to_le_bytes());
    stream2.extend_from_slice(&[0xBB; 10]);

    let mut sources = [Cursor::new(stream1), Cursor::new(stream2)];
    let mut out = Vec::new();

    let err = ShamirShare::reconstruct_stream(&mut sources, &mut out);
    assert!(matches!(err, Err(ShamirError::IoError(_))));
}
