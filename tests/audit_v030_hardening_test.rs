#![cfg(all(feature = "std", feature = "refresh", feature = "streaming"))]

use shamir_share::{
    Config, ShamirError, ShamirShare, Share,
    hsss::{AccessLevel, HierarchicalShare},
};
use std::io::Cursor;

#[test]
fn test_f01_reconstruct_authenticated_apis() {
    let auth_key = [0x5au8; 32];
    let config = Config::new().with_authentication_key(auth_key);
    let scheme = ShamirShare::builder(3, 2)
        .with_config(config)
        .build()
        .unwrap();
    let secret = b"super secret auth test";
    let shares = scheme.split(secret).unwrap();

    // reconstruct_authenticated succeeds on authenticated scheme
    let rec = scheme.reconstruct_authenticated(&shares[0..2]).unwrap();
    assert_eq!(rec.as_slice(), secret);

    // reconstruct_authenticated fails when scheme has no authentication_key
    let unkeyed_scheme = ShamirShare::builder(3, 2).build().unwrap();
    let unkeyed_shares = unkeyed_scheme.split(secret).unwrap();
    let err = unkeyed_scheme.reconstruct_authenticated(&unkeyed_shares[0..2]);
    assert!(matches!(err, Err(ShamirError::UnauthenticatedScheme)));
}

#[test]
fn test_f03_auth_key_without_integrity_rejected() {
    let key = [0x42u8; 32];
    let config = Config::new()
        .with_integrity_check(false)
        .with_authentication_key(key);
    let res = ShamirShare::builder(3, 2).with_config(config).build();
    assert!(matches!(res, Err(ShamirError::InvalidConfig(_))));
}

#[test]
fn test_f07_empty_payload_and_max_share_data_len_rejected() {
    // Share::new rejects empty payload
    let res_empty = Share::new(1, vec![], 2, 3, true, false);
    assert!(matches!(res_empty, Err(ShamirError::InvalidShareFormat)));

    // Share::new rejects > MAX_SHARE_DATA_LEN
    let res_oversized = Share::new(1, vec![0; 64 * 1024 * 1024 + 1], 2, 3, true, false);
    assert!(matches!(
        res_oversized,
        Err(ShamirError::InvalidShareFormat)
    ));

    // Wire format rejects 0 length data
    let mut zero_len_bytes = Vec::new();
    zero_len_bytes.extend_from_slice(b"SHS1");
    zero_len_bytes.push(3); // version
    zero_len_bytes.push(1); // flags (integrity=true)
    zero_len_bytes.push(1); // index
    zero_len_bytes.push(2); // threshold
    zero_len_bytes.push(3); // total
    zero_len_bytes.extend_from_slice(&0u32.to_le_bytes()); // length 0
    let res_wire = Share::from_bytes(&zero_len_bytes);
    assert!(matches!(res_wire, Err(ShamirError::InvalidShareFormat)));
}

#[test]
fn test_f08_f27_field_encapsulation_and_into_data() {
    let share = Share::new(1, vec![10, 20, 30], 2, 3, true, false).unwrap();
    assert_eq!(share.index(), 1);
    assert_eq!(share.threshold(), 2);
    assert_eq!(share.total_shares(), 3);
    assert!(share.integrity_check());
    assert!(!share.compression());
    assert_eq!(share.data(), &[10, 20, 30]);

    // into_data extracts the inner Vec<u8> cleanly wrapped in Zeroizing
    let data = share.into_data();
    assert_eq!(data.as_slice(), &[10, 20, 30]);

    let level = AccessLevel::new("Director", 4);
    assert_eq!(level.name(), "Director");
    assert_eq!(level.shares_count(), 4);

    let h_share = HierarchicalShare::new(
        "Director",
        vec![Share::new(1, vec![1, 2], 2, 3, true, false).unwrap()],
    );
    assert_eq!(h_share.level_name(), "Director");
    assert_eq!(h_share.shares().len(), 1);
    let extracted = h_share.into_shares();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].index(), 1);
}

#[test]
fn test_f24_reconstruct_stream_rejects_excess_sources_before_header() {
    let mut dummy_sources: Vec<_> = (0..256).map(|_| Cursor::new(vec![0u8; 10])).collect();
    let mut out = Vec::new();
    let res = ShamirShare::reconstruct_stream(&mut dummy_sources, &mut out);
    assert!(matches!(res, Err(ShamirError::InvalidShareFormat)));
}

#[test]
fn test_f25_generate_refresh_deltas_bounds() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();

    // 0 length data rejected
    let err_zero = scheme.generate_refresh_deltas(&[1, 2], 0);
    assert!(matches!(err_zero, Err(ShamirError::InvalidConfig(_))));

    // > MAX_SHARE_DATA_LEN rejected
    let err_max = scheme.generate_refresh_deltas(&[1, 2], 64 * 1024 * 1024 + 1);
    assert!(matches!(err_max, Err(ShamirError::InvalidConfig(_))));
}

#[test]
fn test_f05_f21_excess_share_verification_without_p0() {
    let scheme = ShamirShare::builder(5, 3).build().unwrap();
    let secret = b"excess share verification check";
    let shares = scheme.split(secret).unwrap();

    // Reconstruct with 5 shares (threshold 3, 2 excess shares)
    let reconstructed = ShamirShare::reconstruct(&shares).unwrap();
    assert_eq!(reconstructed.as_slice(), secret);

    // Refresh all shares and verify with excess
    let refreshed = scheme.refresh_shares(&shares).unwrap();
    let rec_refreshed = ShamirShare::reconstruct(&refreshed).unwrap();
    assert_eq!(rec_refreshed.as_slice(), secret);

    // Corrupt one excess share in refresh_shares: verification catches it
    let mut corrupted = shares.clone();
    let mut bad_data = corrupted[4].data().to_vec();
    bad_data[0] ^= 0x55;
    corrupted[4] = Share::new(
        corrupted[4].index(),
        bad_data,
        corrupted[4].threshold(),
        corrupted[4].total_shares(),
        corrupted[4].integrity_check(),
        corrupted[4].compression(),
    )
    .unwrap();
    let err = scheme.refresh_shares(&corrupted);
    assert!(matches!(err, Err(ShamirError::IntegrityCheckFailed)));
}

#[cfg(feature = "compress")]
#[test]
fn test_f18_zstd_compress_bound_within_stream_chunk_limit() {
    let bound = zstd::zstd_safe::compress_bound(shamir_share::MAX_CONFIG_CHUNK_SIZE);
    // 49 bytes represents maximum per-chunk header, salt, and framing overhead.
    assert!(
        bound + 49 <= shamir_share::MAX_STREAM_CHUNK_SIZE,
        "Worst-case zstd compress bound ({bound}) + 49 exceeds MAX_STREAM_CHUNK_SIZE ({})",
        shamir_share::MAX_STREAM_CHUNK_SIZE
    );
}
