use shamir_share::{
    FileShareStore, FiniteField, HierarchicalShare, Hsss, ShamirError, ShamirShare, Share,
    ShareStore,
};
use std::io::Cursor;
use tempfile::tempdir;

#[test]
fn test_f01_header_metadata_tampering_rejected() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let secret = b"TRANSFER $100 TO ALICE";
    let mut shares = scheme.split(secret).unwrap();

    // Attacker clears integrity_check bit on shares
    for s in &mut shares {
        s.integrity_check = false;
    }

    // Because metadata is bound into the keyed digest, reconstruction fails
    // or scheme enforcement catches it
    let res = scheme.reconstruct_with_scheme(&shares[0..2]);
    assert!(res.is_err());
}

#[test]
fn test_f02_linear_malleability_rejected_by_keyed_digest() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let original = b"user_permission";
    let target = b"root_permission";
    let mut shares = scheme.split(original).unwrap();

    // Attacker holds only shares[0] (x=1), knows x=2 is used
    let x1 = FiniteField::new(1);
    let x2 = FiniteField::new(2);
    let l1_0 = x2 * (x2 + x1).inverse().unwrap();
    let l1_0_inv = l1_0.inverse().unwrap();

    // In v0.3.0, shares[0].data starts with [salt (32B) || hash (32B) || payload]
    // The attacker doesn't know the 32-byte secret salt, so any linear shift
    // to the payload without the key fails verification with overwhelming probability.
    let diff = original[0] ^ target[0];
    assert_ne!(diff, 0);
    let payload_offset = 32 + 32; // after salt and hash
    shares[0].data[payload_offset] ^= (l1_0_inv * FiniteField::new(diff)).0;

    let res = scheme.reconstruct_with_scheme(&shares[0..2]);
    assert!(matches!(res, Err(ShamirError::IntegrityCheckFailed)));
}

#[test]
fn test_f03_bounded_stream_chunk_resizing() {
    // 32-byte stream claiming 64 MiB chunk must fail without panicking or allocating GiBs
    let mut s1 = Vec::new();
    s1.extend_from_slice(b"SHS_STR\x02"); // Stream format v2
    s1.extend_from_slice(&[0xAA; 16]); // stream_id
    s1.extend_from_slice(&[1, 1, 2, 2]); // flags=1, index=1, threshold=2, total=2
    let max_chunk: u32 = 64 * 1024 * 1024;
    s1.extend_from_slice(&max_chunk.to_le_bytes()); // Claims 64 MiB, but stream ends here!

    let mut s2 = s1.clone();
    s2[25] = 2; // index=2

    let mut sources = [Cursor::new(s1), Cursor::new(s2)];
    let mut out = Vec::new();
    let res = ShamirShare::reconstruct_stream(&mut sources, &mut out);
    assert!(res.is_err());
}

#[test]
fn test_f03_refresh_deltas_bounds_and_duplicates_rejected() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    // Oversized data_length
    let err = scheme.generate_refresh_deltas(&[1, 2], usize::MAX);
    assert!(matches!(err, Err(ShamirError::InvalidConfig(_))));

    // Duplicate indices
    let err_dup = scheme.generate_refresh_deltas(&[1, 1], 16);
    assert!(matches!(err_dup, Err(ShamirError::InvalidShareFormat)));
}

#[test]
fn test_f04_refresh_shares_detects_tail_corruption() {
    let scheme = ShamirShare::builder(5, 3).build().unwrap();
    let secret = b"critical root key";
    let mut shares = scheme.split(secret).unwrap();

    // Corrupt shares[3] and shares[4] (indices 4 and 5)
    shares[3].data[0] ^= 0xFF;
    shares[4].data[0] ^= 0xFF;

    // refresh_shares must detect corrupted tail shares and fail
    let res = scheme.refresh_shares(&shares);
    assert!(matches!(res, Err(ShamirError::IntegrityCheckFailed)));
}

#[test]
fn test_f05_reconstruct_detects_corrupted_extra_shares() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let mut shares = scheme.split(b"secret").unwrap();

    // Corrupt the 3rd share's data completely:
    shares[2].data.fill(0xAA);

    // Passing all 3 shares to reconstruct_with_scheme must detect shares[2] is corrupt
    let res = scheme.reconstruct_with_scheme(&shares);
    assert!(matches!(res, Err(ShamirError::IntegrityCheckFailed)));
}

#[test]
fn test_f06_share_view_debug_redacts_bytes() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let shares = scheme.split(b"super_secret_payload").unwrap();
    let view = shares[0].as_view();

    let view_dbg = format!("{:?}", view);
    assert!(view_dbg.contains("data_len"));
    // Must NOT contain the raw byte pattern
    assert!(!view_dbg.contains("super_secret_payload"));
    assert!(!view_dbg.contains("data: ["));
}

#[test]
fn test_f07_hsss_validates_level_names_and_counts() {
    let hsss = Hsss::builder(5)
        .add_level("President", 5)
        .add_level("VP", 3)
        .build()
        .unwrap();

    // Mismatched share count for VP level
    let invalid_hs = HierarchicalShare::new("VP", vec![]);
    let res = hsss.reconstruct(&[invalid_hs]);
    assert!(matches!(res, Err(ShamirError::InvalidShareFormat)));

    // Unknown level name
    let unknown_hs = HierarchicalShare::new("Contractor", vec![]);
    let res_unknown = hsss.reconstruct(&[unknown_hs]);
    assert!(matches!(res_unknown, Err(ShamirError::InvalidShareFormat)));
}

#[test]
fn test_f08_delta_index_checked() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let mut shares = scheme.split(b"secret payload").unwrap();
    let deltas = scheme
        .generate_refresh_deltas(&[1, 2, 3], shares[0].data.len())
        .unwrap();

    // Applying delta for index 2 to share index 1 must fail
    let res = shares[0].apply_refresh_delta(&deltas[1]);
    assert!(matches!(res, Err(ShamirError::InvalidShareIndex(2))));

    // Applying matching delta for index 1 succeeds
    assert!(shares[0].apply_refresh_delta(&deltas[0]).is_ok());
}

#[test]
fn test_f10_storage_existing_dir_permissions_and_symlinks() {
    let temp = tempdir().unwrap();
    let share_dir = temp.path().join("secure_shares");
    std::fs::create_dir_all(&share_dir).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Set loose permissions on existing directory
        let mut perms = std::fs::metadata(&share_dir).unwrap().permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&share_dir, perms).unwrap();
    }

    // Creating FileShareStore on existing directory must restrict permissions to 0o700
    let mut store = FileShareStore::new(&share_dir).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&share_dir).unwrap().permissions();
        assert_eq!(perms.mode() & 0o077, 0);
    }

    // Symlink attack rejection
    let share = Share::new(1, vec![10, 20, 30], 2, 3, false, false);
    store.store_share(&share).unwrap();

    #[cfg(unix)]
    {
        let share_file = share_dir.join("share_001");
        let symlink_path = share_dir.join("share_002");
        std::os::unix::fs::symlink(&share_file, &symlink_path).unwrap();

        // Loading via symlink must be rejected
        let res = store.load_share(2);
        assert!(matches!(res, Err(ShamirError::InvalidShareFormat)));
    }
}

#[test]
fn test_f13_streaming_rejects_trailing_bytes_after_eos() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let secret = b"streaming secret";
    let mut writers = vec![
        Cursor::new(Vec::new()),
        Cursor::new(Vec::new()),
        Cursor::new(Vec::new()),
    ];
    scheme
        .split_stream(&mut Cursor::new(secret), &mut writers)
        .unwrap();

    let mut stream_bytes: Vec<Vec<u8>> = writers.into_iter().map(|w| w.into_inner()).collect();
    // Append trailing byte after terminal EOS marker on stream 0
    stream_bytes[0].push(0xFF);

    let mut readers: Vec<_> = stream_bytes[0..2]
        .iter()
        .cloned()
        .map(Cursor::new)
        .collect();
    let mut out = Vec::new();
    let res = scheme.reconstruct_stream_with_scheme(&mut readers, &mut out);
    assert!(matches!(res, Err(ShamirError::InvalidShareFormat)));
}
