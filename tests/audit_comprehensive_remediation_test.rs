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

#[test]
fn test_mas01_stream_excess_sources_bounded_memory() {
    // 25 sources claiming 64 MiB chunk must fail on EOF without allocating multi-GiB
    let mut headers = Vec::new();
    let stream_id = [0x55u8; 16];
    let max_chunk: u32 = 64 * 1024 * 1024;

    for i in 1..=25 {
        let mut s = Vec::new();
        s.extend_from_slice(b"SHS_STR\x02");
        s.extend_from_slice(&stream_id);
        s.extend_from_slice(&[1, i as u8, 2, 25]); // flags=1, index=i, threshold=2, total=25
        s.extend_from_slice(&max_chunk.to_le_bytes()); // Claims 64 MiB chunk
        headers.push(Cursor::new(s));
    }

    let mut dest = Vec::new();
    let res = ShamirShare::reconstruct_stream(&mut headers, &mut dest);
    // Should fail cleanly on unexpected EOF during block reading without OOM abort
    assert!(res.is_err());
}

#[test]
fn test_mas02_unauthenticated_shares_rejected_by_default() {
    let scheme = ShamirShare::builder(3, 2)
        .with_config(shamir_share::Config::new().with_integrity_check(false))
        .build()
        .unwrap();

    let shares = scheme.split(b"unauthenticated data").unwrap();

    // Static parameterless reconstruct MUST reject unauthenticated shares
    assert!(matches!(
        ShamirShare::reconstruct(&shares[0..2]),
        Err(ShamirError::InvalidShareFormat)
    ));

    // Reconstruct with explicit scheme succeeds
    let reconstructed = scheme.reconstruct_with_scheme(&shares[0..2]).unwrap();
    assert_eq!(reconstructed.as_slice(), b"unauthenticated data");
}

#[test]
fn test_mas03_bounded_coefficient_allocation() {
    let scheme = ShamirShare::builder(255, 255).build().unwrap();
    // 1 MiB secret * 254 = ~254 MiB coefficients, which exceeds MAX_CONFIG_CHUNK_SIZE (64 MiB)
    let large_secret = vec![0x42u8; 1024 * 1024];
    let res = scheme.try_dealer(&large_secret);
    assert!(matches!(res, Err(ShamirError::InvalidConfig(_))));
}

#[test]
fn test_mas04_hmac_authentication_key_tamper_detection() {
    let key1 = [0x42u8; 32];
    let key2 = [0x99u8; 32];

    let scheme1 = ShamirShare::builder(3, 2)
        .with_config(
            shamir_share::Config::new()
                .with_integrity_check(true)
                .with_authentication_key(key1),
        )
        .build()
        .unwrap();

    let secret = b"authenticated with HMAC key";
    let shares = scheme1.split(secret).unwrap();

    // Reconstruct with matching key succeeds
    let reconstructed = scheme1.reconstruct_with_scheme(&shares[0..2]).unwrap();
    assert_eq!(reconstructed.as_slice(), secret);

    // Reconstruct with wrong key fails integrity check
    let scheme2 = ShamirShare::builder(3, 2)
        .with_config(
            shamir_share::Config::new()
                .with_integrity_check(true)
                .with_authentication_key(key2),
        )
        .build()
        .unwrap();
    let res_wrong_key = scheme2.reconstruct_with_scheme(&shares[0..2]);
    assert!(matches!(
        res_wrong_key,
        Err(ShamirError::IntegrityCheckFailed)
    ));

    // Reconstruct without scheme fails (unauthenticated / missing key)
    let res_no_scheme = ShamirShare::reconstruct(&shares[0..2]);
    assert!(matches!(
        res_no_scheme,
        Err(ShamirError::IntegrityCheckFailed)
    ));
}

#[test]
fn test_mas06_reconstruction_returns_zeroizing() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let secret = b"zeroized secret payload";
    let shares = scheme.split(secret).unwrap();

    let reconstructed: shamir_share::Zeroizing<Vec<u8>> =
        ShamirShare::reconstruct(&shares[0..2]).unwrap();
    assert_eq!(reconstructed.as_slice(), secret);
}

#[test]
fn test_mas07_hsss_duplicate_level_names_and_index_binding() {
    // Duplicate level names rejected
    let res = Hsss::builder(5)
        .add_level("Admin", 3)
        .add_level("Admin", 2)
        .build();
    assert!(matches!(res, Err(ShamirError::InvalidConfig(_))));

    // Index range binding: share with index outside assigned range rejected
    let mut hsss = Hsss::builder(5)
        .add_level("Level1", 3) // range 1..=3
        .add_level("Level2", 2) // range 4..=5
        .build()
        .unwrap();

    let mut shares = hsss.split_secret(b"hsss secret").unwrap();
    // Swap share index: put share from level 2 (index 4) into level 1
    shares[0].shares[0].index = 4;
    let res_forged = hsss.reconstruct(&shares[0..1]);
    assert!(matches!(res_forged, Err(ShamirError::InvalidShareFormat)));
}

#[test]
fn test_mas09_compression_without_integrity_rejected() {
    let _config = shamir_share::Config::new().with_integrity_check(false);

    #[cfg(feature = "compress")]
    {
        let config_compressed = _config.with_compression(true);
        let res = ShamirShare::builder(3, 2)
            .with_config(config_compressed)
            .build();
        assert!(matches!(res, Err(ShamirError::InvalidConfig(_))));
    }

    #[cfg(not(feature = "compress"))]
    {
        // When compress feature is off, with_compression returns InvalidConfig
        let res = shamir_share::Config::new().with_compression(true);
        let res_build = ShamirShare::builder(3, 2).with_config(res).build();
        assert!(matches!(res_build, Err(ShamirError::InvalidConfig(_))));
    }
}

#[test]
fn test_mas10_file_share_store_symlink_base_dir_and_secure_delete() {
    let temp = tempdir().unwrap();
    let real_dir = temp.path().join("real_dir");
    std::fs::create_dir_all(&real_dir).unwrap();

    #[cfg(unix)]
    {
        let symlink_dir = temp.path().join("symlink_dir");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        // Initializing FileShareStore with a symlinked base_dir MUST be rejected
        let res = FileShareStore::new(&symlink_dir);
        assert!(matches!(res, Err(ShamirError::InvalidShareFormat)));
    }

    // Secure file overwrite on delete_share
    let mut store = FileShareStore::new(&real_dir).unwrap();
    let share = Share::new(1, vec![0xAA; 100], 2, 3, true, false);
    store.store_share(&share).unwrap();
    assert!(store.load_share(1).is_ok());

    // delete_share cleans up the file
    store.delete_share(1).unwrap();
    assert!(store.load_share(1).is_err());
}
