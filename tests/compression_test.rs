#![cfg(feature = "compress")]

use shamir_share::{Config, ShamirShare};

#[test]
fn test_compression_e2e() {
    let config = Config::new().with_compression(true);
    let shamir = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();

    let secret = b"this is a test secret that should be compressed";
    let shares = shamir.split(secret).unwrap();

    let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
    assert_eq!(reconstructed.as_slice(), secret);
}

#[test]
fn test_highly_compressible_data() {
    let config = Config::new().with_compression(true);
    let shamir_compressed = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();

    let shamir_uncompressed = ShamirShare::builder(5, 3).build().unwrap();

    let secret = vec![0; 1024];
    let compressed_shares = shamir_compressed.split(&secret).unwrap();
    let uncompressed_shares = shamir_uncompressed.split(&secret).unwrap();

    assert!(
        compressed_shares[0].data.len() < uncompressed_shares[0].data.len(),
        "Compressed share should be smaller"
    );

    let reconstructed = ShamirShare::reconstruct(&compressed_shares[0..3]).unwrap();
    assert_eq!(reconstructed.as_slice(), secret.as_slice());
}

#[test]
fn test_incompressible_data() {
    let config = Config::new().with_compression(true);
    let shamir = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();

    let secret: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let shares = shamir.split(&secret).unwrap();

    let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
    assert_eq!(reconstructed.as_slice(), secret.as_slice());
}

#[test]
fn test_streaming_with_compression() {
    use std::io::Cursor;

    let config = Config::new().with_compression(true);
    let shamir = ShamirShare::builder(3, 2)
        .with_config(config)
        .build()
        .unwrap();

    let data = b"This is a test message for streaming with compression";
    let mut source = Cursor::new(data);

    let mut destinations = vec![Vec::new(); 3];
    let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
        .iter_mut()
        .map(|d| Cursor::new(std::mem::take(d)))
        .collect();

    shamir.split_stream(&mut source, &mut dest_cursors).unwrap();

    let share_data: Vec<Vec<u8>> = dest_cursors
        .into_iter()
        .map(|cursor| cursor.into_inner())
        .collect();

    let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..2]
        .iter()
        .map(|data| Cursor::new(data.clone()))
        .collect();
    let mut destination = Vec::new();
    let mut dest_cursor = Cursor::new(&mut destination);

    ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();

    assert_eq!(&destination, data);
}

#[test]
fn test_decompression_bomb_rejected() {
    use sha2::{Digest, Sha256};
    use shamir_share::{Config, ShamirError};

    // Create a payload that decompresses to > 64 MiB
    // 65 MiB of zeros compresses to under 100 KB with zstd
    let large_zeros = vec![0u8; 65 * 1024 * 1024];
    let compressed_bomb = zstd::encode_all(&large_zeros[..], 1).unwrap();

    let salt = [0u8; 32];
    let flags = 3u8; // integrity_check = true (1) | compression = true (2)
    let mut hasher = Sha256::new();
    hasher.update(b"SHS1_KEYED_V3\0");
    hasher.update([flags, 2, 3]);
    hasher.update(salt);
    hasher.update(&compressed_bomb);
    let hash = hasher.finalize();

    let mut raw_data = Vec::new();
    raw_data.extend_from_slice(&salt);
    raw_data.extend_from_slice(&hash);
    raw_data.extend_from_slice(&compressed_bomb);

    let raw_scheme = ShamirShare::builder(3, 2)
        .with_config(Config::new().with_integrity_check(false))
        .build()
        .unwrap();
    let mut bomb_shares = raw_scheme.split(&raw_data).unwrap();
    for s in &mut bomb_shares {
        s.integrity_check = true;
        s.compression = true;
    }

    // Reconstruction must verify hash, then reject payloads exceeding 64 MiB with DecompressionError
    let result = ShamirShare::reconstruct(&bomb_shares[0..2]);
    assert!(result.is_err());
    assert!(matches!(result, Err(ShamirError::DecompressionError(_))));
}
