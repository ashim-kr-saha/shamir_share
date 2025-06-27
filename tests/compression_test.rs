#![cfg(feature = "compress")]

use shamir_share::{Config, ShamirShare};

#[test]
fn test_compression_e2e() {
    let config = Config::new().with_compression(true);
    let mut shamir = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();

    let secret = b"this is a test secret that should be compressed";
    let shares = shamir.split(secret).unwrap();

    let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_highly_compressible_data() {
    let config = Config::new().with_compression(true);
    let mut shamir_compressed = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();

    let mut shamir_uncompressed = ShamirShare::builder(5, 3).build().unwrap();

    let secret = vec![0; 1024];
    let compressed_shares = shamir_compressed.split(&secret).unwrap();
    let uncompressed_shares = shamir_uncompressed.split(&secret).unwrap();

    assert!(
        compressed_shares[0].data.len() < uncompressed_shares[0].data.len(),
        "Compressed share should be smaller"
    );

    let reconstructed = ShamirShare::reconstruct(&compressed_shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_incompressible_data() {
    let config = Config::new().with_compression(true);
    let mut shamir = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();

    let secret: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
    let shares = shamir.split(&secret).unwrap();

    let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_streaming_with_compression() {
    use std::io::Cursor;

    let config = Config::new().with_compression(true);
    let mut shamir = ShamirShare::builder(3, 2)
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
