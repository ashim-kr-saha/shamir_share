use shamir_share::{ShamirShare, Config, ShamirError};
use std::io::Cursor;

#[test]
fn test_streaming_with_empty_source() {
    // Test streaming with a 0-byte input. The reconstructed output should also be 0 bytes.
    let mut scheme = ShamirShare::builder(3, 2).build().unwrap();
    
    // Create empty source data
    let source_data = Vec::new();
    let mut source = Cursor::new(source_data.clone());
    
    // Create share writers
    let mut share_writers: Vec<_> = (0..3)
        .map(|_| Cursor::new(Vec::new()))
        .collect();
    
    // Split the empty stream
    scheme.split_stream(&mut source, &mut share_writers).unwrap();
    
    // Convert to readers
    let mut share_readers: Vec<_> = share_writers
        .into_iter()
        .map(|c| Cursor::new(c.into_inner()))
        .collect();
    
    // Reconstruct
    let mut reconstructed_writer = Cursor::new(Vec::new());
    ShamirShare::reconstruct_stream(&mut share_readers, &mut reconstructed_writer).unwrap();
    
    // Assert empty output
    let reconstructed_data = reconstructed_writer.into_inner();
    assert_eq!(source_data, reconstructed_data);
    assert_eq!(reconstructed_data.len(), 0);
}

#[test]
fn test_streaming_with_data_smaller_than_chunk_size() {
    // Configure the scheme with a chunk_size of 1024. Test with a 100-byte secret.
    let config = Config::new().with_chunk_size(1024).unwrap();
    let mut scheme = ShamirShare::builder(3, 2)
        .with_config(config)
        .build()
        .unwrap();
    
    // Create 100-byte source data (smaller than chunk size of 1024)
    let source_data: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
    let mut source = Cursor::new(source_data.clone());
    
    // Create share writers
    let mut share_writers: Vec<_> = (0..3)
        .map(|_| Cursor::new(Vec::new()))
        .collect();
    
    // Split the stream
    scheme.split_stream(&mut source, &mut share_writers).unwrap();
    
    // Convert to readers
    let mut share_readers: Vec<_> = share_writers
        .into_iter()
        .map(|c| Cursor::new(c.into_inner()))
        .collect();
    
    // Reconstruct
    let mut reconstructed_writer = Cursor::new(Vec::new());
    ShamirShare::reconstruct_stream(&mut share_readers, &mut reconstructed_writer).unwrap();
    
    // Verify successful reconstruction
    assert_eq!(source_data, reconstructed_writer.into_inner());
}

#[test]
fn test_streaming_with_non_aligned_data() {
    // Configure with chunk_size of 128. Test with a 300-byte secret (not a multiple of 128).
    let config = Config::new().with_chunk_size(128).unwrap();
    let mut scheme = ShamirShare::builder(3, 2)
        .with_config(config)
        .build()
        .unwrap();
    
    // Create 300-byte source data (not aligned to 128-byte chunks: 300 = 128 + 128 + 44)
    let source_data: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
    let mut source = Cursor::new(source_data.clone());
    
    // Create share writers
    let mut share_writers: Vec<_> = (0..3)
        .map(|_| Cursor::new(Vec::new()))
        .collect();
    
    // Split the stream
    scheme.split_stream(&mut source, &mut share_writers).unwrap();
    
    // Convert to readers
    let mut share_readers: Vec<_> = share_writers
        .into_iter()
        .map(|c| Cursor::new(c.into_inner()))
        .collect();
    
    // Reconstruct
    let mut reconstructed_writer = Cursor::new(Vec::new());
    ShamirShare::reconstruct_stream(&mut share_readers, &mut reconstructed_writer).unwrap();
    
    // Verify successful reconstruction
    assert_eq!(source_data, reconstructed_writer.into_inner());
}

#[test]
fn test_streaming_integrity_check_failure() {
    // Perform a split_stream, corrupt a byte, and expect IntegrityCheckFailed error
    let mut scheme = ShamirShare::builder(3, 2).build().unwrap();
    
    // Create test data
    let source_data = vec![42u8; 100];
    let mut source = Cursor::new(source_data.clone());
    
    // Create share writers
    let mut share_writers: Vec<_> = (0..3)
        .map(|_| Cursor::new(Vec::new()))
        .collect();
    
    // Split the stream
    scheme.split_stream(&mut source, &mut share_writers).unwrap();
    
    // Get the inner Vec<u8> from one of the resulting share cursors and corrupt it
    let mut share_data: Vec<Vec<u8>> = share_writers
        .into_iter()
        .map(|c| c.into_inner())
        .collect();
    
    // Corrupt a byte in the first share (skip header bytes and corrupt data)
    if share_data[0].len() > 10 {
        share_data[0][10] ^= 0xFF;
    }
    
    // Convert corrupted data back to readers
    let mut share_readers: Vec<_> = share_data
        .into_iter()
        .map(|data| Cursor::new(data))
        .collect();
    
    // Attempt to reconstruct with the tampered share
    let mut reconstructed_writer = Cursor::new(Vec::new());
    let result = ShamirShare::reconstruct_stream(&mut share_readers, &mut reconstructed_writer);
    
    // Assert that the result is Err(ShamirError::IntegrityCheckFailed)
    assert!(matches!(result, Err(ShamirError::IntegrityCheckFailed)));
}

#[test]
fn test_split_stream_insufficient_destinations_error() {
    // Create a ShamirShare instance for 5 shares, but provide only 4 destinations
    let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
    
    // Create test data
    let source_data = vec![1, 2, 3, 4, 5];
    let mut source = Cursor::new(source_data);
    
    // Create destinations vector with only 4 writers (insufficient for 5 shares)
    let mut destinations: Vec<_> = (0..4)
        .map(|_| Cursor::new(Vec::new()))
        .collect();
    
    // Assert that calling split_stream returns an error
    let result = scheme.split_stream(&mut source, &mut destinations);
    assert!(result.is_err());
    
    // More specifically, it should be an InvalidConfig error
    assert!(matches!(result, Err(ShamirError::InvalidConfig(_))));
}