use shamir_share::ShamirShare;
use std::io::Cursor;

#[test]
fn test_streaming_end_to_end() {
    // Setup
    let total_shares = 5;
    let threshold = 3;

    // Create a ShamirShare instance
    let mut scheme = ShamirShare::builder(total_shares, threshold)
        .build()
        .unwrap();

    // Create mock source data: 5KB vector with pattern [1, 2, 3, 4, 5] repeated
    let source_data = vec![1, 2, 3, 4, 5].repeat(1024); // This creates a 5KB vector
    let mut source = Cursor::new(source_data.clone());

    // Split Stream
    // Create a vector of writable cursors for the shares
    let mut share_writers: Vec<_> = (0..total_shares).map(|_| Cursor::new(Vec::new())).collect();

    // Call split_stream
    scheme
        .split_stream(&mut source, &mut share_writers)
        .unwrap();

    // Prepare for Reconstruction
    // Convert the share writers into share readers
    let mut share_readers: Vec<_> = share_writers
        .into_iter()
        .map(|c| Cursor::new(c.into_inner()))
        .collect();

    // Reconstruct Stream
    // Create a final destination writer
    let mut reconstructed_writer = Cursor::new(Vec::new());

    // Call reconstruct_stream
    ShamirShare::reconstruct_stream(&mut share_readers, &mut reconstructed_writer).unwrap();

    // Assert
    // Compare the original source_data with the data in the reconstructed_writer
    assert_eq!(source_data, reconstructed_writer.into_inner());
}
