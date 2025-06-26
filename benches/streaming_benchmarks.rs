use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use shamir_share::{ShamirShare, Config};
use std::hint::black_box;
use std::io::Cursor;

/// Test data sizes for benchmarking
const DATA_SIZES: &[usize] = &[
    10 * 1024,   // 10KB
    100 * 1024,  // 100KB
    1024 * 1024, // 1MB
];

/// Creates mock data of the specified size
fn create_mock_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Benchmark split_stream performance across different data sizes
fn bench_split_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("split_stream");
    
    for &size in DATA_SIZES {
        let data = create_mock_data(size);
        
        group.bench_with_input(
            BenchmarkId::new("split_stream", format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    // Create a fresh scheme for each iteration
                    let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
                    
                    // Create source cursor
                    let mut source = Cursor::new(black_box(&data));
                    
                    // Create destination cursors
                    let mut destinations = vec![Vec::new(); 5];
                    let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
                        .iter_mut()
                        .map(|d| Cursor::new(std::mem::take(d)))
                        .collect();
                    
                    // Reset source position
                    source.set_position(0);
                    
                    // Perform the split operation
                    scheme.split_stream(
                        black_box(&mut source), 
                        black_box(&mut dest_cursors)
                    ).unwrap();
                    
                    // Black box the results to prevent optimization
                    black_box(dest_cursors);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark reconstruct_stream performance across different data sizes
fn bench_reconstruct_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconstruct_stream");
    
    for &size in DATA_SIZES {
        let data = create_mock_data(size);
        
        // Pre-generate share data for reconstruction benchmarks
        let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
        let mut source = Cursor::new(&data);
        let mut destinations = vec![Vec::new(); 5];
        let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
            .iter_mut()
            .map(|d| Cursor::new(std::mem::take(d)))
            .collect();
        
        scheme.split_stream(&mut source, &mut dest_cursors).unwrap();
        
        let share_data: Vec<Vec<u8>> = dest_cursors
            .into_iter()
            .map(|cursor| cursor.into_inner())
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("reconstruct_stream", format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    // Create source cursors from the first 3 shares (threshold = 3)
                    let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..3]
                        .iter()
                        .map(|data| Cursor::new(black_box(data.clone())))
                        .collect();
                    
                    // Reset positions of all source cursors
                    for source in &mut sources {
                        source.set_position(0);
                    }
                    
                    // Create destination cursor
                    let mut destination = Vec::new();
                    let mut dest_cursor = Cursor::new(&mut destination);
                    
                    // Perform the reconstruction
                    ShamirShare::reconstruct_stream(
                        black_box(&mut sources),
                        black_box(&mut dest_cursor)
                    ).unwrap();
                    
                    // Black box the result
                    black_box(destination);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark streaming vs in-memory comparison for medium data size
fn bench_streaming_vs_memory_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Streaming vs In-Memory Comparison");
    
    // Use 100KB as the medium test size
    let size = 100 * 1024;
    let data = create_mock_data(size);
    
    // Benchmark in-memory workflow
    group.bench_function("in_memory_workflow_100KB", |b| {
        b.iter(|| {
            // Create scheme
            let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
            
            // Split using in-memory method
            let shares = scheme.split(black_box(&data)).unwrap();
            
            // Reconstruct using in-memory method (first 3 shares)
            let reconstructed = ShamirShare::reconstruct(black_box(&shares[0..3])).unwrap();
            
            black_box(reconstructed);
        });
    });
    
    // Benchmark streaming workflow
    group.bench_function("streaming_workflow_100KB", |b| {
        b.iter(|| {
            // Create scheme
            let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
            
            // Split using streaming method
            let mut source = Cursor::new(black_box(&data));
            let mut destinations = vec![Vec::new(); 5];
            let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
                .iter_mut()
                .map(|d| Cursor::new(std::mem::take(d)))
                .collect();
            
            scheme.split_stream(&mut source, &mut dest_cursors).unwrap();
            
            let share_data: Vec<Vec<u8>> = dest_cursors
                .into_iter()
                .map(|cursor| cursor.into_inner())
                .collect();
            
            // Reconstruct using streaming method
            let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..3]
                .iter()
                .map(|data| Cursor::new(data.clone()))
                .collect();
            let mut destination = Vec::new();
            let mut dest_cursor = Cursor::new(&mut destination);
            
            ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();
            
            black_box(destination);
        });
    });
    
    group.finish();
}

/// Benchmark split_stream with different chunk sizes
fn bench_split_stream_chunk_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("split_stream_chunk_sizes");
    
    let size = 100 * 1024; // 100KB test data
    let data = create_mock_data(size);
    let chunk_sizes = &[1024, 4096, 16384, 65536]; // 1KB, 4KB, 16KB, 64KB
    
    for &chunk_size in chunk_sizes {
        group.bench_with_input(
            BenchmarkId::new("chunk_size", format!("{}_bytes", chunk_size)),
            &chunk_size,
            |b, _| {
                b.iter(|| {
                    // Create scheme with custom chunk size
                    let config = Config::new().with_chunk_size(chunk_size).unwrap();
                    let mut scheme = ShamirShare::builder(5, 3)
                        .with_config(config)
                        .build()
                        .unwrap();
                    
                    // Create source cursor
                    let mut source = Cursor::new(black_box(&data));
                    
                    // Create destination cursors
                    let mut destinations = vec![Vec::new(); 5];
                    let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
                        .iter_mut()
                        .map(|d| Cursor::new(std::mem::take(d)))
                        .collect();
                    
                    // Reset source position
                    source.set_position(0);
                    
                    // Perform the split operation
                    scheme.split_stream(
                        black_box(&mut source), 
                        black_box(&mut dest_cursors)
                    ).unwrap();
                    
                    black_box(dest_cursors);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark streaming with and without integrity checking
fn bench_streaming_integrity_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_integrity_check");
    
    let size = 100 * 1024; // 100KB test data
    let data = create_mock_data(size);
    
    // Benchmark with integrity check enabled (default)
    group.bench_function("with_integrity_check", |b| {
        b.iter(|| {
            let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
            
            let mut source = Cursor::new(black_box(&data));
            let mut destinations = vec![Vec::new(); 5];
            let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
                .iter_mut()
                .map(|d| Cursor::new(std::mem::take(d)))
                .collect();
            
            scheme.split_stream(&mut source, &mut dest_cursors).unwrap();
            
            let share_data: Vec<Vec<u8>> = dest_cursors
                .into_iter()
                .map(|cursor| cursor.into_inner())
                .collect();
            
            let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..3]
                .iter()
                .map(|data| Cursor::new(data.clone()))
                .collect();
            let mut destination = Vec::new();
            let mut dest_cursor = Cursor::new(&mut destination);
            
            ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();
            
            black_box(destination);
        });
    });
    
    // Benchmark with integrity check disabled
    group.bench_function("without_integrity_check", |b| {
        b.iter(|| {
            let config = Config::new().with_integrity_check(false);
            let mut scheme = ShamirShare::builder(5, 3)
                .with_config(config)
                .build()
                .unwrap();
            
            let mut source = Cursor::new(black_box(&data));
            let mut destinations = vec![Vec::new(); 5];
            let mut dest_cursors: Vec<Cursor<Vec<u8>>> = destinations
                .iter_mut()
                .map(|d| Cursor::new(std::mem::take(d)))
                .collect();
            
            scheme.split_stream(&mut source, &mut dest_cursors).unwrap();
            
            let share_data: Vec<Vec<u8>> = dest_cursors
                .into_iter()
                .map(|cursor| cursor.into_inner())
                .collect();
            
            let mut sources: Vec<Cursor<Vec<u8>>> = share_data[0..3]
                .iter()
                .map(|data| Cursor::new(data.clone()))
                .collect();
            let mut destination = Vec::new();
            let mut dest_cursor = Cursor::new(&mut destination);
            
            ShamirShare::reconstruct_stream(&mut sources, &mut dest_cursor).unwrap();
            
            black_box(destination);
        });
    });
    
    group.finish();
}

criterion_group!(
    streaming_benches,
    bench_split_stream,
    bench_reconstruct_stream,
    bench_streaming_vs_memory_comparison,
    bench_split_stream_chunk_sizes,
    bench_streaming_integrity_check
);
criterion_main!(streaming_benches);