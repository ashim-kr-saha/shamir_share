use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use shamir_share::ShamirShare;

// Note: For streaming I/O benchmarks, see benches/streaming_benchmarks.rs
// For comprehensive benchmarks across data sizes, see benches/shamir_benchmarks.rs

fn benchmark_split(c: &mut Criterion) {
    // Initialize the scheme with many shares to stress the splitting routine
    let mut scheme = ShamirShare::builder(255, 3).build().unwrap();
    // Create a secret of 1024 bytes
    let secret = vec![0x55u8; 1024];
    c.bench_function("split 1024 bytes", |b| {
        b.iter(|| {
            let shares = scheme.split(black_box(&secret)).unwrap();
            black_box(shares);
        })
    });
}

fn benchmark_reconstruct(c: &mut Criterion) {
    let mut scheme = ShamirShare::builder(5, 3).build().unwrap();
    let secret = b"my secret data";
    let shares = scheme.split(secret).unwrap();
    c.bench_function("reconstruct secret", |b| {
        b.iter(|| {
            let result = ShamirShare::reconstruct(black_box(&shares)).unwrap();
            black_box(result);
        })
    });
}

criterion_group!(benches, benchmark_split, benchmark_reconstruct);
criterion_main!(benches);
