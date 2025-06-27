use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use shamir_share::ShamirShare;

/// Test data sizes for HSSS benchmarking
const DATA_SIZES: &[usize] = &[
    1024,            // 1KB
    10 * 1024,       // 10KB
    100 * 1024,      // 100KB
    1 * 1024 * 1024, // 1MB
];

/// Creates mock data of the specified size
fn create_mock_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn bench_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("split");

    // Benchmark different data sizes
    for size in DATA_SIZES.iter() {
        let data = create_mock_data(*size);
        let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

        group.bench_function(format!("split_{}_bytes", size), |b| {
            b.iter(|| {
                black_box(shamir.split(black_box(&data)).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_reconstruct(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconstruct");
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

    // Benchmark different data sizes
    for size in DATA_SIZES.iter() {
        let data = create_mock_data(*size);
        let shares = shamir.split(&data).unwrap();

        group.bench_function(format!("reconstruct_{}_bytes", size), |b| {
            b.iter(|| {
                black_box(ShamirShare::reconstruct(black_box(&shares[0..3])).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_full_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_workflow");

    // Benchmark complete workflow with different data sizes
    for size in DATA_SIZES.iter() {
        let data = create_mock_data(*size);

        group.bench_function(format!("workflow_{}_bytes", size), |b| {
            b.iter(|| {
                let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
                let shares = shamir.split(black_box(&data)).unwrap();
                black_box(ShamirShare::reconstruct(&shares[0..3]).unwrap());
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_split, bench_reconstruct, bench_full_workflow);
criterion_main!(benches);
