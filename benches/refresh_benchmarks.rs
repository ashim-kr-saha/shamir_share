use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use shamir_share::ShamirShare;
use std::hint::black_box;

/// Test share counts for benchmarking refresh_shares performance
const SHARE_COUNTS: &[usize] = &[10, 50, 100, 200];

/// Creates a test secret of reasonable size for benchmarking
fn create_test_secret() -> Vec<u8> {
    // Use a 1KB secret for consistent benchmarking
    (0..1024).map(|i| (i % 256) as u8).collect()
}

/// Benchmark refresh_shares performance across different numbers of shares
fn bench_refresh_shares(c: &mut Criterion) {
    let mut group = c.benchmark_group("refresh_shares");

    for &share_count in SHARE_COUNTS {
        let secret = create_test_secret();
        
        // Create shares to refresh (using threshold = share_count for maximum work)
        let mut shamir = ShamirShare::builder(share_count as u8, share_count as u8).build().unwrap();
        let shares = shamir.split(&secret).unwrap();

        group.bench_with_input(
            BenchmarkId::new("refresh_shares", format!("{}_shares", share_count)),
            &share_count,
            |b, _| {
                b.iter(|| {
                    let refreshed = black_box(shamir.refresh_shares(&shares).unwrap());
                    black_box(refreshed);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark refresh_shares with varying data sizes (fixed share count)
fn bench_refresh_shares_data_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("refresh_shares_data_size");
    
    // Use fixed share count but vary data size
    const SHARE_COUNT: u8 = 50;
    const DATA_SIZES: &[usize] = &[256, 1024, 4096, 16384]; // 256B to 16KB

    for &data_size in DATA_SIZES {
        let secret: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();
        
        let mut shamir = ShamirShare::builder(SHARE_COUNT, SHARE_COUNT).build().unwrap();
        let shares = shamir.split(&secret).unwrap();

        group.bench_with_input(
            BenchmarkId::new("refresh_shares_data_size", format!("{}_bytes", data_size)),
            &data_size,
            |b, _| {
                b.iter(|| {
                    let refreshed = black_box(shamir.refresh_shares(&shares).unwrap());
                    black_box(refreshed);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark to compare refresh_shares vs split performance
fn bench_refresh_vs_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("refresh_vs_split");
    
    const SHARE_COUNT: u8 = 100;
    let secret = create_test_secret();
    
    let mut shamir = ShamirShare::builder(SHARE_COUNT, SHARE_COUNT).build().unwrap();
    let shares = shamir.split(&secret).unwrap();

    group.bench_function("split_100_shares", |b| {
        b.iter(|| {
            let new_shares = black_box(shamir.split(&secret).unwrap());
            black_box(new_shares);
        });
    });

    group.bench_function("refresh_100_shares", |b| {
        b.iter(|| {
            let refreshed = black_box(shamir.refresh_shares(&shares).unwrap());
            black_box(refreshed);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_refresh_shares,
    bench_refresh_shares_data_size,
    bench_refresh_vs_split
);
criterion_main!(benches);