use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use shamir_share::hsss::Hsss;
use std::hint::black_box;

/// Test data sizes for HSSS benchmarking
const DATA_SIZES: &[usize] = &[
    1024,            // 1KB
    10 * 1024,       // 10KB
    100 * 1024,      // 100KB
];

/// Creates mock data of the specified size
fn create_mock_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Benchmark HSSS split_secret performance with simple scheme
fn bench_hsss_split_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("HSSS Split Simple");

    for &size in DATA_SIZES {
        let data = create_mock_data(size);

        group.bench_with_input(
            BenchmarkId::new("simple_scheme", format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    // Create a simple HSSS scheme: k=5, 3 levels
                    let mut hsss = Hsss::builder(5)
                        .add_level("President", 5)
                        .add_level("VP", 3)
                        .add_level("Executive", 2)
                        .build()
                        .unwrap();

                    // Perform the split operation
                    let hierarchical_shares = hsss.split_secret(black_box(&data)).unwrap();

                    // Black box the results to prevent optimization
                    black_box(hierarchical_shares);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark HSSS split_secret performance with complex scheme
fn bench_hsss_split_complex(c: &mut Criterion) {
    let mut group = c.benchmark_group("HSSS Split Complex");

    for &size in DATA_SIZES {
        let data = create_mock_data(size);

        group.bench_with_input(
            BenchmarkId::new("complex_scheme", format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    // Create a complex HSSS scheme: k=10, 10 levels
                    let mut hsss = Hsss::builder(10)
                        .add_level("CEO", 10)
                        .add_level("CTO", 8)
                        .add_level("CFO", 8)
                        .add_level("VP_Engineering", 6)
                        .add_level("VP_Sales", 6)
                        .add_level("Director", 4)
                        .add_level("Senior_Manager", 3)
                        .add_level("Manager", 2)
                        .add_level("Team_Lead", 2)
                        .add_level("Employee", 1)
                        .build()
                        .unwrap();

                    // Perform the split operation
                    let hierarchical_shares = hsss.split_secret(black_box(&data)).unwrap();

                    // Black box the results to prevent optimization
                    black_box(hierarchical_shares);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark HSSS reconstruct performance with simple scheme
fn bench_hsss_reconstruct_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("HSSS Reconstruct Simple");

    for &size in DATA_SIZES {
        let data = create_mock_data(size);

        // Pre-generate hierarchical shares for reconstruction benchmarks
        let mut hsss = Hsss::builder(5)
            .add_level("President", 5)
            .add_level("VP", 3)
            .add_level("Executive", 2)
            .build()
            .unwrap();

        let hierarchical_shares = hsss.split_secret(&data).unwrap();

        group.bench_with_input(
            BenchmarkId::new("simple_scheme", format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    // Reconstruct using President shares (5 shares >= threshold of 5)
                    let reconstructed = hsss
                        .reconstruct(black_box(&hierarchical_shares[0..1]))
                        .unwrap();

                    // Black box the result to prevent optimization
                    black_box(reconstructed);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark HSSS reconstruct performance with complex scheme
fn bench_hsss_reconstruct_complex(c: &mut Criterion) {
    let mut group = c.benchmark_group("HSSS Reconstruct Complex");

    for &size in DATA_SIZES {
        let data = create_mock_data(size);

        // Pre-generate hierarchical shares for reconstruction benchmarks
        let mut hsss = Hsss::builder(10)
            .add_level("CEO", 10)
            .add_level("CTO", 8)
            .add_level("CFO", 8)
            .add_level("VP_Engineering", 6)
            .add_level("VP_Sales", 6)
            .add_level("Director", 4)
            .add_level("Senior_Manager", 3)
            .add_level("Manager", 2)
            .add_level("Team_Lead", 2)
            .add_level("Employee", 1)
            .build()
            .unwrap();

        let hierarchical_shares = hsss.split_secret(&data).unwrap();

        group.bench_with_input(
            BenchmarkId::new("complex_scheme", format!("{}_bytes", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    // Reconstruct using CEO shares (10 shares >= threshold of 10)
                    let reconstructed = hsss
                        .reconstruct(black_box(&hierarchical_shares[0..1]))
                        .unwrap();

                    // Black box the result to prevent optimization
                    black_box(reconstructed);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark HSSS reconstruct with different collaboration scenarios
fn bench_hsss_reconstruct_collaboration(c: &mut Criterion) {
    let mut group = c.benchmark_group("HSSS Reconstruct Collaboration");

    let size = 1024; // 1KB test data
    let data = create_mock_data(size);

    // Pre-generate hierarchical shares
    let mut hsss = Hsss::builder(5)
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Executive", 2)
        .build()
        .unwrap();

    let hierarchical_shares = hsss.split_secret(&data).unwrap();

    // Benchmark President alone (5 shares)
    group.bench_function("president_alone", |b| {
        b.iter(|| {
            let reconstructed = hsss
                .reconstruct(black_box(&hierarchical_shares[0..1]))
                .unwrap();
            black_box(reconstructed);
        });
    });

    // Benchmark VP + Executive collaboration (3 + 2 = 5 shares)
    group.bench_function("vp_executive_collaboration", |b| {
        b.iter(|| {
            let reconstructed = hsss
                .reconstruct(black_box(&hierarchical_shares[1..3]))
                .unwrap();
            black_box(reconstructed);
        });
    });

    // Benchmark all levels together (5 + 3 + 2 = 10 shares)
    group.bench_function("all_levels_together", |b| {
        b.iter(|| {
            let reconstructed = hsss.reconstruct(black_box(&hierarchical_shares)).unwrap();
            black_box(reconstructed);
        });
    });

    group.finish();
}

/// Benchmark HSSS vs regular Shamir comparison
fn bench_hsss_vs_shamir_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("HSSS vs Shamir Comparison");

    let size = 1024; // 1KB test data
    let data = create_mock_data(size);

    // Benchmark regular Shamir workflow
    group.bench_function("regular_shamir_1KB", |b| {
        b.iter(|| {
            use shamir_share::ShamirShare;

            // Create regular Shamir scheme (5 shares, threshold 3)
            let mut scheme = ShamirShare::builder(5, 3).build().unwrap();

            // Split using regular Shamir
            let shares = scheme.split(black_box(&data)).unwrap();

            // Reconstruct using regular Shamir (first 3 shares)
            let reconstructed = ShamirShare::reconstruct(black_box(&shares[0..3])).unwrap();

            black_box(reconstructed);
        });
    });

    // Benchmark HSSS workflow
    group.bench_function("hsss_workflow_1KB", |b| {
        b.iter(|| {
            // Create HSSS scheme with equivalent complexity
            let mut hsss = Hsss::builder(3)
                .add_level("Admin", 3)
                .add_level("User", 2)
                .build()
                .unwrap();

            // Split using HSSS
            let hierarchical_shares = hsss.split_secret(black_box(&data)).unwrap();

            // Reconstruct using HSSS (Admin level has 3 shares >= threshold of 3)
            let reconstructed = hsss
                .reconstruct(black_box(&hierarchical_shares[0..1]))
                .unwrap();

            black_box(reconstructed);
        });
    });

    group.finish();
}

/// Benchmark HSSS scheme creation overhead
fn bench_hsss_scheme_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("HSSS Scheme Creation");

    // Benchmark simple scheme creation
    group.bench_function("simple_scheme_creation", |b| {
        b.iter(|| {
            let hsss = Hsss::builder(5)
                .add_level("President", 5)
                .add_level("VP", 3)
                .add_level("Executive", 2)
                .build()
                .unwrap();

            black_box(hsss);
        });
    });

    // Benchmark complex scheme creation
    group.bench_function("complex_scheme_creation", |b| {
        b.iter(|| {
            let hsss = Hsss::builder(10)
                .add_level("CEO", 10)
                .add_level("CTO", 8)
                .add_level("CFO", 8)
                .add_level("VP_Engineering", 6)
                .add_level("VP_Sales", 6)
                .add_level("Director", 4)
                .add_level("Senior_Manager", 3)
                .add_level("Manager", 2)
                .add_level("Team_Lead", 2)
                .add_level("Employee", 1)
                .build()
                .unwrap();

            black_box(hsss);
        });
    });

    group.finish();
}

/// Benchmark HSSS split_secret performance with large secrets and complex hierarchy
fn bench_hsss_split_large_secrets(c: &mut Criterion) {
    let mut group = c.benchmark_group("HSSS Split Large Secrets");
    
    // Test with a large secret (100KB) and complex hierarchy
    let data = create_mock_data(100 * 1024);
    
    group.bench_function("complex_hierarchy_100KB", |b| {
        b.iter(|| {
            // Create a complex HSSS scheme: k=10, 6 levels with varying share counts
            let mut hsss = Hsss::builder(10)
                .add_level("CEO", 10)
                .add_level("CTO", 7)
                .add_level("VP", 5)
                .add_level("Director", 4)
                .add_level("Manager", 3)
                .add_level("Employee", 2)
                .build()
                .unwrap();
            
            let hierarchical_shares = hsss.split_secret(black_box(&data)).unwrap();
            black_box(hierarchical_shares);
        });
    });
    
    group.finish();
}

criterion_group!(
    hsss_benches,
    bench_hsss_split_simple,
    bench_hsss_split_complex,
    bench_hsss_split_large_secrets,
    bench_hsss_reconstruct_simple,
    bench_hsss_reconstruct_complex,
    bench_hsss_reconstruct_collaboration,
    bench_hsss_vs_shamir_comparison,
    bench_hsss_scheme_creation
);
criterion_main!(hsss_benches);
