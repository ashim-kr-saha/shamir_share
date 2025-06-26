use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use shamir_share::ShamirShare;

fn bench_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("split");

    // Benchmark different data sizes
    for size in [1024, 10240, 102400].iter() {
        let data = vec![0u8; *size];
        let mut shamir = ShamirShare::new(5, 3).unwrap();

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
    let mut shamir = ShamirShare::new(5, 3).unwrap();

    // Benchmark different data sizes
    for size in [1024, 10240, 102400].iter() {
        let data = vec![0u8; *size];
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
    for size in [1024, 10240, 102400].iter() {
        let data = vec![0u8; *size];

        group.bench_function(format!("workflow_{}_bytes", size), |b| {
            b.iter(|| {
                let mut shamir = ShamirShare::new(5, 3).unwrap();
                let shares = shamir.split(black_box(&data)).unwrap();
                black_box(ShamirShare::reconstruct(&shares[0..3]).unwrap());
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_split, bench_reconstruct, bench_full_workflow);
criterion_main!(benches);
