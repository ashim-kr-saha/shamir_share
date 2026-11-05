use shamir_share::hsss::Hsss;
use std::time::Instant;

fn main() {
    println!("=== HSSS Performance Test - Optimized Version ===");

    // Test different data sizes
    let test_sizes = [1024, 10 * 1024, 100 * 1024]; // 1KB, 10KB, 100KB
    let iterations = 20;

    for &size in &test_sizes {
        println!("\nTesting with {} KB:", size / 1024);
        println!("{}", "-".repeat(50));

        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // Simple HSSS configuration
        let mut total_split_time = 0u128;
        let mut total_reconstruct_time = 0u128;

        for _ in 0..iterations {
            let mut hsss = Hsss::builder(5)
                .add_level("President", 5)
                .add_level("VP", 3)
                .add_level("Executive", 2)
                .build()
                .unwrap();

            // Test split performance
            let start = Instant::now();
            let hierarchical_shares = hsss.split_secret(&data).unwrap();
            total_split_time += start.elapsed().as_nanos();

            // Test reconstruct performance (using first level that has enough shares)
            let start = Instant::now();
            let _reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap();
            total_reconstruct_time += start.elapsed().as_nanos();
        }

        let avg_split = total_split_time / iterations as u128;
        let avg_reconstruct = total_reconstruct_time / iterations as u128;

        println!("  Split:       {:>8.2} ms", avg_split as f64 / 1_000_000.0);
        println!(
            "  Reconstruct: {:>8.2} ms",
            avg_reconstruct as f64 / 1_000_000.0
        );
        println!(
            "  Total:       {:>8.2} ms",
            (avg_split + avg_reconstruct) as f64 / 1_000_000.0
        );
    }

    // Complex HSSS configuration
    println!("\n=== Complex HSSS Configuration ===");
    let data: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect(); // 10KB
    let iterations = 10;

    let mut total_split_time = 0u128;
    let mut total_reconstruct_time = 0u128;

    for _ in 0..iterations {
        let mut hsss = Hsss::builder(10)
            .add_level("CEO", 10)
            .add_level("CTO", 8)
            .add_level("CFO", 8)
            .add_level("VP_Engineering", 6)
            .add_level("VP_Sales", 6)
            .add_level("Director", 4)
            .build()
            .unwrap();

        // Test split performance
        let start = Instant::now();
        let hierarchical_shares = hsss.split_secret(&data).unwrap();
        total_split_time += start.elapsed().as_nanos();

        // Test reconstruct performance
        let start = Instant::now();
        let _reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap();
        total_reconstruct_time += start.elapsed().as_nanos();
    }

    let avg_split = total_split_time / iterations as u128;
    let avg_reconstruct = total_reconstruct_time / iterations as u128;

    println!("Complex (42 total shares):");
    println!("  Split:       {:>8.2} ms", avg_split as f64 / 1_000_000.0);
    println!(
        "  Reconstruct: {:>8.2} ms",
        avg_reconstruct as f64 / 1_000_000.0
    );
    println!(
        "  Total:       {:>8.2} ms",
        (avg_split + avg_reconstruct) as f64 / 1_000_000.0
    );

    println!("\n=== Performance Optimization Complete ===");
}
