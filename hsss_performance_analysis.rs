use shamir_share::ShamirShare;
use shamir_share::hsss::Hsss;
use std::time::Instant;

fn main() {
    println!("HSSS Performance Analysis");
    println!("========================");

    // Test different data sizes
    let test_sizes = [1024, 10 * 1024, 100 * 1024, 1024 * 1024]; // 1KB, 10KB, 100KB, 1MB
    let iterations = 50;

    println!(
        "\nTesting with {} iterations per configuration\n",
        iterations
    );

    for &size in &test_sizes {
        println!("Data size: {} KB", size / 1024);
        println!("-".repeat(40));

        let data = create_test_data(size);

        // Test simple HSSS configuration
        test_hsss_performance("Simple HSSS (3 levels)", &data, iterations, |threshold| {
            Hsss::builder(threshold)
                .add_level("President", threshold)
                .add_level("VP", threshold - 2)
                .add_level("Executive", 2)
                .build()
                .unwrap()
        });

        // Test more complex HSSS configuration
        test_hsss_performance("Complex HSSS (5 levels)", &data, iterations, |threshold| {
            Hsss::builder(threshold)
                .add_level("CEO", threshold)
                .add_level("CTO", threshold - 2)
                .add_level("CFO", threshold - 3)
                .build()
                .unwrap()
        });
        // Test HSSS with more levels
        test_hsss_performance("HSSS with 6 levels", &data, iterations, |threshold| {
            Hsss::builder(threshold)
                .add_level("Level1", threshold)
                .add_level("Level2", threshold - 1)
                .add_level("Level3", threshold - 2)
                .add_level("Level4", threshold - 3)
                .add_level("Level5", threshold - 4)
                .add_level("Level6", threshold - 5)
                .build()
                .unwrap()
        });
        // Test complex HSSS configuration
        test_hsss_performance("Complex HSSS (6 levels)", &data, iterations, |threshold| {
            Hsss::builder(threshold)
                .add_level("CEO", threshold)
                .add_level("CTO", threshold - 2)
                .add_level("VP_Engineering", threshold - 4)
                .add_level("Director", 4)
                .add_level("Manager", 3)
                .add_level("Employee", 2)
                .build()
                .unwrap()
        });

        // Test regular Shamir for comparison
        test_shamir_performance("Regular Shamir", &data, iterations);

        println!();
    }
}

fn create_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn test_hsss_performance<F>(name: &str, data: &[u8], iterations: u32, create_hsss: F)
where
    F: Fn(u8) -> Hsss,
{
    let threshold = 10;
    let mut total_split_time = 0u128;
    let mut total_reconstruct_time = 0u128;

    for _ in 0..iterations {
        // Test split performance
        let mut hsss = create_hsss(threshold);
        let start = Instant::now();
        let hierarchical_shares = hsss.split_secret(data).unwrap();
        total_split_time += start.elapsed().as_nanos();

        // Test reconstruct performance (using first level that has enough shares)
        let start = Instant::now();
        let _reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap();
        total_reconstruct_time += start.elapsed().as_nanos();
    }

    let avg_split = total_split_time / iterations as u128;
    let avg_reconstruct = total_reconstruct_time / iterations as u128;

    println!(
        "  {:<25} Split: {:>8} µs | Reconstruct: {:>8} µs | Total: {:>8} µs",
        name,
        avg_split / 1000,
        avg_reconstruct / 1000,
        (avg_split + avg_reconstruct) / 1000
    );
}

fn test_shamir_performance(name: &str, data: &[u8], iterations: u32) {
    let mut total_split_time = 0u128;
    let mut total_reconstruct_time = 0u128;

    for _ in 0..iterations {
        // Test split performance
        let mut shamir = ShamirShare::builder(15, 10).build().unwrap(); // Similar total shares as HSSS
        let start = Instant::now();
        let shares = shamir.split(data).unwrap();
        total_split_time += start.elapsed().as_nanos();

        // Test reconstruct performance
        let start = Instant::now();
        let _reconstructed = ShamirShare::reconstruct(&shares[0..10]).unwrap();
        total_reconstruct_time += start.elapsed().as_nanos();
    }

    let avg_split = total_split_time / iterations as u128;
    let avg_reconstruct = total_reconstruct_time / iterations as u128;

    println!(
        "  {:<25} Split: {:>8} µs | Reconstruct: {:>8} µs | Total: {:>8} µs",
        name,
        avg_split / 1000,
        avg_reconstruct / 1000,
        (avg_split + avg_reconstruct) / 1000
    );
}
