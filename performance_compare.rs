use shamir_share::ShamirShare;
use std::time::Instant;

fn main() {
    println!("Performance Comparison - Shamir Secret Sharing");
    println!("=============================================");
    
    // Test different configurations
    let test_sizes = [1024, 10240, 102400];
    let iterations = 50;
    
    // Default configuration (5 shares, 3 threshold)
    println!("\nDefault Configuration (5 shares, 3 threshold):");
    test_threshold_configuration(5, 3, &test_sizes, iterations);
    
    // Different threshold configurations
    println!("\nLow Threshold (10 shares, 3 threshold):");
    test_threshold_configuration(10, 3, &test_sizes, iterations);
    
    println!("\nHigh Threshold (10 shares, 8 threshold):");
    test_threshold_configuration(10, 8, &test_sizes, iterations);
}

fn test_threshold_configuration(n: u8, k: u8, test_sizes: &[usize], iterations: u32) {
    for &size in test_sizes {
        println!("  Testing with {} bytes:", size);
        
        let data = vec![0x55u8; size];
        let mut total_split_time = 0u128;
        let mut total_reconstruct_time = 0u128;
        
        for _ in 0..iterations {
            // Test split performance
            let mut shamir = ShamirShare::new(n, k).unwrap();
            
            let start = Instant::now();
            let shares = shamir.split(&data).unwrap();
            total_split_time += start.elapsed().as_nanos();
            
            // Test reconstruct performance
            let start = Instant::now();
            let _reconstructed = ShamirShare::reconstruct(&shares[0..k as usize]).unwrap();
            total_reconstruct_time += start.elapsed().as_nanos();
        }
        
        let avg_split = total_split_time / iterations as u128;
        let avg_reconstruct = total_reconstruct_time / iterations as u128;
        
        println!("    Split:       {} us", avg_split / 1000);
        println!("    Reconstruct: {} us", avg_reconstruct / 1000);
        println!("    Total:       {} us", (avg_split + avg_reconstruct) / 1000);
    }
}