use shamir_share::ShamirShare;
use std::time::Instant;

fn main() {
    println!("Performance Test - Optimized Shamir Secret Sharing");
    println!("==================================================");
    
    // Test different data sizes
    let test_sizes = [1024, 10240, 102400];
    let iterations = 100;
    
    for &size in &test_sizes {
        println!("\nTesting with {} bytes:", size);
        
        let data = vec![0x55u8; size];
        let mut total_split_time = 0u128;
        let mut total_reconstruct_time = 0u128;
        
        for _ in 0..iterations {
            // Test split performance
            let mut shamir = ShamirShare::new(5, 3).unwrap();
            let start = Instant::now();
            let shares = shamir.split(&data).unwrap();
            total_split_time += start.elapsed().as_nanos();
            
            // Test reconstruct performance
            let start = Instant::now();
            let _reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
            total_reconstruct_time += start.elapsed().as_nanos();
        }
        
        let avg_split = total_split_time / iterations as u128;
        let avg_reconstruct = total_reconstruct_time / iterations as u128;
        
        println!("  Split:       {} µs", avg_split / 1000);
        println!("  Reconstruct: {} µs", avg_reconstruct / 1000);
        println!("  Total:       {} µs", (avg_split + avg_reconstruct) / 1000);
    }
}