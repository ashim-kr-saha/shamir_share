use shamir_share::hsss::Hsss;
use std::time::Instant;

fn main() {
    // Test with a moderately large secret (10KB)
    let secret: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();
    
    println!("Testing HSSS performance with 10KB secret...");
    
    // Create a complex HSSS scheme
    let mut hsss = Hsss::builder(10)
        .add_level("CEO", 10)
        .add_level("CTO", 7)
        .add_level("VP", 5)
        .add_level("Director", 4)
        .add_level("Manager", 3)
        .add_level("Employee", 2)
        .build()
        .unwrap();
    
    // Measure split performance
    let start = Instant::now();
    let hierarchical_shares = hsss.split_secret(&secret).unwrap();
    let split_duration = start.elapsed();
    
    println!("Split time: {:?}", split_duration);
    println!("Generated {} hierarchical levels with {} total shares", 
             hierarchical_shares.len(),
             hierarchical_shares.iter().map(|h| h.shares.len()).sum::<usize>());
    
    // Test reconstruction
    let start = Instant::now();
    let reconstructed = hsss.reconstruct(&hierarchical_shares[0..1]).unwrap(); // CEO alone
    let reconstruct_duration = start.elapsed();
    
    println!("Reconstruct time: {:?}", reconstruct_duration);
    println!("Reconstruction successful: {}", reconstructed == secret);
}