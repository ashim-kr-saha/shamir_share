use shamir_share::ShamirShare;

fn main() {
    println!("=== Shamir Share Dealer Demo ===\n");

    let mut shamir = ShamirShare::builder(10, 5).build().unwrap();
    let secret = b"This is a secret message that demonstrates the new dealer API!";

    println!("Secret: {:?}", std::str::from_utf8(secret).unwrap());
    println!("Configuration: 10 total shares, threshold of 5\n");

    // Demo 1: Generate only the shares we need
    println!("Demo 1: Generate only 5 shares (threshold)");
    let shares: Vec<_> = shamir.dealer(secret).take(5).collect();
    println!(
        "Generated {} shares with indices: {:?}",
        shares.len(),
        shares.iter().map(|s| s.index).collect::<Vec<_>>()
    );

    // Verify reconstruction
    let reconstructed = ShamirShare::reconstruct(&shares).unwrap();
    println!("Reconstruction successful: {}", reconstructed == secret);
    println!();

    // Demo 2: Lazy evaluation - generate shares one by one
    println!("Demo 2: Lazy evaluation - generate shares one by one");
    let mut dealer = shamir.dealer(secret);
    for _i in 1..=3 {
        if let Some(share) = dealer.next() {
            println!(
                "Generated share {} with {} bytes of data",
                share.index,
                share.data.len()
            );
        }
    }
    println!("Remaining shares available: {}", dealer.len());
    println!();

    // Demo 3: Use iterator methods for filtering
    println!("Demo 3: Filter shares using iterator methods");
    let even_shares: Vec<_> = shamir
        .dealer(secret)
        .filter(|share| share.index % 2 == 0)
        .take(5)
        .collect();

    println!(
        "Generated {} even-indexed shares: {:?}",
        even_shares.len(),
        even_shares.iter().map(|s| s.index).collect::<Vec<_>>()
    );

    // Verify reconstruction with filtered shares
    let reconstructed = ShamirShare::reconstruct(&even_shares).unwrap();
    println!(
        "Reconstruction with even shares successful: {}",
        reconstructed == secret
    );
    println!();

    // Demo 4: Compare with traditional split method
    println!("Demo 4: Compare dealer vs split method");
    let split_shares = shamir.split(secret).unwrap();
    let dealer_shares: Vec<_> = shamir.dealer(secret).take(10).collect();

    println!("Split method generated: {} shares", split_shares.len());
    println!("Dealer method generated: {} shares", dealer_shares.len());

    // Both should reconstruct to the same secret
    let reconstructed_split = ShamirShare::reconstruct(&split_shares[0..5]).unwrap();
    let reconstructed_dealer = ShamirShare::reconstruct(&dealer_shares[0..5]).unwrap();

    println!(
        "Both methods produce equivalent results: {}",
        reconstructed_split == reconstructed_dealer && reconstructed_split == secret
    );
    println!();

    println!("=== Demo Complete ===");
}
