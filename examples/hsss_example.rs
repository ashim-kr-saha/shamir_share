use shamir_share::hsss::Hsss;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an HSSS scheme with master threshold of 5
    let mut hsss = Hsss::builder(5)
        .add_level("President", 5)    // President gets 5 shares (can reconstruct alone)
        .add_level("VP", 3)           // VP gets 3 shares
        .add_level("Executive", 2)    // Executive gets 2 shares
        .build()?;

    let secret = b"Top secret company information";
    println!("Original secret: {:?}", std::str::from_utf8(secret).unwrap());

    // Split the secret into hierarchical shares
    let hierarchical_shares = hsss.split_secret(secret)?;
    
    println!("\nHierarchical shares created:");
    for (i, share) in hierarchical_shares.iter().enumerate() {
        println!("  {}: {} shares for level '{}'", 
                 i, share.shares.len(), share.level_name);
    }

    // Scenario 1: President reconstructs alone
    println!("\n--- Scenario 1: President alone ---");
    let reconstructed = hsss.reconstruct(&hierarchical_shares[0..1])?;
    println!("Reconstructed: {:?}", std::str::from_utf8(&reconstructed).unwrap());
    assert_eq!(reconstructed, secret);

    // Scenario 2: VP and Executive collaborate
    println!("\n--- Scenario 2: VP + Executive ---");
    let reconstructed = hsss.reconstruct(&hierarchical_shares[1..3])?;
    println!("Reconstructed: {:?}", std::str::from_utf8(&reconstructed).unwrap());
    assert_eq!(reconstructed, secret);

    // Scenario 3: VP alone (should fail)
    println!("\n--- Scenario 3: VP alone (should fail) ---");
    match hsss.reconstruct(&hierarchical_shares[1..2]) {
        Ok(_) => println!("ERROR: VP should not be able to reconstruct alone!"),
        Err(e) => println!("Expected failure: {}", e),
    }

    println!("\nAll scenarios completed successfully!");
    Ok(())
}