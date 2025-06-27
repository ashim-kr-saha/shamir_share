use shamir_share::{Config, ShamirShare, ShamirError};

#[test]
fn test_refreshed_shares_reconstruct_correctly() {
    // Create a ShamirShare instance with threshold 3 out of 5 shares
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
    
    // Define a test secret
    let secret = b"This is a secret message that should be preserved after refreshing";
    
    // Split the secret into initial shares
    let original_shares = shamir.split(secret).unwrap();
    
    // Refresh the shares using a valid subset (we need at least threshold shares)
    let refreshed_shares = shamir.refresh_shares(&original_shares[0..3]).unwrap();
    
    // Take a valid subset of the refreshed shares and reconstruct
    let reconstructed_secret = ShamirShare::reconstruct(&refreshed_shares[0..3]).unwrap();
    
    // Assert that the reconstructed secret is identical to the original
    assert_eq!(&reconstructed_secret, secret);
}

#[test]
fn test_refreshed_shares_are_different_from_original() {
    // Create a ShamirShare instance
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
    
    // Define a test secret
    let secret = b"Different data test";
    
    // Split the secret into initial shares
    let original_shares = shamir.split(secret).unwrap();
    
    // Refresh the shares
    let refreshed_shares = shamir.refresh_shares(&original_shares[0..3]).unwrap();
    
    // Assert that the data field of the first original share is not equal to 
    // the data field of the first refreshed share
    assert_ne!(original_shares[0].data, refreshed_shares[0].data);
    
    // Also verify that all corresponding shares have different data
    for i in 0..3 {
        assert_ne!(original_shares[i].data, refreshed_shares[i].data);
    }
    
    // But verify that metadata is preserved
    for i in 0..3 {
        assert_eq!(original_shares[i].index, refreshed_shares[i].index);
        assert_eq!(original_shares[i].threshold, refreshed_shares[i].threshold);
        assert_eq!(original_shares[i].total_shares, refreshed_shares[i].total_shares);
        assert_eq!(original_shares[i].integrity_check, refreshed_shares[i].integrity_check);
    }
}

#[test]
fn test_mixing_old_and_new_shares_fails_reconstruction() {
    // Create a ShamirShare instance with integrity checking enabled (default)
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
    
    // Define a test secret
    let secret = b"Mixed shares should fail";
    
    // Split the secret into initial shares (shares_v1)
    let shares_v1 = shamir.split(secret).unwrap();
    
    // Refresh them to get new shares (shares_v2)
    let shares_v2 = shamir.refresh_shares(&shares_v1[0..3]).unwrap();
    
    // Create a mixed set of shares: two from v1 and one from v2
    let mixed_shares = vec![
        shares_v1[0].clone(),  // Old share
        shares_v1[1].clone(),  // Old share
        shares_v2[2].clone(),  // New share
    ];
    
    // Attempt to reconstruct from the mixed set
    let result = ShamirShare::reconstruct(&mixed_shares);
    
    // Assert that reconstruction fails
    assert!(result.is_err());
    
    // With integrity checking enabled, it should be IntegrityCheckFailed
    match result.unwrap_err() {
        ShamirError::IntegrityCheckFailed => {
            // This is expected with integrity checking
        }
        other_error => {
            // If integrity checking is disabled, we might get a different error
            // but it should still fail
            println!("Got error (acceptable): {:?}", other_error);
        }
    }
}

#[test]
fn test_mixing_old_and_new_shares_fails_reconstruction_no_integrity() {
    // Create a ShamirShare instance with integrity checking disabled
    let config = Config::new().with_integrity_check(false);
    let mut shamir = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();
    
    // Define a test secret
    let secret = b"Mixed shares without integrity";
    
    // Split the secret into initial shares
    let shares_v1 = shamir.split(secret).unwrap();
    
    // Refresh them to get new shares
    let shares_v2 = shamir.refresh_shares(&shares_v1[0..3]).unwrap();
    
    // Create a mixed set of shares
    let mixed_shares = vec![
        shares_v1[0].clone(),
        shares_v1[1].clone(),
        shares_v2[2].clone(),
    ];
    
    // Attempt to reconstruct from the mixed set
    let result = ShamirShare::reconstruct(&mixed_shares);
    
    // Even without integrity checking, the reconstruction should produce
    // incorrect data (not matching the original secret)
    if let Ok(reconstructed) = result {
        assert_ne!(&reconstructed, secret);
    } else {
        // Or it might fail with some other error, which is also acceptable
        assert!(result.is_err());
    }
}

#[test]
fn test_refresh_with_insufficient_shares_errors() {
    // Create a scheme with threshold k=3
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
    
    // Define a test secret
    let secret = b"Insufficient shares test";
    
    // Split the secret
    let shares = shamir.split(secret).unwrap();
    
    // Call refresh_shares with only k-1 (i.e., 2) shares
    let result = shamir.refresh_shares(&shares[0..2]);
    
    // Assert that the result is Err(ShamirError::InsufficientShares)
    assert!(result.is_err());
    match result.unwrap_err() {
        ShamirError::InsufficientShares { needed, got } => {
            assert_eq!(needed, 3);
            assert_eq!(got, 2);
        }
        other => panic!("Expected InsufficientShares error, got: {:?}", other),
    }
}

#[test]
fn test_refresh_with_empty_shares_errors() {
    // Create a ShamirShare instance
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
    
    // Call refresh_shares with an empty slice
    let result = shamir.refresh_shares(&[]);
    
    // Assert that the result is an error
    assert!(result.is_err());
    match result.unwrap_err() {
        ShamirError::InsufficientShares { needed, got } => {
            assert_eq!(needed, 1);
            assert_eq!(got, 0);
        }
        other => panic!("Expected InsufficientShares error, got: {:?}", other),
    }
}

#[test]
fn test_refresh_preserves_share_metadata() {
    // Create a ShamirShare instance
    let mut shamir = ShamirShare::builder(7, 4).build().unwrap();
    
    // Define a test secret
    let secret = b"Metadata preservation test";
    
    // Split the secret
    let original_shares = shamir.split(secret).unwrap();
    
    // Refresh a subset of shares
    let refreshed_shares = shamir.refresh_shares(&original_shares[1..5]).unwrap();
    
    // Verify that all metadata is preserved
    for (original, refreshed) in original_shares[1..5].iter().zip(refreshed_shares.iter()) {
        assert_eq!(original.index, refreshed.index);
        assert_eq!(original.threshold, refreshed.threshold);
        assert_eq!(original.total_shares, refreshed.total_shares);
        assert_eq!(original.integrity_check, refreshed.integrity_check);
        
        // But data should be different
        assert_ne!(original.data, refreshed.data);
        
        // And data length should be the same
        assert_eq!(original.data.len(), refreshed.data.len());
    }
}

#[test]
fn test_multiple_refresh_rounds() {
    // Create a ShamirShare instance
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
    
    // Define a test secret
    let secret = b"Multiple refresh rounds test";
    
    // Split the secret
    let shares_v1 = shamir.split(secret).unwrap();
    
    // First refresh
    let shares_v2 = shamir.refresh_shares(&shares_v1[0..3]).unwrap();
    
    // Second refresh
    let shares_v3 = shamir.refresh_shares(&shares_v2[0..3]).unwrap();
    
    // Third refresh
    let shares_v4 = shamir.refresh_shares(&shares_v3[0..3]).unwrap();
    
    // All versions should reconstruct to the same secret
    let reconstructed_v1 = ShamirShare::reconstruct(&shares_v1[0..3]).unwrap();
    let reconstructed_v2 = ShamirShare::reconstruct(&shares_v2[0..3]).unwrap();
    let reconstructed_v3 = ShamirShare::reconstruct(&shares_v3[0..3]).unwrap();
    let reconstructed_v4 = ShamirShare::reconstruct(&shares_v4[0..3]).unwrap();
    
    assert_eq!(&reconstructed_v1, secret);
    assert_eq!(&reconstructed_v2, secret);
    assert_eq!(&reconstructed_v3, secret);
    assert_eq!(&reconstructed_v4, secret);
    
    // But all share data should be different
    assert_ne!(shares_v1[0].data, shares_v2[0].data);
    assert_ne!(shares_v2[0].data, shares_v3[0].data);
    assert_ne!(shares_v3[0].data, shares_v4[0].data);
    assert_ne!(shares_v1[0].data, shares_v4[0].data);
}

#[test]
fn test_refresh_with_inconsistent_share_lengths() {
    // Create a ShamirShare instance
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();
    
    // Create shares with different data lengths manually
    // This is a bit artificial since normal split() creates consistent shares,
    // but we want to test the validation
    let secret1 = b"short";
    let secret2 = b"this is a much longer secret";
    
    let shares1 = shamir.split(secret1).unwrap();
    let shares2 = shamir.split(secret2).unwrap();
    
    // Create a mixed set with inconsistent lengths
    let inconsistent_shares = vec![
        shares1[0].clone(),  // Short data
        shares1[1].clone(),  // Short data
        shares2[2].clone(),  // Long data
    ];
    
    // Attempt to refresh with inconsistent shares
    let result = shamir.refresh_shares(&inconsistent_shares);
    
    // Should fail with InconsistentShareLength
    assert!(result.is_err());
    match result.unwrap_err() {
        ShamirError::InconsistentShareLength => {
            // This is expected
        }
        other => panic!("Expected InconsistentShareLength error, got: {:?}", other),
    }
}