use shamir_share::hsss::Hsss;
use shamir_share::{ShamirError, ShamirShare};

#[test]
fn test_president_can_reconstruct_alone() {
    // Setup: Create HSSS scheme with master threshold of 5
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Executive", 2)
        .add_level("Contractor", 1)
        .build()
        .unwrap();

    let secret = b"top secret organizational data";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: President should be able to reconstruct alone (5 shares >= threshold of 5)
    let president_shares = &all_h_shares[0]; // President is first level
    assert_eq!(president_shares.level_name, "President");
    assert_eq!(president_shares.shares.len(), 5);

    let reconstructed = hsss.reconstruct(&[president_shares.clone()]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_vp_and_executive_can_reconstruct() {
    // Setup: Create HSSS scheme with master threshold of 5
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Executive", 2)
        .add_level("Contractor", 1)
        .build()
        .unwrap();

    let secret = b"top secret organizational data";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: VP (3 shares) + Executive (2 shares) = 5 shares >= threshold of 5
    let vp_shares = &all_h_shares[1]; // VP is second level
    let executive_shares = &all_h_shares[2]; // Executive is third level

    assert_eq!(vp_shares.level_name, "VP");
    assert_eq!(vp_shares.shares.len(), 3);
    assert_eq!(executive_shares.level_name, "Executive");
    assert_eq!(executive_shares.shares.len(), 2);

    let reconstructed = hsss
        .reconstruct(&[vp_shares.clone(), executive_shares.clone()])
        .unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_two_vps_can_reconstruct() {
    // Setup: Create HSSS scheme with multiple VPs
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP1", 3)
        .add_level("VP2", 3)
        .add_level("Executive", 2)
        .build()
        .unwrap();

    let secret = b"confidential business strategy";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: VP1 (3 shares) + VP2 (3 shares) = 6 shares >= threshold of 5
    let vp1_shares = &all_h_shares[1]; // VP1 is second level
    let vp2_shares = &all_h_shares[2]; // VP2 is third level

    assert_eq!(vp1_shares.level_name, "VP1");
    assert_eq!(vp1_shares.shares.len(), 3);
    assert_eq!(vp2_shares.level_name, "VP2");
    assert_eq!(vp2_shares.shares.len(), 3);

    let reconstructed = hsss
        .reconstruct(&[vp1_shares.clone(), vp2_shares.clone()])
        .unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_vp_alone_cannot_reconstruct() {
    // Setup: Create HSSS scheme with master threshold of 5
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Executive", 2)
        .add_level("Contractor", 1)
        .build()
        .unwrap();

    let secret = b"top secret organizational data";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: VP alone has only 3 shares, which is less than threshold of 5
    let vp_shares = &all_h_shares[1]; // VP is second level
    assert_eq!(vp_shares.level_name, "VP");
    assert_eq!(vp_shares.shares.len(), 3);

    // Test using the HSSS reconstruct method
    let result = hsss.reconstruct(&[vp_shares.clone()]);
    assert!(matches!(
        result,
        Err(ShamirError::InsufficientShares { needed: 5, got: 3 })
    ));

    // Also test using the raw ShamirShare reconstruct method as specified in the prompt
    let result = ShamirShare::reconstruct(&vp_shares.shares);
    assert!(matches!(
        result,
        Err(ShamirError::InsufficientShares { needed: 5, got: 3 })
    ));
}

#[test]
fn test_three_contractors_cannot_reconstruct() {
    // Setup: Create HSSS scheme with 3 contractors, each with 1 share
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Contractor1", 1)
        .add_level("Contractor2", 1)
        .add_level("Contractor3", 1)
        .build()
        .unwrap();

    let secret = b"classified project details";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: Three contractors with 1 share each = 3 shares total, which is less than threshold of 5
    let contractor1_shares = &all_h_shares[2]; // Contractor1 is third level
    let contractor2_shares = &all_h_shares[3]; // Contractor2 is fourth level
    let contractor3_shares = &all_h_shares[4]; // Contractor3 is fifth level

    assert_eq!(contractor1_shares.level_name, "Contractor1");
    assert_eq!(contractor1_shares.shares.len(), 1);
    assert_eq!(contractor2_shares.level_name, "Contractor2");
    assert_eq!(contractor2_shares.shares.len(), 1);
    assert_eq!(contractor3_shares.level_name, "Contractor3");
    assert_eq!(contractor3_shares.shares.len(), 1);

    let result = hsss.reconstruct(&[
        contractor1_shares.clone(),
        contractor2_shares.clone(),
        contractor3_shares.clone(),
    ]);
    assert!(matches!(
        result,
        Err(ShamirError::InsufficientShares { needed: 5, got: 3 })
    ));
}

#[test]
fn test_executive_and_contractors_cannot_reconstruct() {
    // Additional test: Executive (2) + 2 Contractors (1 each) = 4 shares < threshold of 5
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Executive", 2)
        .add_level("Contractor1", 1)
        .add_level("Contractor2", 1)
        .build()
        .unwrap();

    let secret = b"sensitive operational data";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: Executive (2) + Contractor1 (1) + Contractor2 (1) = 4 shares < threshold of 5
    let executive_shares = &all_h_shares[2]; // Executive is third level
    let contractor1_shares = &all_h_shares[3]; // Contractor1 is fourth level
    let contractor2_shares = &all_h_shares[4]; // Contractor2 is fifth level

    let result = hsss.reconstruct(&[
        executive_shares.clone(),
        contractor1_shares.clone(),
        contractor2_shares.clone(),
    ]);
    assert!(matches!(
        result,
        Err(ShamirError::InsufficientShares { needed: 5, got: 4 })
    ));
}

#[test]
fn test_vp_executive_and_contractor_can_reconstruct() {
    // Additional test: VP (3) + Executive (2) + Contractor (1) = 6 shares >= threshold of 5
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Executive", 2)
        .add_level("Contractor", 1)
        .build()
        .unwrap();

    let secret = b"multi-level collaboration data";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: VP (3) + Executive (2) + Contractor (1) = 6 shares >= threshold of 5
    let vp_shares = &all_h_shares[1]; // VP is second level
    let executive_shares = &all_h_shares[2]; // Executive is third level
    let contractor_shares = &all_h_shares[3]; // Contractor is fourth level

    let reconstructed = hsss
        .reconstruct(&[
            vp_shares.clone(),
            executive_shares.clone(),
            contractor_shares.clone(),
        ])
        .unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_all_levels_can_reconstruct() {
    // Test: All levels together should definitely work
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Executive", 2)
        .add_level("Contractor", 1)
        .build()
        .unwrap();

    let secret = b"complete organizational access";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: All levels together = 5 + 3 + 2 + 1 = 11 shares >= threshold of 5
    let reconstructed = hsss.reconstruct(&all_h_shares).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_edge_case_exact_threshold() {
    // Test with a scheme where we need exactly the threshold
    let mut hsss = Hsss::builder(3) // Master threshold of 3
        .add_level("Manager", 3)
        .add_level("Employee1", 1)
        .add_level("Employee2", 1)
        .add_level("Employee3", 1)
        .build()
        .unwrap();

    let secret = b"exact threshold test";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: Manager alone can reconstruct (3 shares = threshold of 3)
    let manager_shares = &all_h_shares[0];
    let reconstructed = hsss.reconstruct(&[manager_shares.clone()]).unwrap();
    assert_eq!(reconstructed, secret);

    // Test: All three employees together can reconstruct (1 + 1 + 1 = 3 shares = threshold of 3)
    let employee1_shares = &all_h_shares[1];
    let employee2_shares = &all_h_shares[2];
    let employee3_shares = &all_h_shares[3];

    let reconstructed = hsss
        .reconstruct(&[
            employee1_shares.clone(),
            employee2_shares.clone(),
            employee3_shares.clone(),
        ])
        .unwrap();
    assert_eq!(reconstructed, secret);

    // Test: Only two employees cannot reconstruct (1 + 1 = 2 shares < threshold of 3)
    let result = hsss.reconstruct(&[employee1_shares.clone(), employee2_shares.clone()]);
    assert!(matches!(
        result,
        Err(ShamirError::InsufficientShares { needed: 3, got: 2 })
    ));
}

#[test]
fn test_complex_hierarchy() {
    // Test a more complex hierarchy with different threshold requirements
    let mut hsss = Hsss::builder(7) // Master threshold of 7
        .add_level("CEO", 7) // CEO can reconstruct alone
        .add_level("CTO", 4) // CTO needs help
        .add_level("Manager1", 3) // Manager needs help
        .add_level("Manager2", 2) // Manager needs help
        .add_level("Employee1", 1) // Employee needs lots of help
        .add_level("Employee2", 1) // Employee needs lots of help
        .add_level("Employee3", 1) // Employee needs lots of help
        .build()
        .unwrap();

    let secret = b"complex organizational structure";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Test: CEO alone can reconstruct (7 shares = threshold of 7)
    let ceo_shares = &all_h_shares[0];
    let reconstructed = hsss.reconstruct(&[ceo_shares.clone()]).unwrap();
    assert_eq!(reconstructed, secret);

    // Test: CTO + Manager1 can reconstruct (4 + 3 = 7 shares = threshold of 7)
    let cto_shares = &all_h_shares[1];
    let manager1_shares = &all_h_shares[2];
    let reconstructed = hsss
        .reconstruct(&[cto_shares.clone(), manager1_shares.clone()])
        .unwrap();
    assert_eq!(reconstructed, secret);

    // Test: CTO + Manager2 + Employee1 can reconstruct (4 + 2 + 1 = 7 shares = threshold of 7)
    let manager2_shares = &all_h_shares[3];
    let employee1_shares = &all_h_shares[4];
    let reconstructed = hsss
        .reconstruct(&[
            cto_shares.clone(),
            manager2_shares.clone(),
            employee1_shares.clone(),
        ])
        .unwrap();
    assert_eq!(reconstructed, secret);

    // Test: All managers and employees together can reconstruct (3 + 2 + 1 + 1 + 1 = 8 shares >= threshold of 7)
    let employee2_shares = &all_h_shares[5];
    let employee3_shares = &all_h_shares[6];
    let reconstructed = hsss
        .reconstruct(&[
            manager1_shares.clone(),
            manager2_shares.clone(),
            employee1_shares.clone(),
            employee2_shares.clone(),
            employee3_shares.clone(),
        ])
        .unwrap();
    assert_eq!(reconstructed, secret);

    // Test: CTO alone cannot reconstruct (4 shares < threshold of 7)
    let result = hsss.reconstruct(&[cto_shares.clone()]);
    assert!(matches!(
        result,
        Err(ShamirError::InsufficientShares { needed: 7, got: 4 })
    ));

    // Test: Manager1 + Manager2 cannot reconstruct (3 + 2 = 5 shares < threshold of 7)
    let result = hsss.reconstruct(&[manager1_shares.clone(), manager2_shares.clone()]);
    assert!(matches!(
        result,
        Err(ShamirError::InsufficientShares { needed: 7, got: 5 })
    ));
}

#[test]
fn test_share_properties_consistency() {
    // Test that all shares have consistent properties regardless of their hierarchical level
    let mut hsss = Hsss::builder(5) // Master threshold of 5
        .add_level("President", 5)
        .add_level("VP", 3)
        .add_level("Executive", 2)
        .add_level("Contractor", 1)
        .build()
        .unwrap();

    let secret = b"property consistency test";
    let all_h_shares = hsss.split_secret(secret).unwrap();

    // Verify that all shares have the same threshold and total_shares properties
    let expected_threshold = 5;
    let expected_total_shares = 5 + 3 + 2 + 1; // 11 total shares

    for hierarchical_share in &all_h_shares {
        for share in &hierarchical_share.shares {
            assert_eq!(share.threshold, expected_threshold);
            assert_eq!(share.total_shares, expected_total_shares);
            assert!(share.integrity_check); // Default should be true
            assert!(share.index >= 1 && share.index <= expected_total_shares);
        }
    }

    // Verify that all share indices are unique across all levels
    let mut all_indices = Vec::new();
    for hierarchical_share in &all_h_shares {
        for share in &hierarchical_share.shares {
            all_indices.push(share.index);
        }
    }

    all_indices.sort();
    for i in 1..all_indices.len() {
        assert_ne!(
            all_indices[i - 1],
            all_indices[i],
            "Found duplicate share index: {}",
            all_indices[i]
        );
    }

    // Verify indices are sequential from 1 to total_shares
    for (i, &index) in all_indices.iter().enumerate() {
        assert_eq!(index, (i + 1) as u8);
    }
}
