use shamir_share::{Config, ShamirShare};

#[test]
fn test_builder_defaults() {
    // Build a ShamirShare instance using the builder with default configuration
    let shamir = ShamirShare::builder(5, 3).build().unwrap();

    // Assert that its internal configuration for integrity_check is true (the default)
    // We need to access the config through the split method behavior since config is private
    // We'll verify this by checking the integrity_check field in generated shares
    let secret = b"test secret";
    let mut shamir_mut = shamir;
    let shares = shamir_mut.split(secret).unwrap();

    // Default configuration should have integrity_check = true
    assert!(shares[0].integrity_check);
}

#[test]
fn test_builder_with_custom_config() {
    // Create a Config with integrity_check set to false
    let config = Config::new().with_integrity_check(false);

    // Build a ShamirShare instance using the builder and .with_config()
    let shamir = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();

    // Assert that its internal configuration for integrity_check is false
    let secret = b"test secret";
    let mut shamir_mut = shamir;
    let shares = shamir_mut.split(secret).unwrap();

    // Custom configuration should have integrity_check = false
    assert!(!shares[0].integrity_check);
}

#[test]
fn test_split_with_integrity_check_disabled() {
    // Create a Config with integrity_check set to false
    let config = Config::new().with_integrity_check(false);

    // Build a ShamirShare instance with this config
    let mut shamir = ShamirShare::builder(5, 3)
        .with_config(config)
        .build()
        .unwrap();

    // Define a secret
    let secret = b"no hash please";

    // Call the split() method
    let shares = shamir.split(secret).unwrap();

    // Assert that the length of the data in each generated share is exactly equal to secret.len()
    for share in &shares {
        assert_eq!(share.data.len(), secret.len());
    }

    // Reconstruct the secret from the shares and assert that it matches the original
    let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
    assert_eq!(&reconstructed, secret);
}

#[test]
fn test_split_with_integrity_check_enabled() {
    // Build a ShamirShare instance using the default configuration (integrity_check: true)
    let mut shamir = ShamirShare::builder(5, 3).build().unwrap();

    // Define a secret
    let secret = b"hash me please";

    // Call the split() method
    let shares = shamir.split(secret).unwrap();

    // Assert that the length of the data in each generated share is greater than secret.len()
    // Specifically, secret.len() + 32 (SHA-256 hash size)
    for share in &shares {
        assert!(share.data.len() > secret.len());
        assert_eq!(share.data.len(), secret.len() + 32);
    }

    // Reconstruct the secret and assert it matches
    let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
    assert_eq!(&reconstructed, secret);
}
