#![cfg(feature = "std")]

use proptest::prelude::*;
use shamir_share::{Config, ShamirError, ShamirShare, Share};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_split_reconstruct_roundtrip(
        secret in proptest::collection::vec(any::<u8>(), 0..2048),
        threshold in 2u8..=8u8,
        extra in 0u8..=6u8,
        integrity in any::<bool>(),
    ) {
        let total_shares = threshold + extra;
        let config = Config::new().with_integrity_check(integrity);
        let scheme = ShamirShare::builder(total_shares, threshold)
            .with_config(config)
            .build()
            .unwrap();

        let res = scheme.split(&secret);
        if secret.is_empty() && !integrity {
            prop_assert!(matches!(res, Err(ShamirError::InvalidConfig(_))));
            return Ok(());
        }
        let shares = res.unwrap();
        prop_assert_eq!(shares.len(), total_shares as usize);

        // Serialize and deserialize all shares
        let mut encoded = Vec::new();
        for s in &shares {
            let bytes = s.to_bytes().unwrap();
            let parsed = Share::from_bytes(&bytes).unwrap();
            prop_assert_eq!(&parsed, s);
            encoded.push(parsed);
        }

        if integrity {
            // Reconstruct from exact threshold
            let reconstructed = ShamirShare::reconstruct(&encoded[0..threshold as usize]).unwrap();
            prop_assert_eq!(reconstructed.as_slice(), secret.as_slice());

            // Reconstruct from all shares (verifies excess share consistency)
            let reconstructed_all = ShamirShare::reconstruct(&encoded).unwrap();
            prop_assert_eq!(reconstructed_all.as_slice(), secret.as_slice());
        } else {
            // Unauthenticated shares require explicit scheme validation
            let reconstructed = scheme.reconstruct_with_scheme(&encoded[0..threshold as usize]).unwrap();
            prop_assert_eq!(reconstructed.as_slice(), secret.as_slice());

            let reconstructed_all = scheme.reconstruct_with_scheme(&encoded).unwrap();
            prop_assert_eq!(reconstructed_all.as_slice(), secret.as_slice());
        }
    }

    #[test]
    fn prop_share_new_validation(
        index in any::<u8>(),
        threshold in any::<u8>(),
        total_shares in any::<u8>(),
        data_len in 0usize..1024,
    ) {
        let data = vec![0x55; data_len];
        let res = Share::new(index, data, threshold, total_shares, true, false);

        let is_valid = (1..=total_shares).contains(&index)
            && (2..=total_shares).contains(&threshold)
            && (1..=shamir_share::MAX_SHARE_DATA_LEN).contains(&data_len);

        if is_valid {
            prop_assert!(res.is_ok());
        } else {
            prop_assert!(res.is_err());
        }
    }

    #[test]
    fn prop_excess_share_tampering_detected(
        secret in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let scheme = ShamirShare::builder(4, 2).build().unwrap();
        let mut shares = scheme.split(&secret).unwrap();

        // Corrupt an excess share (share 3)
        let mut corrupted_data = shares[2].data().to_vec();
        if let Some(byte) = corrupted_data.first_mut() {
            *byte ^= 0x01;
        }
        shares[2] = Share::new(
            shares[2].index(),
            corrupted_data,
            shares[2].threshold(),
            shares[2].total_shares(),
            shares[2].integrity_check(),
            shares[2].compression(),
        )
        .unwrap();

        // Reconstructing with excess corrupted share must fail
        let res = ShamirShare::reconstruct(&shares[0..3]);
        prop_assert!(matches!(res, Err(ShamirError::IntegrityCheckFailed)));
    }
}
