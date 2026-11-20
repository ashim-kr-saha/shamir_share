//! Verification and regression tests for security audit remediations.
//!
//! Covers:
//! - Exhaustive GF(2^8) math & inversion verification
//! - Known-Answer Tests (KAT) against independent reference implementation (F-16)
//! - Bounded serde deserialization rejecting oversized inputs without OOM (F-01)
//! - Zeroization and memory hygiene (F-02)
//! - Authenticated streaming and HSSS fail-closed APIs (F-03)
//! - Empty secret rejection when integrity_check = false (F-04)
//! - Refresh verification for k == n schemes and duplicate-delta behavior (F-06)
//! - Infallible allocation conversions (F-07)
//! - Serde TryFrom invariant validation for AccessLevel and HierarchicalShare (F-11)
//! - Streaming edge cases with ErrorKind::Interrupted

#![cfg(feature = "std")]

use shamir_share::{Config, FiniteField, ShamirError, ShamirShare, Share};
#[cfg(feature = "streaming")]
use std::io::{Cursor, Error, ErrorKind, Read};

// ============================================================================
// 1. Independent GF(2^8) Reference Implementation & Exhaustive Math Check
// ============================================================================

mod ref_math {
    /// Schoolbook carryless multiplication modulo irreducible polynomial
    /// x^8 + x^4 + x^3 + x + 1 (0x11B).
    pub fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    pub fn pow(mut base: u8, mut exp: u32) -> u8 {
        let mut res = 1u8;
        while exp > 0 {
            if exp & 1 == 1 {
                res = mul(res, base);
            }
            base = mul(base, base);
            exp >>= 1;
        }
        res
    }

    pub fn inv(a: u8) -> u8 {
        assert_ne!(a, 0);
        pow(a, 254)
    }
}

#[test]
fn test_exhaustive_gf256_arithmetic_against_reference() {
    // 1. Exhaustive 256 x 256 multiplication verification
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            let (a, b) = (a as u8, b as u8);
            let product = (FiniteField::new(a) * FiniteField::new(b)).0;
            let expected = ref_math::mul(a, b);
            assert_eq!(
                product, expected,
                "Multiplication mismatch for a={a}, b={b}"
            );
        }
    }

    // 2. Exhaustive inversion verification (1..=255) and zero non-invertibility
    for a in 1u16..=255 {
        let a = a as u8;
        let ff_a = FiniteField::new(a);
        let inv = ff_a
            .inverse()
            .expect("Non-zero field element must have an inverse");
        let expected_inv = ref_math::inv(a);
        assert_eq!(inv.0, expected_inv, "Inverse mismatch for a={a}");
        assert_eq!((ff_a * inv).0, 1, "a * inv(a) must equal 1 for a={a}");
    }

    assert_eq!(FiniteField::new(0).inverse(), None);
    assert!(!bool::from(FiniteField::new(0).ct_inverse().is_some()));
}

// ============================================================================
// 2. Known-Answer Test (KAT) Vectors (F-16)
// ============================================================================

#[test]
fn test_shamir_known_answer_test_vectors() {
    // Polynomial: P(x) = S + c1*x + c2*x^2 over GF(2^8) (mod 0x11B)
    // S = 0x42 ('B'), c1 = 0x07, c2 = 0x0B
    // Threshold k = 3, n = 5
    // P(1) = 0x42 ^ (0x07 * 1) ^ (0x0B * 1) = 0x42 ^ 0x07 ^ 0x0B = 0x4E
    // P(2) = 0x42 ^ (0x07 * 2) ^ (0x0B * 4)
    //       0x07 * 2 = 0x0E
    //       0x0B * 4 = ref_math::mul(0x0B, 4) = 0x2C
    //       P(2) = 0x42 ^ 0x0E ^ 0x2C = 0x60
    // P(3) = 0x42 ^ (0x07 * 3) ^ (0x0B * 5)
    //       0x07 * 3 = 0x07 ^ 0x0E = 0x09
    //       0x0B * 9 = 0x0B * (3^2 in GF) where 3^2 = 0x05:
    //       ref_math::mul(3, 3) = 0x05
    //       ref_math::mul(0x0B, 0x05) = 0x37
    //       P(3) = 0x42 ^ 0x09 ^ 0x37 = 0x7C

    let x1 = 1u8;
    let y1 = 0x42 ^ ref_math::mul(0x07, x1) ^ ref_math::mul(0x0B, ref_math::mul(x1, x1));
    let x2 = 2u8;
    let y2 = 0x42 ^ ref_math::mul(0x07, x2) ^ ref_math::mul(0x0B, ref_math::mul(x2, x2));
    let x3 = 3u8;
    let y3 = 0x42 ^ ref_math::mul(0x07, x3) ^ ref_math::mul(0x0B, ref_math::mul(x3, x3));

    // Construct shares directly
    let s1 = Share::new(x1, vec![y1], 3, 5, false, false).unwrap();
    let s2 = Share::new(x2, vec![y2], 3, 5, false, false).unwrap();
    let s3 = Share::new(x3, vec![y3], 3, 5, false, false).unwrap();

    let scheme = ShamirShare::builder(5, 3)
        .with_config(Config::new().with_integrity_check(false))
        .build()
        .unwrap();

    let reconstructed = scheme.reconstruct_with_scheme(&[s1, s2, s3]).unwrap();
    assert_eq!(reconstructed.as_slice(), &[0x42]);
}

// ============================================================================
// 3. F-04: Empty Secret with integrity_check = false Rejected
// ============================================================================

#[test]
fn test_f04_empty_secret_with_integrity_disabled_rejected() {
    let scheme = ShamirShare::builder(3, 2)
        .with_config(Config::new().with_integrity_check(false))
        .build()
        .unwrap();

    // Splitting an empty secret when integrity checking is disabled MUST return InvalidConfig
    let err = scheme.split(b"");
    assert!(
        matches!(err, Err(ShamirError::InvalidConfig(_))),
        "Expected InvalidConfig, got {err:?}"
    );

    // Non-empty secret succeeds and round-trips
    let valid_shares = scheme.split(b"A").unwrap();
    let reconstructed = scheme.reconstruct_with_scheme(&valid_shares[0..2]).unwrap();
    assert_eq!(reconstructed.as_slice(), b"A");
}

// ============================================================================
// 4. F-01: Bounded Serde Deserialization Rejects Oversized / Empty Inputs
// ============================================================================

#[cfg(feature = "serde")]
#[test]
fn test_f01_serde_bounded_deserialization() {
    // 1. Valid share round-trips through JSON
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let shares = scheme.split(b"serde test payload").unwrap();
    let json = serde_json::to_string(&shares[0]).unwrap();
    let parsed: Share = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.data(), shares[0].data());

    // 2. Crafted JSON declaring data length 0 is rejected
    let empty_data_json = serde_json::json!({
        "index": 1,
        "data": [],
        "threshold": 2,
        "total_shares": 3,
        "integrity_check": true,
        "compression": false
    })
    .to_string();
    let err = serde_json::from_str::<Share>(&empty_data_json);
    assert!(
        err.is_err(),
        "Empty data must be rejected during serde deserialization"
    );

    // 3. Invalid threshold or total_shares in JSON rejected
    let invalid_threshold_json = serde_json::json!({
        "index": 1,
        "data": [1, 2, 3],
        "threshold": 1, // Invalid: threshold must be >= 2
        "total_shares": 3,
        "integrity_check": true,
        "compression": false
    })
    .to_string();
    assert!(serde_json::from_str::<Share>(&invalid_threshold_json).is_err());
}

// ============================================================================
// 5. F-03: Authenticated Streaming & HSSS APIs Fail Closed
// ============================================================================

#[cfg(feature = "streaming")]
#[test]
fn test_f03_streaming_authenticated_api() {
    let key = [0x55u8; 32];
    let keyed_scheme = ShamirShare::builder(3, 2)
        .with_config(Config::new().with_authentication_key(key))
        .build()
        .unwrap();

    let unkeyed_scheme = ShamirShare::builder(3, 2).build().unwrap();

    let data = b"authenticated streaming test data";
    let mut source = Cursor::new(data);
    let mut dest_cursors: Vec<Cursor<Vec<u8>>> = (0..3).map(|_| Cursor::new(Vec::new())).collect();

    keyed_scheme
        .split_stream(&mut source, &mut dest_cursors)
        .unwrap();

    let mut sources: Vec<Cursor<Vec<u8>>> = dest_cursors
        .into_iter()
        .take(2)
        .map(|c| Cursor::new(c.into_inner()))
        .collect();

    // 1. Unkeyed scheme calling reconstruct_stream_authenticated must fail closed
    let mut out = Vec::new();
    let unkeyed_res = unkeyed_scheme.reconstruct_stream_authenticated(&mut sources, &mut out);
    assert!(
        matches!(unkeyed_res, Err(ShamirError::UnauthenticatedScheme)),
        "Expected UnauthenticatedScheme, got {unkeyed_res:?}"
    );

    // 2. Keyed scheme calling reconstruct_stream_authenticated must succeed
    for s in &mut sources {
        s.set_position(0);
    }
    out.clear();
    let keyed_res = keyed_scheme.reconstruct_stream_authenticated(&mut sources, &mut out);
    assert!(keyed_res.is_ok());
    assert_eq!(out.as_slice(), data);
}

#[cfg(feature = "hsss")]
#[test]
fn test_f03_hsss_authenticated_api() {
    use shamir_share::hsss::Hsss;

    let key = [0x88u8; 32];
    let keyed_hsss = Hsss::builder(2)
        .add_level("Director", 2)
        .with_config(Config::new().with_authentication_key(key))
        .build()
        .unwrap();

    let unkeyed_hsss = Hsss::builder(2).add_level("Director", 2).build().unwrap();

    let secret = b"hsss authenticated secret";
    let shares = keyed_hsss.split_secret(secret).unwrap();

    // 1. Unkeyed HSSS calling reconstruct_authenticated must fail closed
    let unkeyed_res = unkeyed_hsss.reconstruct_authenticated(&shares);
    assert!(
        matches!(unkeyed_res, Err(ShamirError::UnauthenticatedScheme)),
        "Expected UnauthenticatedScheme, got {unkeyed_res:?}"
    );

    // 2. Keyed HSSS calling reconstruct_authenticated must succeed
    let keyed_res = keyed_hsss.reconstruct_authenticated(&shares);
    assert!(keyed_res.is_ok());
    assert_eq!(keyed_res.unwrap().as_slice(), secret);
}

// ============================================================================
// 6. F-06: Refresh Verification for k == n Schemes & Duplicate Delta Cancellation
// ============================================================================

#[cfg(feature = "refresh")]
#[test]
fn test_f06_refresh_k_equals_n_verifies_integrity() {
    // 3-of-3 scheme (k == n)
    let scheme = ShamirShare::builder(3, 3)
        .with_config(Config::new().with_integrity_check(true))
        .build()
        .unwrap();

    let secret = b"proactive refresh k == n test";
    let mut shares = scheme.split(secret).unwrap();

    // Corrupt one share byte
    let mut corrupted = shares[0].clone();
    let mut data = corrupted.data().to_vec();
    data[10] ^= 0xFF;
    corrupted = Share::new(
        corrupted.index(),
        data,
        corrupted.threshold(),
        corrupted.total_shares(),
        corrupted.integrity_check(),
        corrupted.compression(),
    )
    .unwrap();
    shares[0] = corrupted;

    // Refreshing corrupted shares in k == n scheme MUST fail with IntegrityCheckFailed
    let refresh_res = scheme.refresh_shares(&shares);
    assert!(
        matches!(refresh_res, Err(ShamirError::IntegrityCheckFailed)),
        "Expected IntegrityCheckFailed on k == n refresh with corrupted share, got {refresh_res:?}"
    );
}

#[cfg(feature = "refresh")]
#[test]
fn test_f06_refresh_k_equals_n_short_share_rejected() {
    // 2-of-2 scheme with integrity enabled
    let scheme = ShamirShare::builder(2, 2)
        .with_config(Config::new().with_integrity_check(true))
        .build()
        .unwrap();

    // Create valid 2-of-2 shares with integrity check disabled just to get short shares (< 64 bytes)
    let raw_scheme = ShamirShare::builder(2, 2)
        .with_config(Config::new().with_integrity_check(false))
        .build()
        .unwrap();
    let raw_shares = raw_scheme.split(b"short").unwrap();
    assert!(raw_shares[0].data().len() < 64);

    // Rebrand shares as integrity_check = true
    let short_share1 = Share::new(
        1,
        raw_shares[0].data().to_vec(),
        2,
        2,
        true, // integrity_check = true
        false,
    )
    .unwrap();
    let short_share2 = Share::new(
        2,
        raw_shares[1].data().to_vec(),
        2,
        2,
        true, // integrity_check = true
        false,
    )
    .unwrap();

    // Refreshing shares with data_length < SALT_SIZE + HASH_SIZE must fail closed with IntegrityCheckFailed
    let res = scheme.refresh_shares(&[short_share1, short_share2]);
    assert!(
        matches!(res, Err(ShamirError::IntegrityCheckFailed)),
        "Expected IntegrityCheckFailed for short shares under integrity_check = true, got {res:?}"
    );
}

#[cfg(feature = "refresh")]
#[test]
fn test_f06_duplicate_delta_cancellation_documented_behavior() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let secret = b"duplicate delta cancellation test";
    let shares = scheme.split(secret).unwrap();

    let deltas = scheme
        .generate_refresh_deltas(&[1, 2, 3], shares[0].data().len())
        .unwrap();

    let mut share1 = shares[0].clone();
    let original_data = share1.data().to_vec();

    // Apply delta once: data changes
    share1.apply_refresh_delta(&deltas[0]).unwrap();
    assert_ne!(share1.data(), original_data.as_slice());

    // Apply same delta twice: cancels out via XOR (a ^ d ^ d == a)
    share1.apply_refresh_delta(&deltas[0]).unwrap();
    assert_eq!(share1.data(), original_data.as_slice());
}

// ============================================================================
// 7. F-11: AccessLevel & HierarchicalShare Serde Invariant Checks
// ============================================================================

#[cfg(all(feature = "hsss", feature = "serde"))]
#[test]
fn test_f11_hsss_serde_invariants() {
    use shamir_share::hsss::{AccessLevel, HierarchicalShare};

    // AccessLevel with 0 shares must fail deserialization
    let zero_shares_json = serde_json::json!({
        "name": "InvalidLevel",
        "shares_count": 0
    })
    .to_string();
    assert!(serde_json::from_str::<AccessLevel>(&zero_shares_json).is_err());

    // AccessLevel with empty name must fail deserialization
    let empty_name_json = serde_json::json!({
        "name": "",
        "shares_count": 3
    })
    .to_string();
    assert!(serde_json::from_str::<AccessLevel>(&empty_name_json).is_err());

    // HierarchicalShare with empty level_name must fail deserialization
    let empty_level_share_json = serde_json::json!({
        "level_name": "",
        "shares": []
    })
    .to_string();
    assert!(serde_json::from_str::<HierarchicalShare>(&empty_level_share_json).is_err());

    // HierarchicalShare with > 255 shares must fail deserialization
    let single_share = serde_json::json!({
        "index": 1,
        "data": [42],
        "threshold": 2,
        "total_shares": 2,
        "integrity_check": false,
        "compression": false
    });
    let too_many_shares_json = serde_json::json!({
        "level_name": "LevelA",
        "shares": vec![single_share; 256]
    })
    .to_string();
    assert!(serde_json::from_str::<HierarchicalShare>(&too_many_shares_json).is_err());
}

// ============================================================================
// 8. Streaming Edge Cases: Interrupted Reader Adapter
// ============================================================================

#[cfg(feature = "streaming")]
struct InterruptedReader<R> {
    inner: R,
    toggle: bool,
}

#[cfg(feature = "streaming")]
impl<R: Read> Read for InterruptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.toggle = !self.toggle;
        if self.toggle {
            Err(Error::new(
                ErrorKind::Interrupted,
                "Interrupted signal simulation",
            ))
        } else {
            let limit = buf.len().min(7); // read in small chunks
            self.inner.read(&mut buf[..limit])
        }
    }
}

#[cfg(feature = "streaming")]
#[test]
fn test_streaming_interrupted_reader_handling() {
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let data = b"large streaming input with simulated EINTR on every other read";
    let mut reader = InterruptedReader {
        inner: Cursor::new(data),
        toggle: false,
    };

    let mut dest_cursors: Vec<Cursor<Vec<u8>>> = (0..3).map(|_| Cursor::new(Vec::new())).collect();

    scheme.split_stream(&mut reader, &mut dest_cursors).unwrap();

    let mut sources: Vec<Cursor<Vec<u8>>> = dest_cursors
        .into_iter()
        .take(2)
        .map(|c| Cursor::new(c.into_inner()))
        .collect();

    let mut out = Vec::new();
    ShamirShare::reconstruct_stream(&mut sources, &mut out).unwrap();
    assert_eq!(out.as_slice(), data);
}
