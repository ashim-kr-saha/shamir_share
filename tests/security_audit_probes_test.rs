//! Consolidated security and correctness audit probes for `shamir_share`.
//!
//! Ported directly from the standalone `shamir_share_audit` harness into `shamir_share`
//! as part of the v0.3.0 audit consolidation. All probes exercise strictly the public API.

use shamir_share::FiniteField;

#[cfg(feature = "std")]
use shamir_share::{Config, ShamirError, ShamirShare, Share};

// ============================================================================
// 1. Independent GF(2^8) Reference Implementation
// ============================================================================

/// Independent reference arithmetic over GF(2^8) defined by irreducible polynomial
/// x^8 + x^4 + x^3 + x + 1 (0x11B). Deliberately implements schoolbook carryless
/// multiplication and Fermat's Little Theorem inversion without reusing any crate internals.
#[allow(dead_code)]
mod gf_reference {
    pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
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

    pub fn gf_pow(mut base: u8, mut e: u32) -> u8 {
        let mut r = 1u8;
        while e > 0 {
            if e & 1 == 1 {
                r = gf_mul(r, base);
            }
            base = gf_mul(base, base);
            e >>= 1;
        }
        r
    }

    pub fn gf_inv(a: u8) -> u8 {
        assert_ne!(a, 0);
        gf_pow(a, 254)
    }

    /// Lagrange coefficients L_i(0) for interpolation at x = 0 over GF(2^8).
    pub fn lagrange_at_zero(indices: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(indices.len());
        for (i, &xi) in indices.iter().enumerate() {
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, &xj) in indices.iter().enumerate() {
                if i != j {
                    num = gf_mul(num, xj);
                    den = gf_mul(den, xi ^ xj);
                }
            }
            out.push(gf_mul(num, gf_inv(den)));
        }
        out
    }

    /// Recomputes the expected internal integrity digest:
    /// `domain || [flags, threshold, total] || salt || payload`.
    pub fn expected_digest(
        flags: u8,
        threshold: u8,
        total_shares: u8,
        salt: &[u8],
        payload: &[u8],
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"SHS1_SHA256_V3\0");
        h.update([flags, threshold, total_shares]);
        h.update(salt);
        h.update(payload);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }
}

// ----------------------------------------------------------------------------
// GF(2^8) Exhaustive Cross-Checks
// ----------------------------------------------------------------------------

#[test]
fn test_gf_exhaustive_multiplication() {
    let mut mismatches = 0u32;
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            let (a, b) = (a as u8, b as u8);
            let got = (FiniteField::new(a) * FiniteField::new(b)).0;
            let want = gf_reference::gf_mul(a, b);
            if got != want {
                mismatches += 1;
            }
        }
    }
    assert_eq!(mismatches, 0, "Exhaustive multiplication mismatch count");
}

#[test]
fn test_gf_exhaustive_inverses() {
    let mut mismatches = 0u32;
    for a in 1u16..=255 {
        let a = a as u8;
        let got = FiniteField::new(a).inverse().map(|f| f.0);
        let want = gf_reference::gf_inv(a);
        if got != Some(want) {
            mismatches += 1;
        }
    }
    assert_eq!(mismatches, 0, "Exhaustive inverse mismatch count");

    assert_eq!(FiniteField::new(0).inverse(), None);
    assert!(!bool::from(FiniteField::new(0).ct_inverse().is_some()));
}

#[test]
fn test_gf_exp_edge_cases() {
    assert_eq!(FiniteField::new(3).exp(5).0, gf_reference::gf_pow(3, 5));
    assert_eq!(FiniteField::new(0).exp(0).0, 1);
    assert_eq!(FiniteField::new(0).exp(5).0, 0);

    for a in 1u16..=255 {
        let a = a as u8;
        assert_eq!(
            FiniteField::new(a).exp(255).0,
            1,
            "Fermat little theorem failure for a={a}"
        );
    }
}

#[test]
fn test_gf_distributivity() {
    let mut violations = 0u32;
    for a in (0u16..256).step_by(7) {
        for b in (0u16..256).step_by(11) {
            for c in (0u16..256).step_by(13) {
                let (a, b, c) = (a as u8, b as u8, c as u8);
                let ref_lhs = gf_reference::gf_mul(a, b ^ c);
                let ref_rhs = gf_reference::gf_mul(a, b) ^ gf_reference::gf_mul(a, c);
                if ref_lhs != ref_rhs {
                    violations += 1;
                }
                let ff_a = FiniteField::new(a);
                let ff_b = FiniteField::new(b);
                let ff_c = FiniteField::new(c);
                assert_eq!(ff_a * (ff_b + ff_c), (ff_a * ff_b) + (ff_a * ff_c));
            }
        }
    }
    assert_eq!(violations, 0);
}

// ============================================================================
// 2. Forgery Boundary & Authenticated Reconstruction (F-01)
// ============================================================================

#[cfg(feature = "std")]
#[test]
fn test_f01_forgery_boundary_and_authenticated_reconstruction() {
    use gf_reference::{expected_digest, gf_inv, gf_mul, lagrange_at_zero};

    let secret: &[u8] = b"transfer USD 10 to account ALICE-1111";
    let scheme = ShamirShare::builder(3, 2).build().unwrap();
    let shares = scheme.split(secret).unwrap();

    let victim_share = shares[0].clone();

    // Adversary targets chosen plaintext of equal length
    let evil: &[u8] = b"transfer USD 10 to account MALLORY-66";
    assert_eq!(evil.len(), secret.len());

    let salt = [0xAAu8; 32];
    let flags = 1u8; // integrity_check = true, compression = false
    let digest = expected_digest(flags, 2, 3, &salt, evil);
    let mut blob = Vec::with_capacity(64 + evil.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&digest);
    blob.extend_from_slice(evil);
    assert_eq!(blob.len(), victim_share.data().len());

    // Lagrange basis at x=0 for shares {1, 2}
    let coeffs = lagrange_at_zero(&[1, 2]);
    let (l1, l2) = (coeffs[0], coeffs[1]);
    let l2_inv = gf_inv(l2);
    let forged_data: Vec<u8> = blob
        .iter()
        .zip(victim_share.data())
        .map(|(&target, &y1)| gf_mul(l2_inv, target ^ gf_mul(l1, y1)))
        .collect();
    let forged = Share::new(2, forged_data, 2, 3, true, false).expect("forged share creation");

    // 1. Unkeyed reconstruct_authenticated MUST reject with UnauthenticatedScheme
    let auth_res = scheme.reconstruct_authenticated(&[victim_share.clone(), forged.clone()]);
    assert!(
        matches!(auth_res, Err(ShamirError::UnauthenticatedScheme)),
        "Expected UnauthenticatedScheme, got: {auth_res:?}"
    );

    // 2. Keyed scheme MUST reject tampered or forged shares in both reconstruct_authenticated
    // and reconstruct_with_scheme
    let key = [0x77u8; 32];
    let authed_scheme = ShamirShare::builder(3, 2)
        .with_config(Config::new().with_authentication_key(key))
        .build()
        .unwrap();
    let authed_shares = authed_scheme.split(secret).unwrap();

    // Tamper single payload byte
    let mut tampered_data = authed_shares[1].data().to_vec();
    let n = tampered_data.len();
    tampered_data[n - 1] ^= 0x01;
    let tampered_share = Share::new(
        authed_shares[1].index(),
        tampered_data,
        authed_shares[1].threshold(),
        authed_shares[1].total_shares(),
        authed_shares[1].integrity_check(),
        authed_shares[1].compression(),
    )
    .unwrap();

    let rec_auth = authed_scheme
        .reconstruct_authenticated(&[authed_shares[0].clone(), tampered_share.clone()]);
    assert!(
        matches!(rec_auth, Err(ShamirError::IntegrityCheckFailed)),
        "Expected IntegrityCheckFailed in reconstruct_authenticated, got: {rec_auth:?}"
    );

    let rec_scheme =
        authed_scheme.reconstruct_with_scheme(&[authed_shares[0].clone(), tampered_share.clone()]);
    assert!(
        matches!(rec_scheme, Err(ShamirError::IntegrityCheckFailed)),
        "Expected IntegrityCheckFailed in reconstruct_with_scheme, got: {rec_scheme:?}"
    );

    let rec_static = ShamirShare::reconstruct(&[authed_shares[0].clone(), tampered_share]);
    assert!(
        matches!(rec_static, Err(ShamirError::IntegrityCheckFailed)),
        "Expected IntegrityCheckFailed in static reconstruct, got: {rec_static:?}"
    );
}

// ============================================================================
// 3. Auth-Key / Config Validation (F-03)
// ============================================================================

#[cfg(feature = "std")]
#[test]
fn test_f03_auth_key_and_integrity_config_validation() {
    let key = [0x5Au8; 32];
    let invalid_cfg = Config::new()
        .with_authentication_key(key)
        .with_integrity_check(false);

    let build_res = ShamirShare::builder(3, 2).with_config(invalid_cfg).build();
    assert!(
        matches!(build_res, Err(ShamirError::InvalidConfig(_))),
        "Expected InvalidConfig when auth key has integrity_check=false, got: {build_res:?}"
    );

    // Keyed shares with integrity check enabled reject tampering
    let valid_cfg = Config::new().with_authentication_key(key);
    let scheme = ShamirShare::builder(3, 2)
        .with_config(valid_cfg)
        .build()
        .unwrap();
    let shares = scheme.split(b"confidential keyed data").unwrap();

    let mut bad_data = shares[1].data().to_vec();
    bad_data[5] ^= 0xFF;
    let bad_share = Share::new(
        shares[1].index(),
        bad_data,
        shares[1].threshold(),
        shares[1].total_shares(),
        shares[1].integrity_check(),
        shares[1].compression(),
    )
    .unwrap();

    let res = scheme.reconstruct_with_scheme(&[shares[0].clone(), bad_share]);
    assert!(
        matches!(res, Err(ShamirError::IntegrityCheckFailed)),
        "Expected IntegrityCheckFailed on tampered keyed share, got: {res:?}"
    );
}

// ============================================================================
// 4. Wire Canonicalization, Mutations, Leak Redaction & Parallel Parity (F-07)
// ============================================================================

#[cfg(feature = "std")]
#[test]
fn test_wire_single_byte_mutation_canonical_sweep() {
    let s = ShamirShare::builder(3, 2).build().unwrap();
    let shares = s.split(b"wire canonicalization probe payload").unwrap();
    let bytes = shares[0].to_bytes().unwrap();

    let mut accepted = 0u32;
    let mut non_canonical = 0u32;

    for i in 0..bytes.len() {
        for v in [0x00u8, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, bytes[i] ^ 0x01] {
            if bytes[i] == v {
                continue;
            }
            let mut mutated = bytes.clone();
            mutated[i] = v;

            if let Ok(sh) = Share::from_bytes(&mutated) {
                accepted += 1;
                if sh.to_bytes().unwrap() != mutated {
                    non_canonical += 1;
                }
            }
        }
    }

    assert!(accepted > 0, "Expected some mutated bytes to parse");
    assert_eq!(
        non_canonical, 0,
        "Every accepted wire representation must be canonically byte-identical on re-serialization"
    );
}

#[cfg(feature = "std")]
#[test]
fn test_leak_redaction_debug_canary() {
    let canary = "DEBUG-LEAK-CANARY-0123456789";
    let s = ShamirShare::builder(5, 3).build().unwrap();
    let shares = s.split(canary.as_bytes()).unwrap();

    let dbg_share = format!("{:?}", shares[0]);
    assert!(
        !dbg_share.contains(canary),
        "Share Debug leaked secret canary: {dbg_share}"
    );

    let dbg_view = format!("{:?}", shares[0].as_view());
    assert!(
        !dbg_view.contains(canary),
        "ShareView Debug leaked secret canary: {dbg_view}"
    );

    let dbg_config = format!("{:?}", s.config());
    assert!(
        !dbg_config.contains(canary),
        "Config Debug leaked secret canary: {dbg_config}"
    );

    #[cfg(feature = "hsss")]
    {
        use shamir_share::hsss::HierarchicalShare;
        let h_share = HierarchicalShare::new("CanaryLevel", vec![shares[0].clone()]);
        let dbg_hsss = format!("{:?}", h_share);
        assert!(
            !dbg_hsss.contains(canary),
            "HierarchicalShare Debug leaked secret canary: {dbg_hsss}"
        );
    }
}

#[cfg(feature = "parallel")]
#[test]
fn test_parallel_vs_sequential_parity() {
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;
    use shamir_share::SplitMode;

    let secret = b"parallel vs sequential split consistency payload";
    let mut rng_a = ChaCha20Rng::from_seed([42u8; 32]);
    let mut rng_b = ChaCha20Rng::from_seed([42u8; 32]);

    let seq_scheme = ShamirShare::builder(5, 3).build().unwrap();
    let par_scheme = ShamirShare::builder(5, 3)
        .with_config(Config::new().with_mode(SplitMode::Parallel))
        .build()
        .unwrap();

    let shares_seq = seq_scheme.split_with_rng(secret, &mut rng_a).unwrap();
    let shares_par = par_scheme.split_with_rng(secret, &mut rng_b).unwrap();
    assert_eq!(
        shares_seq, shares_par,
        "Parallel and sequential split must yield identical shares for same RNG"
    );

    // Parallel reconstruction on payload >= 16384 bytes (40 KiB)
    let big_secret = vec![0x3Cu8; 40_000];
    let big_shares = par_scheme.split(&big_secret).unwrap();

    let par_rec = par_scheme
        .reconstruct_with_scheme(&big_shares[0..3])
        .unwrap();
    assert_eq!(par_rec.as_slice(), big_secret.as_slice());

    let seq_rec = ShamirShare::reconstruct(&big_shares[0..3]).unwrap();
    assert_eq!(seq_rec.as_slice(), big_secret.as_slice());
}

// ============================================================================
// 5. Streaming & Compression (F-02, F-16, F-18, F-22)
// ============================================================================

#[cfg(all(feature = "streaming", feature = "compress"))]
#[test]
fn test_streaming_unlimited_max_decompressed_size_roundtrip() {
    use std::io::Cursor;

    let secret = b"ABCDEFGH12345678";

    // 1. with_max_decompressed_stream_size(u64::MAX)
    let cfg_unlimited = Config::new()
        .with_chunk_size(4)
        .unwrap()
        .with_compression(true)
        .with_max_decompressed_stream_size(u64::MAX);
    let scheme = ShamirShare::builder(3, 2)
        .with_config(cfg_unlimited)
        .build()
        .unwrap();

    let mut writers: Vec<Cursor<Vec<u8>>> = (0..3).map(|_| Cursor::new(Vec::new())).collect();
    scheme
        .split_stream(&mut Cursor::new(&secret[..]), &mut writers)
        .unwrap();
    let bufs: Vec<Vec<u8>> = writers.into_iter().map(|c| c.into_inner()).collect();

    let mut sources: Vec<Cursor<Vec<u8>>> =
        bufs[0..2].iter().map(|b| Cursor::new(b.clone())).collect();
    let mut out: Vec<u8> = Vec::new();
    let mut sink = Cursor::new(&mut out);
    scheme
        .reconstruct_stream_with_scheme(&mut sources, &mut sink)
        .unwrap();
    assert_eq!(out.as_slice(), secret);

    // 2. with_max_decompressed_stream_size(1u64 << 32)
    let cfg_4gb = Config::new()
        .with_chunk_size(4)
        .unwrap()
        .with_compression(true)
        .with_max_decompressed_stream_size(1u64 << 32);
    let scheme_4gb = ShamirShare::builder(3, 2)
        .with_config(cfg_4gb)
        .build()
        .unwrap();

    let mut writers2: Vec<Cursor<Vec<u8>>> = (0..3).map(|_| Cursor::new(Vec::new())).collect();
    scheme_4gb
        .split_stream(&mut Cursor::new(&secret[..]), &mut writers2)
        .unwrap();
    let bufs2: Vec<Vec<u8>> = writers2.into_iter().map(|c| c.into_inner()).collect();

    let mut sources2: Vec<Cursor<Vec<u8>>> =
        bufs2[0..2].iter().map(|b| Cursor::new(b.clone())).collect();
    let mut out2: Vec<u8> = Vec::new();
    let mut sink2 = Cursor::new(&mut out2);
    scheme_4gb
        .reconstruct_stream_with_scheme(&mut sources2, &mut sink2)
        .unwrap();
    assert_eq!(out2.as_slice(), secret);
}

#[cfg(all(feature = "streaming", feature = "compress"))]
#[test]
fn test_streaming_tamper_and_truncation_rejections() {
    use std::io::Cursor;

    let secret = b"streaming rejection verification input bytes";
    let cfg = Config::new()
        .with_chunk_size(8)
        .unwrap()
        .with_compression(true);
    let scheme = ShamirShare::builder(3, 2).with_config(cfg).build().unwrap();

    let mut writers: Vec<Cursor<Vec<u8>>> = (0..3).map(|_| Cursor::new(Vec::new())).collect();
    scheme
        .split_stream(&mut Cursor::new(&secret[..]), &mut writers)
        .unwrap();
    let bufs: Vec<Vec<u8>> = writers.into_iter().map(|c| c.into_inner()).collect();

    // 1. Truncate stream mid-stream
    let mut trunc_sources = vec![
        Cursor::new(bufs[0][..bufs[0].len() / 2].to_vec()),
        Cursor::new(bufs[1].clone()),
    ];
    let mut out = Vec::new();
    let res_trunc =
        scheme.reconstruct_stream_with_scheme(&mut trunc_sources, &mut Cursor::new(&mut out));
    assert!(res_trunc.is_err(), "Mid-stream truncation must be rejected");

    // 2. Trailing bytes after EOS
    let mut trailing_buf = bufs[0].clone();
    trailing_buf.extend_from_slice(b"EXTRA_TRAILING_BYTES");
    let mut trailing_sources = vec![Cursor::new(trailing_buf), Cursor::new(bufs[1].clone())];
    out.clear();
    let res_trailing =
        scheme.reconstruct_stream_with_scheme(&mut trailing_sources, &mut Cursor::new(&mut out));
    assert!(
        matches!(res_trailing, Err(ShamirError::InvalidShareFormat)),
        "Trailing bytes after EOS must return InvalidShareFormat, got: {res_trailing:?}"
    );

    // 3. Zero-length chunk before EOS
    let mut zero_len_buf = bufs[0].clone();
    // Header is 28 bytes. The next 4 bytes are chunk length.
    zero_len_buf[28..32].copy_from_slice(&0u32.to_le_bytes());
    let mut zero_sources = vec![Cursor::new(zero_len_buf), Cursor::new(bufs[1].clone())];
    out.clear();
    let res_zero =
        scheme.reconstruct_stream_with_scheme(&mut zero_sources, &mut Cursor::new(&mut out));
    assert!(
        res_zero.is_err(),
        "Zero-length chunk before EOS must be rejected, got: {res_zero:?}"
    );

    // 4. Swap chunk 0 and chunk 1 (chunk reorder)
    let swap_chunks = |buf: &[u8]| -> Vec<u8> {
        let l0 = u32::from_le_bytes(buf[28..32].try_into().unwrap()) as usize;
        let chunk0_end = 32 + l0;
        let l1 = u32::from_le_bytes(buf[chunk0_end..chunk0_end + 4].try_into().unwrap()) as usize;
        let chunk1_end = chunk0_end + 4 + l1;

        let mut reordered = Vec::new();
        reordered.extend_from_slice(&buf[..28]); // 28-byte header
        reordered.extend_from_slice(&buf[chunk0_end..chunk1_end]); // chunk 1 first
        reordered.extend_from_slice(&buf[28..chunk0_end]); // chunk 0 second
        reordered.extend_from_slice(&buf[chunk1_end..]); // remainder (chunk 2..EOS)
        reordered
    };

    // 4a. Both shares have swapped chunks
    let mut reordered_sources = vec![
        Cursor::new(swap_chunks(&bufs[0])),
        Cursor::new(swap_chunks(&bufs[1])),
    ];
    out.clear();
    let res_reorder =
        scheme.reconstruct_stream_with_scheme(&mut reordered_sources, &mut Cursor::new(&mut out));
    assert!(
        res_reorder.is_err(),
        "Reordered chunks across all shares must be rejected, got: {res_reorder:?}"
    );

    // 4b. Single share has swapped chunks
    let mut single_reordered_sources = vec![
        Cursor::new(swap_chunks(&bufs[0])),
        Cursor::new(bufs[1].clone()),
    ];
    out.clear();
    let res_single_reorder = scheme
        .reconstruct_stream_with_scheme(&mut single_reordered_sources, &mut Cursor::new(&mut out));
    assert!(
        res_single_reorder.is_err(),
        "Single share with reordered chunks must be rejected, got: {res_single_reorder:?}"
    );
}

#[cfg(all(feature = "streaming", feature = "compress"))]
#[test]
fn test_streaming_trailing_byte_interrupted_retry() {
    use std::io::{Cursor, Error, ErrorKind, Read};

    struct InterruptedTrailingReader<R> {
        inner: R,
        interrupted_injected: bool,
    }

    impl<R: Read> Read for InterruptedTrailingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            if n == 0 && !self.interrupted_injected {
                self.interrupted_injected = true;
                return Err(Error::new(
                    ErrorKind::Interrupted,
                    "simulated interrupted read on trailing probe",
                ));
            }
            Ok(n)
        }
    }

    let secret = b"trailing byte retry probe";
    let cfg = Config::new()
        .with_chunk_size(8)
        .unwrap()
        .with_compression(true);
    let scheme = ShamirShare::builder(3, 2).with_config(cfg).build().unwrap();

    let mut writers: Vec<Cursor<Vec<u8>>> = (0..3).map(|_| Cursor::new(Vec::new())).collect();
    scheme
        .split_stream(&mut Cursor::new(&secret[..]), &mut writers)
        .unwrap();
    let bufs: Vec<Vec<u8>> = writers.into_iter().map(|c| c.into_inner()).collect();

    let mut reader0 = InterruptedTrailingReader {
        inner: Cursor::new(bufs[0].clone()),
        interrupted_injected: false,
    };
    let mut reader1 = Cursor::new(bufs[1].clone());
    let mut sources: Vec<&mut dyn Read> = vec![&mut reader0, &mut reader1];
    let mut out = Vec::new();
    let res = scheme.reconstruct_stream_with_scheme(&mut sources, &mut Cursor::new(&mut out));
    assert!(
        res.is_ok(),
        "reconstruct_stream must transparently retry and succeed on ErrorKind::Interrupted: {res:?}"
    );
    assert_eq!(out.as_slice(), secret);
    assert!(reader0.interrupted_injected);
}

#[cfg(all(feature = "streaming", feature = "compress"))]
#[test]
#[ignore]
fn test_heavy_64mib_incompressible_stream_roundtrip() {
    use std::io::Cursor;

    let chunk = 64 * 1024 * 1024usize;
    let mut data = vec![0u8; chunk];

    // Xorshift fill incompressible data
    let mut s: u64 = 0x243F_6A88_85A3_08D3;
    for c in data.chunks_mut(8) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let bytes = s.to_le_bytes();
        let n = c.len();
        c.copy_from_slice(&bytes[..n]);
    }

    let cfg = Config::new()
        .with_chunk_size(chunk)
        .unwrap()
        .with_compression(true);
    let scheme = ShamirShare::builder(2, 2).with_config(cfg).build().unwrap();

    let mut writers: Vec<Cursor<Vec<u8>>> = (0..2).map(|_| Cursor::new(Vec::new())).collect();
    scheme
        .split_stream(&mut Cursor::new(&data[..]), &mut writers)
        .expect("Heavy 64 MiB stream split failed");

    let bufs: Vec<Vec<u8>> = writers.into_iter().map(|c| c.into_inner()).collect();
    let mut sources: Vec<Cursor<Vec<u8>>> = bufs.into_iter().map(Cursor::new).collect();
    let mut out = Vec::new();
    scheme
        .reconstruct_stream_with_scheme(&mut sources, &mut Cursor::new(&mut out))
        .expect("Heavy 64 MiB stream reconstruction failed");

    assert_eq!(out.len(), data.len());
    assert_eq!(out, data);
}

// ============================================================================
// 6. Proactive Refresh (F-15, F-21)
// ============================================================================

#[cfg(all(feature = "std", feature = "refresh"))]
#[test]
fn test_refresh_proactive_consistency() {
    let secret = b"proactive refresh security verification secret";
    let s = ShamirShare::builder(3, 2).build().unwrap();
    let clean = s.split(secret).unwrap();

    let refreshed = s.refresh_shares(&clean).unwrap();
    assert_eq!(refreshed.len(), clean.len());
    assert_ne!(
        refreshed[0].data(),
        clean[0].data(),
        "Refreshed shares must have distinct share data bytes"
    );

    let rec = ShamirShare::reconstruct(&refreshed[0..2]).unwrap();
    assert_eq!(rec.as_slice(), secret);

    // Mixing old and new epoch shares MUST fail integrity check
    let mixed = vec![clean[0].clone(), refreshed[1].clone()];
    let res_mixed = s.reconstruct_with_scheme(&mixed);
    assert!(
        matches!(res_mixed, Err(ShamirError::IntegrityCheckFailed)),
        "Mixing shares across epochs must fail integrity check: {res_mixed:?}"
    );

    // Corrupted share at k < n MUST be rejected during refresh
    let mut corrupted = clean.clone();
    let mut bad_data = corrupted[1].data().to_vec();
    bad_data[70] ^= 0x01;
    corrupted[1] = Share::new(
        corrupted[1].index(),
        bad_data,
        corrupted[1].threshold(),
        corrupted[1].total_shares(),
        corrupted[1].integrity_check(),
        corrupted[1].compression(),
    )
    .unwrap();

    let res_corrupted_refresh = s.refresh_shares(&corrupted);
    assert!(
        matches!(
            res_corrupted_refresh,
            Err(ShamirError::IntegrityCheckFailed)
        ),
        "Refreshing with corrupted share below n must fail: {res_corrupted_refresh:?}"
    );
}

// ============================================================================
// 7. HSSS & Serde Probes (F-13, F-27)
// ============================================================================

#[cfg(all(feature = "std", feature = "hsss"))]
#[test]
fn test_hsss_encapsulation_and_adversarial_validation() {
    use shamir_share::hsss::{AccessLevel, HierarchicalShare, Hsss};

    // 1. AccessLevel accessors and encapsulation
    let level = AccessLevel::new("Director", 3);
    assert_eq!(level.name(), "Director");
    assert_eq!(level.shares_count(), 3);

    // 2. HierarchicalShare accessors and into_shares
    let sh = Share::new(1, vec![1, 2, 3], 2, 3, true, false).unwrap();
    let h_share = HierarchicalShare::new("Director", vec![sh]);
    assert_eq!(h_share.level_name(), "Director");
    assert_eq!(h_share.shares().len(), 1);
    let extracted = h_share.into_shares();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].index(), 1);

    // 3. Adversarial builder checks
    let thresh_too_large = Hsss::builder(5).add_level("LevelA", 2).build();
    assert!(
        thresh_too_large.is_err(),
        "Threshold exceeding total shares must be rejected"
    );

    let dup_name = Hsss::builder(2)
        .add_level("LevelA", 1)
        .add_level("LevelA", 1)
        .build();
    assert!(dup_name.is_err(), "Duplicate level names must be rejected");

    let zero_count = Hsss::builder(2).add_level("LevelA", 0).build();
    assert!(
        zero_count.is_err(),
        "Zero shares count in level must be rejected"
    );

    // 4. Split and threshold reconstruction
    let hsss = Hsss::builder(4)
        .add_level("Executive", 3)
        .add_level("Manager", 2)
        .add_level("Employee", 1)
        .with_config(Config::new().with_integrity_check(true))
        .build()
        .unwrap();

    let secret = b"hsss secret resolution";
    let p_shares = hsss.split_secret(secret).unwrap();
    assert_eq!(p_shares.len(), 3);

    // Executive (3) + Employee (1) = 4 >= threshold 4
    let rec_ok = hsss.reconstruct(&[p_shares[0].clone(), p_shares[2].clone()]);
    assert_eq!(rec_ok.unwrap().as_slice(), secret);

    // Manager (2) + Employee (1) = 3 < threshold 4
    let rec_insufficient = hsss.reconstruct(&[p_shares[1].clone(), p_shares[2].clone()]);
    assert!(
        matches!(
            rec_insufficient,
            Err(ShamirError::InsufficientShares { .. })
        ),
        "Expected InsufficientShares, got: {rec_insufficient:?}"
    );
}

#[cfg(feature = "serde")]
#[test]
fn test_serde_share_invariants_and_roundtrip() {
    let original = Share::new(1, vec![0x10, 0x20, 0x30], 2, 3, true, false).unwrap();
    let json = serde_json::to_string(&original).expect("serialize failed");
    let deserialized: Share = serde_json::from_str(&json).expect("deserialize failed");
    assert_eq!(original, deserialized);

    // Reject index == 0
    let invalid_index = r#"{"index":0,"data":[1,2,3],"threshold":2,"total_shares":3,"integrity_check":true,"compression":false}"#;
    assert!(serde_json::from_str::<Share>(invalid_index).is_err());

    // Reject threshold < 2
    let invalid_thresh = r#"{"index":1,"data":[1,2,3],"threshold":1,"total_shares":3,"integrity_check":true,"compression":false}"#;
    assert!(serde_json::from_str::<Share>(invalid_thresh).is_err());

    // Reject threshold > total_shares
    let invalid_total = r#"{"index":1,"data":[1,2,3],"threshold":5,"total_shares":3,"integrity_check":true,"compression":false}"#;
    assert!(serde_json::from_str::<Share>(invalid_total).is_err());

    // Reject compression without integrity
    let invalid_comp = r#"{"index":1,"data":[1,2,3],"threshold":2,"total_shares":3,"integrity_check":false,"compression":true}"#;
    assert!(serde_json::from_str::<Share>(invalid_comp).is_err());

    // Reject empty data payload
    let invalid_empty = r#"{"index":1,"data":[],"threshold":2,"total_shares":3,"integrity_check":true,"compression":false}"#;
    assert!(serde_json::from_str::<Share>(invalid_empty).is_err());
}

#[cfg(all(feature = "serde", feature = "hsss"))]
#[test]
fn test_serde_hsss_roundtrip() {
    use shamir_share::hsss::{AccessLevel, HierarchicalShare};

    let level = AccessLevel::new("Lead", 4);
    let level_json = serde_json::to_string(&level).unwrap();
    let level_de: AccessLevel = serde_json::from_str(&level_json).unwrap();
    assert_eq!(level.name(), level_de.name());
    assert_eq!(level.shares_count(), level_de.shares_count());

    let sh = Share::new(1, vec![5, 6, 7], 2, 3, true, false).unwrap();
    let h_share = HierarchicalShare::new("Lead", vec![sh]);
    let h_json = serde_json::to_string(&h_share).unwrap();
    let h_de: HierarchicalShare = serde_json::from_str(&h_json).unwrap();
    assert_eq!(h_share.level_name(), h_de.level_name());
    assert_eq!(h_share.shares(), h_de.shares());
}

// ============================================================================
// 8. Fuzz Corpus Replay (corpus.rs)
// ============================================================================

#[cfg(feature = "std")]
#[test]
#[ignore]
fn test_heavy_fuzz_corpus_replay() {
    use std::fs;
    use std::path::Path;

    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    if !corpus_root.exists() {
        println!(
            "fuzz/corpus not found at {:?}; skipping replay.",
            corpus_root
        );
        return;
    }

    // 1. fuzz_share_from_bytes
    let share_dir = corpus_root.join("fuzz_share_from_bytes");
    if share_dir.exists() {
        let mut ok = 0;
        let mut err = 0;
        let mut non_canonical = 0;
        for entry in fs::read_dir(share_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = fs::read(&path).unwrap();
                match Share::from_bytes(&bytes) {
                    Ok(s) => {
                        ok += 1;
                        if s.to_bytes().unwrap().as_slice() != bytes.as_slice() {
                            non_canonical += 1;
                        }
                    }
                    Err(_) => err += 1,
                }
            }
        }
        assert_eq!(non_canonical, 0, "Non-canonical decodings in fuzz corpus");
        println!("fuzz_share_from_bytes corpus: {ok} accepted, {err} rejected, 0 non-canonical");
    }

    // 2. fuzz_reconstruct_stream
    #[cfg(feature = "streaming")]
    {
        use std::io::Cursor;
        let stream_dir = corpus_root.join("fuzz_reconstruct_stream");
        if stream_dir.exists() {
            let mut count = 0;
            for entry in fs::read_dir(stream_dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_file() {
                    let data = fs::read(&path).unwrap();
                    let mut sources = vec![Cursor::new(&data[..]), Cursor::new(&data[..])];
                    let mut out = Vec::new();
                    let _ =
                        ShamirShare::reconstruct_stream(&mut sources, &mut Cursor::new(&mut out));
                    count += 1;
                }
            }
            println!("fuzz_reconstruct_stream corpus: {count} inputs replayed without panic");
        }
    }
}
