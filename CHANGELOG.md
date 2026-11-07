# Changelog

All notable changes to `shamir_share` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-11-07

### Breaking Changes

- **Removed `storage.rs`**: Completely eliminated `FileShareStore`, `ShareStore` trait, and all filesystem I/O. The crate now focuses solely on pure cryptographic secret sharing and in-memory operations.
  - Use `Share::to_bytes()` and `Share::from_bytes(&[u8])` for canonical wire serialization.
  - Use the optional `"serde"` feature for JSON/Bincode serialization.
- **`#![no_std]` + `alloc` by Default**:
  - The crate is now `#![no_std]` compatible out-of-the-box.
  - Convenience methods that rely on system entropy (`ShamirShare::split`, `ShamirShare::try_dealer`, `Hsss::split_secret`, `ShamirShare::refresh_shares`, `ShamirShare::split_stream`) require the `"std"` feature.
  - In `#![no_std]` environments (embedded, WASM), use `split_with_rng`, `try_dealer_with_rng`, `split_secret_with_rng`, and `refresh_shares_with_rng` with any `rand_core::Rng`.
- **Modular Feature Flags**:
  - `default = ["std", "zeroize", "streaming", "hsss", "refresh"]`
  - High-level capabilities are now individually toggled via Cargo features:
    - `"streaming"`: `split_stream` and `reconstruct_stream` I/O routines.
    - `"hsss"`: Hierarchical Shamir Secret Sharing module.
    - `"refresh"`: Proactive share refresh routines.
    - `"parallel"`: Rayon multi-threaded polynomial evaluation and reconstruction.
    - `"compress"`: Zstandard compression and decompression.
    - `"serde"`: Serde `Serialize` and `Deserialize` derivations on `Share`.
- **Removed `ShamirShare::dealer`**: Replaced with the fallible method `ShamirShare::try_dealer` (and `#![no_std]` variant `try_dealer_with_rng`) to safely return an error if entropy generation fails instead of panicking.
- **Updated Share & Stream Wire Formats**: In-memory shares and stream formats now include cryptographically random salts and bind scheme metadata into integrity digests to protect against share tampering. Shares and streams created with v0.2.x cannot be reconstructed with v0.3.0.
- **Strict Share Count in `refresh_shares`**: Refreshing shares now strictly requires all `total_shares` to prevent invalidating remaining shares.
- **Type Signature of `Share::apply_refresh_delta`**: Now takes `&Share` instead of raw byte slices, ensuring the delta belongs to the matching share index.
- **Strict Share Index Bounds**: All operations now reject share index `0` or indices greater than `total_shares`.
- **Chunk Size Limit**: `MAX_CONFIG_CHUNK_SIZE` enforced at 64 MiB to bound memory consumption and avoid buffer overflow DoS.

### Added

- **Canonical Wire Format**: `Share::to_bytes()` and `Share::from_bytes(&[u8])` providing zero-dependency serialization with version 3 (`b"SHS1"`), 13-byte framing header, and strict bounds checking.
- **Optional Serde Support**: Added `#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]` on `Share`.
- **`#![no_std]` Fallback `Zeroizing`**: Built-in fallback wrapper when `"zeroize"` feature is disabled or on `#![no_std]`, performing volatile zeroing on drop and redacting secrets in `Debug`.
- **Excess Share Consistency Checking**: When more than `threshold` shares are supplied to `reconstruct` or `reconstruct_stream`, all additional shares are cross-verified against the reconstructed secret to catch any corrupted or tampered shares.
- **Strict Access Level Validation in HSSS**: Hierarchical secret reconstruction now verifies access level names and share counts to prevent mismatched shares.
- **Constant-Memory Streaming**: Streaming reconstruction operates in fixed 64 KiB block slices, keeping peak memory usage low (~64 MiB max) even with high share counts and thresholds.
- **Cumulative Buffer Budget**: Enforced 256 MiB allocation limit on `chunk_size * total_shares` in `split_stream`.
- **Fuzzing Modernization**: Added `fuzz_share_from_bytes` target exercising wire format parsing.

### Security

- **Filesystem Attack Surface Eliminated**: Removing `storage.rs` permanently eliminates TOCTOU races, symlink follow vulnerabilities, temporary file persistence, and platform file permission discrepancies.
- **Tamper Detection**: Shares and stream chunks bind framing metadata and random salts into their integrity digests, preventing modifications, flag stripping, and truncation.
- **Constant-Time Operations**: Finite field comparisons and operations use constant-time primitives to resist timing side channels.
- **HMAC Buffer Hygiene**: Explicitly zeroized `ipad` and `opad` padding buffers during keyed HMAC digest computation.
- **Debug Redaction**: Redacted `authentication_key` in `Config` `Debug` output, and redacted sensitive share bytes in `ShareView` and fallback `Zeroizing`.
- **Memory Hygiene**: Decompressed buffers shrink to fit without unzeroized heap residue.
- **Stream Termination Guard**: Streaming reconstruction strictly validates the end-of-stream marker and rejects unexpected trailing bytes.
- **CI/CD Supply Chain Hardening**: Pinned GitHub Actions to immutable full commit SHAs, enforced `permissions: contents: read`, added tag-to-Cargo.toml version verification, and used `--locked` on `cargo publish`.
