# Changelog

All notable changes to `shamir_share` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-11-21

### Breaking Changes

- **Removed `storage.rs`**: Completely eliminated `FileShareStore`, `ShareStore` trait, and all filesystem I/O. The crate now focuses solely on pure cryptographic secret sharing and in-memory operations.
  - Use `Share::to_bytes()` and `Share::from_bytes(&[u8])` for canonical wire serialization.
  - Use the optional `"serde"` feature for JSON/Bincode serialization.
- **`#![no_std]` + `alloc` Supported**:
  - The crate is `#![no_std]` compatible out-of-the-box when disabling default features (`default-features = false`).
  - Convenience methods that rely on system entropy (`ShamirShare::split`, `ShamirShare::try_dealer`, `Hsss::split_secret`, `ShamirShare::refresh_shares`, `ShamirShare::split_stream`) require the `"std"` feature.
  - In `#![no_std]` environments (embedded, WASM), use `split_with_rng`, `try_dealer_with_rng`, `split_secret_with_rng`, and `refresh_shares_with_rng` with any `rand_core::CryptoRng`.
- **Fallible `Share::to_bytes()` and `Share::new()`**:
  - `Share::to_bytes()` now returns `Result<Zeroizing<Vec<u8>>, ShamirError>`, eliminating all panic paths, returning zeroized buffers, and validating share invariants.
  - `Share::new()` now returns `Result<Self, ShamirError>`, validating indices, thresholds, compression settings, and enforcing maximum payload size bounds.
- **Private Field Encapsulation**:
  - Encapsulated internal fields of `Share`, `HierarchicalShare`, and `AccessLevel`.
  - Added public getter methods (`index()`, `threshold()`, `total_shares()`, `integrity_check()`, `compression()`, `data()`, `level_name()`, `shares()`, `name()`, `shares_count()`).
  - Added zero-copy consuming methods `Share::into_data()` (returning `Zeroizing<Vec<u8>>`) and `HierarchicalShare::into_shares()`.
- **Explicit Authenticated Reconstruction APIs**:
  - Added `reconstruct_authenticated`, `reconstruct_from_views_authenticated`, `ShamirShare::reconstruct_stream_authenticated`, and `Hsss::reconstruct_authenticated` ensuring that schemes configured without an explicit caller-held HMAC authentication key fail closed with `ShamirError::UnauthenticatedScheme`.
- **CSPRNG Trait Enforcement (`rand_core::CryptoRng`)**:
  - All `*_with_rng` entry points (`split_with_rng`, `try_dealer_with_rng`, `split_secret_with_rng`, `generate_refresh_deltas_with_rng`, `refresh_shares_with_rng`) now bound on `R: CryptoRng` instead of general `Rng`, preventing non-cryptographic PRNGs from compiling silently. Re-exported `CryptoRng` in crate root and prelude.
- **Empty-Secret Validation**:
  - Splitting an empty secret (`b""`) when `integrity_check = false` is now rejected with `ShamirError::InvalidConfig`, preventing the generation of 0-byte shares that break wire serialization and refresh invariants.
- **Proactive Refresh $k == n$ Integrity Verification & Memory Hygiene**:
  - Refreshing in $k == n$ schemes verifies the cryptographic integrity digest across active shares before mutating share data, failing closed with `ShamirError::IntegrityCheckFailed` on corruption or truncated shares. Intermediate reconstructed buffers are strictly wrapped in `Zeroizing`.
- **Bounded Serde Deserialization (DoS Protection)**:
  - `Share` and `HierarchicalShare` implement bounded element-by-element deserialization (`deserialize_seq`), capping allocations and rejecting inputs exceeding limits (64 MiB payload cap for `Share`, 255 share cap for `HierarchicalShare`).
- **Structured Error Hierarchy**:
  - Removed dead `ShareNotFound(u8)` error variant.
  - Added structured error variants: `AllocationFailed`, `ChunkIndexOverflow`, `ChunkLengthOverflow`, and `UnauthenticatedScheme`.
- **Cryptographic Domain Separation**:
  - Unkeyed SHA-256 integrity digests now use `SHS1_SHA256_V3` and `SHS1_STR_SHA256_V2` domain tags, eliminating misleading "KEYED" labels.
- **Minimum Supported Rust Version (MSRV)**:
  - Bumped MSRV to Rust 1.88 due to dependency requirements (`sha2@0.11.1`).
- **Re-exported `rand_core`**:
  - Re-exported `rand_core` and `rand_core::CryptoRng` in root and `prelude` to ensure seamless `#![no_std]` integration without version conflicts.
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
- **Type Signature of `Share::apply_refresh_delta`**: Now takes `&Share` instead of raw byte slices, ensuring the delta belongs to the matching share index and verifies scheme metadata parity.
- **Strict Share Index Bounds**: All operations now reject share index `0` or indices greater than `total_shares`.
- **Chunk Size Limit**: `MAX_CONFIG_CHUNK_SIZE` enforced at 64 MiB to bound memory consumption and avoid buffer overflow DoS.

### Fixed

- **HSSS `#![no_std]` Doctest Compilation**: Gated `split_secret` usage in doctests with `#[cfg(feature = "std")]`, resolving compilation failures when building with `--no-default-features --features "hsss"`.
- **Wire Serialization Invariant Validation**: Enforced index, threshold, compression-without-integrity, and data length bounds in `Share::to_bytes()` to ensure serialized shares strictly round-trip through `Share::from_bytes()`.
- **Proactive Share Refresh Metadata Validation**: `Share::apply_refresh_delta()` now strictly validates that `threshold`, `total_shares`, `integrity_check`, and `compression` match between base share and delta share before applying XOR refresh deltas, preventing cross-scheme corruption.
- **Disallowed Compression without Integrity Checking**: `Share::new()`, `Share::from_bytes()`, and `Share::to_bytes()` now reject `compression: true, integrity_check: false` uniformly with `ShamirError::InvalidShareFormat`.
- **Documentation Parity for Excess Shares**: Updated doc comments in `reconstruct()` and `reconstruct_from_views()` to reflect that all excess shares beyond threshold are actively verified against the interpolated polynomial in GF(2^8).
- **Documentation Parity for HSSS Scheme Pool**: Corrected HSSS concept documentation to match the builder's exact total share sum calculation ($n = \sum \text{level\_shares}$).
- **Streaming Header Parsing Robustness**: Eliminated panic path in streaming reconstruction (`headers[0][8..24].try_into()`) by propagating `ShamirError::InvalidShareFormat`.
- **HSSS Splitting Ergonomics**: Changed `Hsss::split_secret` and `split_secret_with_rng` signatures from `&mut self` to `&self`, enabling concurrent secret splitting from a shared reference without requiring mutability.
- **Excess Share Verification in Share Domain**: Evaluating Lagrange basis polynomials $L_i(x_e)$ directly in GF($2^8$) eliminates repeating $n-k$ $P(0)$ reconstructions and buffer allocations, and prevents secret plaintext materialization during proactive share refresh (while algebraic GF arithmetic for verifying $n-k$ excess shares remains $O((n-k) \cdot k \cdot L)$).
- **Eliminated Dead Unauthenticated Compression**: Compression strictly requires integrity checking; unreachable unauthenticated compression codepaths were removed.
- **Decompression Bound Hardening**: Fixed integer overflow and 32-bit truncation in bounded decompression, and replaced panicking allocations with fallible reservations.

### Added

- **Canonical Wire Format**: `Share::to_bytes()` and `Share::from_bytes(&[u8])` providing zero-dependency serialization with version 3 (`b"SHS1"`), 13-byte framing header, and strict bounds checking.
- **Optional Serde Support**: Added `#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]` on `Share`.
- **`#![no_std]` Fallback `Zeroizing`**: Built-in fallback wrapper when `"zeroize"` feature is disabled or on `#![no_std]`, performing volatile zeroing on drop and redacting secrets in `Debug`.
- **Excess Share Consistency Checking**: When more than `threshold` shares are supplied to `reconstruct` or `reconstruct_stream`, all additional shares are cross-verified against the reconstructed secret to catch any corrupted or tampered shares.
- **Strict Access Level Validation in HSSS**: Hierarchical secret reconstruction now verifies access level names and share counts to prevent mismatched shares.
- **Constant-Memory Streaming**: Streaming reconstruction operates in fixed 64 KiB block slices, keeping peak memory usage low (~64 MiB max) even with high share counts and thresholds.
- **Cumulative Buffer Budget**: Enforced 256 MiB cumulative chunk allocation budget (`chunk_size * total_shares`) in `split_stream`.
- **Fuzzing Modernization**: Added `fuzz_share_from_bytes` target exercising wire format parsing.
- **CI Feature Powerset Coverage**: Added `--no-default-features --features hsss` to GitHub Actions test matrix to prevent regressions on isolated feature builds.
- **Comprehensive Regression Test Suites**: Added test coverage for `Share::to_bytes()` invariant validation, metadata mismatch rejection in `apply_refresh_delta()`, and compression flag rejection.

### Security

- **Filesystem Attack Surface Eliminated**: Removing `storage.rs` permanently eliminates TOCTOU races, symlink follow vulnerabilities, temporary file persistence, and platform file permission discrepancies.
- **Tamper Detection**: Shares and stream chunks bind framing metadata and random salts into their integrity digests, preventing modifications, flag stripping, and truncation.
- **Constant-Time Operations**: Finite field comparisons and operations use constant-time primitives to resist timing side channels.
- **HMAC Buffer Hygiene**: Explicitly zeroized `ipad` and `opad` padding buffers during keyed HMAC digest computation.
- **Debug Redaction**: Redacted `authentication_key` in `Config` `Debug` output, and redacted sensitive share bytes in `ShareView` and fallback `Zeroizing`.
- **Memory Hygiene**: Decompressed buffers use bounded, exact reservations and zeroize on drop, eliminating unzeroized heap residue.
- **Stream Termination Guard**: Streaming reconstruction strictly validates the end-of-stream marker and rejects unexpected trailing bytes.
- **CI/CD Supply Chain Hardening**: Pinned GitHub Actions to immutable full commit SHAs, enforced `permissions: contents: read`, added tag-to-Cargo.toml version verification, and used `--locked` on `cargo publish`.
