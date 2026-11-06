# Changelog

All notable changes to `shamir_share` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-11-06

### Breaking Changes

- **Removed `ShamirShare::dealer`**: Replaced with the fallible method `ShamirShare::try_dealer` to safely return an error if system entropy generation fails instead of panicking.
  ```rust
  // Before (v0.2.x):
  let shares: Vec<_> = scheme.dealer(secret).take(3).collect();

  // After (v0.3.0):
  let shares: Vec<_> = scheme.try_dealer(secret)?.take(3).collect();
  ```
- **Updated Share & Stream Wire Formats**: In-memory shares and stream formats now include cryptographically random salts and bind scheme metadata into integrity digests to protect against share tampering. Shares and streams created with v0.2.x cannot be reconstructed with v0.3.0.
- **Strict Share Count in `refresh_shares`**: Refreshing shares now strictly requires all `total_shares` to prevent invalidating remaining shares.
- **Type Signature of `Share::apply_refresh_delta`**: Now takes `&Share` instead of raw byte slices, ensuring the delta belongs to the matching share index.
- **Strict Share Index Bounds**: All operations now reject share index `0` or indices greater than `total_shares`.

### Added

- **Excess Share Consistency Checking**: When more than `threshold` shares are supplied to `reconstruct` or `reconstruct_stream`, all additional shares are cross-verified against the reconstructed secret to catch any corrupted or tampered shares.
- **Strict Access Level Validation in HSSS**: Hierarchical secret reconstruction now verifies access level names and share counts to prevent mismatched shares.
- **Constant-Memory Streaming**: Streaming reconstruction operates in fixed 64 KiB block slices, keeping peak memory usage low (~64 MiB max) even with high share counts and thresholds.

### Changed

- **ShareView Debug Redaction**: Debug formatting for `ShareView` now redacts sensitive share bytes (`[REDACTED]`), matching `Share`.
- **Storage Hardening**: `FileShareStore` enforces restrictive directory permissions on Unix (`0o700`), cleans up orphaned temporary files on startup, and rejects symbolic links.

### Security

- **Tamper Detection**: Shares and stream chunks bind framing metadata and random salts into their integrity digests, preventing modifications, flag stripping, and truncation.
- **Constant-Time Operations**: Finite field comparisons and operations use constant-time primitives to resist timing side channels.
- **Memory Hygiene**: Decompressed buffers shrink to fit and file persistence writes directly without unzeroized heap residue.
- **Stream Termination Guard**: Streaming reconstruction strictly validates the end-of-stream marker and rejects unexpected trailing bytes.
