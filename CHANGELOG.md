# Changelog

All notable changes to `shamir_share` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-11-06

### Breaking Changes

#### 1. Removal of `ShamirShare::dealer`
The panicking method `ShamirShare::dealer(&mut self, secret: &[u8]) -> Dealer` has been removed. Callers must now use the fallible [`ShamirShare::try_dealer(&mut self, secret: &[u8]) -> Result<Dealer, ShamirError>`](https://docs.rs/shamir_share/latest/shamir_share/struct.ShamirShare.html#method.try_dealer).

**Reasoning:** Polynomial coefficient generation and secret compression can fail due to system entropy exhaustion (`rand::rngs::SysRng`) or invalid compression configurations. A library API in cryptography should never hide potential failure modes behind an implicit `.expect()` panic.

**Migration Guide:**
```rust
// Before (v0.2.x):
let shares: Vec<_> = scheme.dealer(secret).take(3).collect();

// After (v0.3.0):
let shares: Vec<_> = scheme.try_dealer(secret)?.take(3).collect();
```

#### 2. Streaming Protocol Framing Upgrade (Version 1)
Streaming secretly shared data (`split_stream` and `reconstruct_stream`) now uses an authenticated 28-byte stream header:
- `STREAM_MAGIC`: `b"SHS_STR"` (7 bytes)
- `STREAM_VERSION`: `1u8` (1 byte)
- `stream_id`: 128-bit cryptographically random nonce generated from `SysRng` (16 bytes)
- `flags`: `u8` (bit 0: SHA-256 integrity check, bit 1: zstd compression)
- `index`: Share index (1 byte)
- `threshold`: Required threshold $k$ (1 byte)
- `total_shares`: Total shares $n$ (1 byte)

Streams end with an explicit terminal 4-byte `0u32` end-of-stream marker, and each chunk includes a 1-chunk lookahead `is_last` boolean flag authenticated under SHA-256. 

**Impact:** Streams generated with v0.2.x are incompatible with v0.3.0 stream reconstruction.

#### 3. Strict Share Count in `refresh_shares`
`refresh_shares` now strictly requires exactly all `total_shares` shares (`shares.len() == total_shares as usize`). 

**Reasoning:** In proactive secret sharing over linear Shamir schemes, refreshing only a threshold subset $k < n$ changes the polynomial, rendering all remaining $n - k$ unrefreshed shares permanently invalid and corrupted. Supplying fewer than `total_shares` returns `ShamirError::InsufficientShares`; supplying more returns `ShamirError::InvalidShareFormat`.

#### 4. Strict Share Index Upper Bounds
All reconstruction and storage entry points now enforce `1 <= index <= total_shares`:
- `ShamirShare::reconstruct` and `reconstruct_from_views`
- `ShamirShare::reconstruct_stream`
- `ShamirShare::refresh_shares`
- `FileShareStore::store_share` and `load_share`

Passing `index == 0` or `index > total_shares` now consistently returns `ShamirError::InvalidShareIndex(index)`.

---

### Security & Hardening Improvements

- **Bounded Decompression:** `decompress_bounded` prevents decompression bombs by enforcing a strict 64 MiB ceiling (`MAX_DECOMPRESSED_CHUNK_SIZE`) and verifying EOF, returning `ShamirError::DecompressionError` instead of truncating or exhausting host memory.
- **Framing & Headroom Alignment:** `MAX_STREAM_CHUNK_SIZE` and `MAX_SHARE_DATA_LEN` are expanded to `(64 * 1024 * 1024) + (256 * 1024) + 256` bytes to safely accommodate worst-case incompressible zstd expansion and framing.
- **Constant-Time Field Operations:** `FiniteField::multiply` and `FiniteField::exp` use `subtle::Choice` and `subtle::ConditionallySelectable::conditional_select` on `u8` to prevent micro-architectural timing side channels.
- **Zero-Copy Memory Hygiene:** Intermediate reconstruction buffers, zero-polynomial deltas, and stream chunks are zeroized on drop with `zeroize::Zeroizing`. Buffer transfers use `std::mem::take` and in-place `drain(..HASH_SIZE)` to eliminate unnecessary heap copies.
- **Atomic File Store:** `FileShareStore::store_share` writes to randomized temporary files (`.share_XXX_<nonce>.tmp`) with `O_CREAT | O_EXCL` (`create_new`), flushes, syncs file and parent directory descriptors, and renames atomically to prevent race conditions or symlink attacks.
- **Quadratic Duplicate Loop Guards:** `reconstruct_from_views` and `reconstruct_stream` validate slice lengths against `total_shares` before duplicate index loops, bounding worst-case comparisons to $\le 255$.

