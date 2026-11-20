# Shamir's Secret Sharing (shamir_share)

[![Crates.io](https://img.shields.io/crates/v/shamir_share.svg)](https://crates.io/crates/shamir_share)
[![Documentation](https://docs.rs/shamir_share/badge.svg)](https://docs.rs/shamir_share)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A security-first, high-performance implementation of Shamir's Secret Sharing scheme over GF(2^8) with constant-time operations, modular Cargo features, and `#![no_std]` support.

## Key Features

- **Constant-Time GF(2^8) Arithmetic**: Branchless Russian Peasant Multiplication and fixed-chain Fermat inversion resist cache-timing and execution-timing side-channels.
- **Embedded & Enclave Ready (`#![no_std]`)**: Core arithmetic, share splitting (`split_with_rng`), and reconstruction operate cleanly with only `alloc`, verifiable on WebAssembly (`wasm32-unknown-unknown`) and embedded targets. Optional features (`compress`, `parallel`, `streaming`) require `std`.
- **Canonical Binary Wire Format**: Self-contained zero-dependency wire serialization via `Share::to_bytes()` and `Share::from_bytes(&[u8])` with format version 3 (`b"SHS1"`) framing.
- **Modular Feature Architecture**: Opt-in capabilities keep your binary lean and dependencies minimal:
  - `streaming`: Large file chunked streaming I/O.
  - `hsss`: Hierarchical secret sharing with role-based access levels.
  - `refresh`: Proactive secret sharing with zero-polynomial share refreshing.
  - `parallel`: Multi-threaded parallel polynomial evaluation via Rayon.
  - `compress`: Transparent Zstandard chunk compression.
  - `serde`: Optional `serde::Serialize` and `serde::Deserialize` implementations.
  - `zeroize`: Secure memory hygiene clearing sensitive buffers on drop.
- **Authenticated Shares**: Optional caller-held 256-bit authentication key verifies shares with HMAC-SHA256 across in-memory (`reconstruct_authenticated`), streaming (`reconstruct_stream_authenticated`), and hierarchical (`Hsss::reconstruct_authenticated`) APIs, protecting against active share tampering and splicing.
- **100% Safe Rust**: `#![forbid(unsafe_code)]` enforced across the entire library core. When the optional `compress` feature is enabled, decompression links to the upstream Zstandard C implementation.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
shamir_share = "0.3.0"
```

For `#![no_std]` environments (hardware wallets, secure enclaves, embedded systems):

```toml
[dependencies]
shamir_share = { version = "0.3.0", default-features = false }
```

## Quick Start

### Basic Usage
```rust
use shamir_share::{ShamirShare, Share};

// Create a scheme with 5 shares and threshold 3
let scheme = ShamirShare::builder(5, 3).build().unwrap();

// Split a secret
let secret = b"my secret data";
let shares = scheme.split(secret).unwrap();

// Serialize shares to canonical bytes (e.g. for transmission or storage)
let serialized_shares: Vec<_> = shares.iter().map(|s| s.to_bytes().unwrap()).collect();

// Later, deserialize and reconstruct from any 3 shares
let loaded_shares: Vec<Share> = serialized_shares[0..3]
    .iter()
    .map(|b| Share::from_bytes(b).unwrap())
    .collect();

let reconstructed = ShamirShare::reconstruct(&loaded_shares).unwrap();
assert_eq!(reconstructed.as_slice(), secret);
```

### Lazy Share Generation with Dealer
```rust
use shamir_share::ShamirShare;

let scheme = ShamirShare::builder(10, 5).build().unwrap();
let secret = b"my secret data";

// Generate only the shares you need
let shares: Vec<_> = scheme.try_dealer(secret).unwrap().take(5).collect();

// Or use iterator methods for advanced filtering
let even_shares: Vec<_> = scheme.try_dealer(secret)
    .unwrap()
    .filter(|share| share.index() % 2 == 0)
    .take(5)
    .collect();

let reconstructed = ShamirShare::reconstruct(&shares).unwrap();
assert_eq!(reconstructed.as_slice(), secret);
```

### `#![no_std]` Usage
```rust
use shamir_share::{ShamirShare, Share};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

// In no_std mode, supply any Rng (from rand_core) implementation.
// WARNING: Never use a static or predictable seed in production!
// Always acquire cryptographic randomness from hardware or secure enclave entropy.
let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
let scheme = ShamirShare::builder(5, 3).build().unwrap();
let secret = b"embedded enclave secret";

let shares = scheme.split_with_rng(secret, &mut rng).unwrap();
let reconstructed = ShamirShare::reconstruct(&shares[0..3]).unwrap();
assert_eq!(reconstructed.as_slice(), secret);
```

## Feature Matrix

| Feature | Default | Description |
|---|:---:|---|
| `std` | Yes | Standard library integration, OS system entropy (`SysRng`), and I/O error bridging. |
| `zeroize` | Yes | Best-effort memory zeroization on drop for buffers, intermediate HMAC states, and keys. |
| `streaming` | Yes | Chunked streaming I/O (`split_stream` and `reconstruct_stream`). |
| `hsss` | Yes | Hierarchical secret sharing scheme (role-based access structures). |
| `refresh` | Yes | Proactive secret sharing (epoch refreshing via zero polynomials). |
| `parallel` | No | Multi-threaded CPU evaluation using Rayon parallel iterators. |
| `compress` | No | Zstandard compression before splitting. |
| `serde` | No | Serde `Serialize` and `Deserialize` support for `Share`. |

## Security Guarantees & Threat Model

- **Information-Theoretic Security**: Any set of fewer than $k$ shares reveals mathematically zero information about the secret, assuming an honest dealer and uniform cryptographic entropy (enforced via `CryptoRng`).
- **Constant-Time Execution & Timing Boundaries**: GF($2^8$) arithmetic operations (multiplication and inversion) are verified branchless to protect against cache and timing attacks. Secret length, share count $k$, excess share count $n - k$, error early-returns, and compression are **not** constant-time.
- **Accidental Corruption vs. Malicious Forgery**: When more than $k$ shares are provided, all excess shares are actively cross-verified in GF($2^8$) against the polynomial formed by the first $k$ shares. Inconsistent or accidentally corrupted excess shares will cause reconstruction to fail with `IntegrityCheckFailed`. However, excess share verification does not identify which share is rogue, nor does it protect against an active adversary possessing $k-1$ shares who crafts a rogue share targeting chosen plaintext.
- **Corruption Detection vs. Authenticity**: Unkeyed SHA-256 verification detects accidental bit-rot and framing errors. To protect against malicious share holders actively forging shares with known plaintext, configure a 256-bit authentication key with `Config::with_authentication_key` and use fail-closed authenticated reconstruction APIs (`reconstruct_authenticated`, `reconstruct_stream_authenticated`, or `Hsss::reconstruct_authenticated`).
- **Memory Hygiene Caveats**: When the `zeroize` feature is enabled, sensitive buffers, keys, and SHA-256 internal compression states are zeroized on drop. However, in safe Rust, compiler register/stack spills, operating system swap, and core dumps cannot be eliminated, and `rand_chacha 0.10` does not implement zeroization.
- **Side-Channel Caution with Compression**: When `compress` is enabled, ciphertext length varies with plaintext entropy (CRIME/BREACH style leaks). Do not enable compression for fixed-entropy secrets like cryptographic keys.

## Development & Testing

```bash
# Run all tests with all features
cargo test --all-features

# Run core tests in bare no_std mode
cargo check --target wasm32-unknown-unknown --no-default-features

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Run fuzzing
cd fuzz
cargo +nightly fuzz run fuzz_reconstruct
cargo +nightly fuzz run fuzz_share_from_bytes
cargo +nightly fuzz run fuzz_reconstruct_stream
cargo +nightly fuzz run fuzz_hsss
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
