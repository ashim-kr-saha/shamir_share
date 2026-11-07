# Shamir's Secret Sharing (shamir_share)

[![Crates.io](https://img.shields.io/crates/v/shamir_share.svg)](https://crates.io/crates/shamir_share)
[![Documentation](https://docs.rs/shamir_share/badge.svg)](https://docs.rs/shamir_share)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A security-first, high-performance implementation of Shamir's Secret Sharing scheme over GF(2^8) with constant-time operations, modular Cargo features, and `#![no_std]` support.

## Key Features

- **Constant-Time GF(2^8) Arithmetic**: Branchless Russian Peasant Multiplication and fixed-chain Fermat inversion resist cache-timing and execution-timing side-channels.
- **Embedded & Enclave Ready (`#![no_std]`)**: Core arithmetic, share splitting (`split_with_rng`), and reconstruction operate cleanly with only `alloc`, verifiable on WebAssembly (`wasm32-unknown-unknown`) and embedded targets.
- **Canonical Binary Wire Format**: Self-contained zero-dependency wire serialization via `Share::to_bytes()` and `Share::from_bytes(&[u8])` with format version 3 (`b"SHS1"`) framing.
- **Modular Feature Architecture**: Opt-in capabilities keep your binary lean and dependencies minimal:
  - `streaming`: Large file chunked streaming I/O.
  - `hsss`: Hierarchical secret sharing with role-based access levels.
  - `refresh`: Proactive secret sharing with zero-polynomial share refreshing.
  - `parallel`: Multi-threaded parallel polynomial evaluation via Rayon.
  - `compress`: Transparent Zstandard chunk compression.
  - `serde`: Optional `serde::Serialize` and `serde::Deserialize` implementations.
  - `zeroize`: Secure memory hygiene clearing sensitive buffers on drop.
- **Authenticated Shares**: Optional caller-held 256-bit authentication key verifies shares with HMAC-SHA256, protecting against active share tampering and splicing.
- **100% Safe Rust**: `#![forbid(unsafe_code)]` enforced across the entire library.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
shamir_share = "0.4.0"
```

For `#![no_std]` environments (hardware wallets, secure enclaves, embedded systems):

```toml
[dependencies]
shamir_share = { version = "0.4.0", default-features = false, features = ["alloc"] }
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
let serialized_shares: Vec<Vec<u8>> = shares.iter().map(|s| s.to_bytes()).collect();

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
    .filter(|share| share.index % 2 == 0)
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

// In no_std mode, supply any RngCore implementation
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
| `zeroize` | Yes | Hardware-grade memory zeroization on drop for buffers, RNG states, and HMAC keys. |
| `streaming` | Yes | Chunked streaming I/O (`split_stream` and `reconstruct_stream`). |
| `hsss` | Yes | Hierarchical secret sharing scheme (role-based access structures). |
| `refresh` | Yes | Proactive secret sharing (epoch refreshing via zero polynomials). |
| `parallel` | No | Multi-threaded CPU evaluation using Rayon parallel iterators. |
| `compress` | No | Zstandard compression before splitting. |
| `serde` | No | Serde `Serialize` and `Deserialize` support for `Share`. |

## Security Guarantees & Threat Model

- **Information-Theoretic Security**: Any set of fewer than $k$ shares reveals mathematically zero information about the secret.
- **Constant-Time Execution**: Arithmetic routines are verified branchless to protect against cache and timing attacks.
- **Corruption Detection vs. Authenticity**: Unkeyed SHA-256 verification detects accidental bit-rot and framing errors. To protect against malicious share holders actively forging shares with known plaintext, configure a 256-bit authentication key with `Config::with_authentication_key`.
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
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
