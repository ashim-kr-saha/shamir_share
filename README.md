# shamir_share

A secure and efficient Rust library for Shamir's Secret Sharing, built with a security-first, constant-time design to prevent side-channel attacks. Split sensitive data into multiple shares where only a threshold number is needed for reconstruction.

[![Crates.io](https://img.shields.io/crates/v/shamir_share.svg)](https://crates.io/crates/shamir_share)
[![Documentation](https://docs.rs/shamir_share/badge.svg)](https://docs.rs/shamir_share)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`shamir_share` provides a robust implementation of Shamir's Secret Sharing scheme as a Rust library. It allows you to split sensitive data (such as database files) into multiple shares, where the original data can only be reconstructed when a predetermined number of shares are combined.

### Key Features

- **Flexible Share Generation:**
  - Split data into customizable number of shares (n)
  - Define threshold (k) for minimum shares needed for reconstruction
  - Lazy iterator-based share generation with `Dealer` for memory efficiency
  - Support for up to 255 shares (GF(256) field limitation)
- **Strong Security Features:**
  - Secure random number generation using `ChaCha20Rng`
  - Constant-time cryptographic operations to prevent side-channel attacks
  - SHA-256 integrity verification of reconstructed secrets
  - Magic number and version checks for share file format
  - Comprehensive fuzzing for robustness testing
- **Performance & Usability:**
  - Zero-copy operations for efficient memory usage
  - Streaming support for large files
  - Builder pattern for ergonomic configuration
  - Cross-platform compatibility
  - Comprehensive error handling

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
shamir_share = "0.1.0"
```

## Quick Start

### Basic Usage
```rust
use shamir_share::{ShamirShare, FileShareStore, ShareStore};

// Create a scheme with 5 shares and threshold 3
let mut scheme = ShamirShare::builder(5, 3).build().unwrap();

// Split a secret
let secret = b"my secret data";
let shares = scheme.split(secret).unwrap();

// Store shares
let temp_dir = tempfile::tempdir().unwrap();
let mut store = FileShareStore::new(temp_dir.path()).unwrap();
for share in &shares {
    store.store_share(share).unwrap();
}

// Reconstruct from 3 shares
let loaded_shares = vec![
    store.load_share(1).unwrap(),
    store.load_share(2).unwrap(),
    store.load_share(3).unwrap(),
];
let reconstructed = ShamirShare::reconstruct(&loaded_shares).unwrap();
assert_eq!(reconstructed, secret);
```

### Lazy Share Generation with Dealer
```rust
use shamir_share::ShamirShare;

let mut scheme = ShamirShare::builder(10, 5).build().unwrap();
let secret = b"my secret data";

// Generate only the shares you need
let shares: Vec<_> = scheme.dealer(secret).take(5).collect();

// Or use iterator methods for advanced filtering
let even_shares: Vec<_> = scheme.dealer(secret)
    .filter(|share| share.index % 2 == 0)
    .take(5)
    .collect();

let reconstructed = ShamirShare::reconstruct(&shares).unwrap();
assert_eq!(reconstructed, secret);
```

## Usage Examples

### Basic Usage

```rust
use shamir_share::{ShamirShare, FileShareStore, ShareStore};
use std::path::Path;

// Create a new ShamirShare instance with 5 shares, threshold of 3
let mut shamir = ShamirShare::builder(5, 3).build()?;

// Split a secret
let secret = b"This is a secret message";
let shares = shamir.split(secret)?;

// Store shares in a directory
let store = FileShareStore::new(Path::new("/path/to/shares"))?;
for share in &shares {
    store.store_share(share)?;
}

// Later, reconstruct the secret using at least 3 shares
let mut reconstruction_shares = Vec::new();
for i in 1..=3 {
    reconstruction_shares.push(store.load_share(i)?);
}

let reconstructed = ShamirShare::reconstruct(&reconstruction_shares)?;
assert_eq!(&reconstructed, secret);
```

## Security

This library is designed with security as the primary concern, implementing multiple layers of protection against various attack vectors:

### Cryptographic Security Guarantees

- **Constant-Time GF(2^8) Arithmetic**: All finite field operations use constant-time algorithms with no lookup tables, preventing cache-timing side-channel attacks
- **Resistant to Side-Channel Attacks**: Russian Peasant Multiplication and Fermat's Little Theorem for inversion ensure consistent execution time regardless of input values
- **Cryptographically Secure Random Number Generation**: Uses `ChaCha20Rng` seeded from `OsRng` for polynomial coefficient generation
- **Integrity Checking**: SHA-256 hash verification with constant-time comparison prevents tampering detection
- **No Information Leakage**: Individual shares reveal no information about the secret without meeting the threshold

### Implementation Security Features

- **Memory Safety**: Written in Rust with zero unsafe code blocks
- **Constant-Time Hash Comparison**: Prevents timing attacks during integrity verification
- **Secure Share Format**: Magic numbers and version checks prevent format confusion attacks
- **Parallel Processing**: Uses Rayon for safe parallel computation without compromising security

### Security Considerations for Users

- **Share Distribution**: Distribute and store shares in different physical locations
- **Access Control**: Implement proper access controls for share storage locations
- **Network Security**: Use secure channels when transmitting shares over networks

### Security-Performance Tradeoff

This library prioritizes security over raw performance. The constant-time implementations of cryptographic operations protect against side-channel attacks but are slower than lookup table-based approaches. For typical use cases (secrets under a few MB), the performance impact is minimal:

| Operation | 1KB Secret | 10KB Secret | 100KB Secret |
|-----------|------------|-------------|--------------|
| Split     | ~160 us    | ~550 us     | ~3.4 ms      |
| Reconstruct| ~80 us     | ~170 us     | ~680 us      |
| Total     | ~240 us    | ~720 us     | ~4.1 ms      |

## API Documentation

For detailed API documentation, please visit [docs.rs/shamir_share](https://docs.rs/shamir_share).

### Core Types

- `ShamirShare`: Main implementation of Shamir's Secret Sharing scheme
- `ShamirShareBuilder`: Builder pattern for configuring `ShamirShare` instances
- `Dealer`: Lazy iterator for generating shares on-demand
- `Share`: Represents a single share of the secret
- `FileShareStore`: File-based storage for shares
- `ShareStore`: Trait for implementing custom storage backends
- `Config`: Configuration options for the sharing process
- `SplitMode`: Enum for specifying how data is split (Sequential or Parallel)

## Development & Testing

### Running Tests
```bash
# Run all tests
cargo test

# Run tests with coverage
cargo test --all-features

# Run benchmarks
cargo bench
```

### Fuzzing for Security
This library includes comprehensive fuzzing targets to ensure robustness against malformed inputs:

```bash
# Install nightly Rust and cargo-fuzz
rustup install nightly
cargo +nightly install cargo-fuzz

# Run fuzzing targets
cd fuzz
cargo +nightly fuzz run fuzz_reconstruct    # Test reconstruction logic
cargo +nightly fuzz run fuzz_share_storage  # Test share parsing logic

# Or use the convenience script
./run_fuzz.sh all 300  # Run all targets for 5 minutes each
```

The fuzzing targets test:
- **Reconstruction robustness**: Invalid shares, corrupted data, edge cases
- **Storage parsing**: Malformed files, truncated data, invalid headers
- **Memory safety**: Buffer overruns, integer overflows, panic conditions

### Performance Testing
```bash
# Run streaming benchmarks
./run_streaming_benchmarks.sh

# Compare with baseline
cargo run --release --bin performance_compare
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

### Security Considerations for Contributors

- All cryptographic operations must be constant-time
- New features should include comprehensive fuzzing targets
- Performance changes should be benchmarked
- Security-sensitive code requires additional review

## License

This project is licensed under the MIT License - see the LICENSE file for details.
