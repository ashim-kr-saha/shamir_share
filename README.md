# shamir_share

A secure and efficient Rust library for Shamir's Secret Sharing, designed for splitting and reconstructing sensitive data across multiple locations.

[![Crates.io](https://img.shields.io/crates/v/shamir_share.svg)](https://crates.io/crates/shamir_share)
[![Documentation](https://docs.rs/shamir_share/badge.svg)](https://docs.rs/shamir_share)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`shamir_share` provides a robust implementation of Shamir's Secret Sharing scheme as a Rust library. It allows you to split sensitive data (such as database files) into multiple shares, where the original data can only be reconstructed when a predetermined number of shares are combined.

### Key Features

- Split data into customizable number of shares (n)
- Define threshold (k) for minimum shares needed for reconstruction
- **Strong Security Features:**
  - Secure random number generation using `ChaCha20Rng`
  - Constant-time cryptographic operations to prevent side-channel attacks
  - SHA-256 integrity verification of reconstructed secrets
  - Magic number and version checks for share file format
- Zero-copy operations for efficient memory usage
- Streaming support for large files
- Cross-platform compatibility
- Comprehensive error handling

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
shamir_share = "0.1.0"
```

## Quick Start

```rust
use shamir_share::{ShamirShare, FileShareStore, ShareStore};

// Create a scheme with 5 shares and threshold 3
let mut scheme = ShamirShare::new(5, 3).unwrap();

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

## Usage Examples

### Basic Usage

```rust
use shamir_share::{ShamirShare, FileShareStore, ShareStore};
use std::path::Path;

// Create a new ShamirShare instance with 5 shares, threshold of 3
let mut shamir = ShamirShare::new(5, 3)?;

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

### Custom Configuration

```rust
use shamir_share::{Config, ShamirShare, SplitMode};

// Create a custom configuration
let config = Config::new()
    .with_chunk_size(1024)?
    .with_mode(SplitMode::Sequential)
    .with_compression(true)
    .with_integrity_check(true);

// Use the configuration when creating shares
let mut shamir = ShamirShare::new(5, 3)?;
// ... proceed with splitting and reconstruction
```

## Security Considerations

- **Cryptographically Secure Random Generation**: The implementation uses `ChaCha20Rng` seeded from `OsRng` for polynomial creation, ensuring that each set of shares is unique and unpredictable.
- **Constant-Time Cryptographic Operations**: All finite field arithmetic operations (multiplication, inversion, etc.) are implemented using constant-time algorithms to prevent timing side-channel attacks. This is a deliberate security-performance tradeoff that prioritizes security over raw speed.
- **Data Integrity**: SHA-256 hash verification ensures data integrity when reconstructing secrets. The hash is prepended to the secret before splitting and verified during reconstruction using constant-time comparison.
- **File Format Security**: Share files include magic numbers and version information to prevent format attacks and ensure compatibility.
- **Share Distribution**: It is the responsibility of the user to distribute and store the shares in a secure manner. For example, storing shares on different physical devices or in different cloud storage regions.

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
- `Share`: Represents a single share of the secret
- `FileShareStore`: File-based storage for shares
- `ShareStore`: Trait for implementing custom storage backends
- `Config`: Configuration options for the sharing process
- `SplitMode`: Enum for specifying how data is split (Sequential or Parallel)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache 2.0 licensed - see the LICENSE file for details.
