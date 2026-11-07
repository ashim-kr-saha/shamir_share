# Fuzzing for shamir_share

This directory contains fuzzing targets for the `shamir_share` library using `cargo-fuzz` and `libfuzzer-sys`.

## Overview

Fuzzing is a critical security testing technique that feeds random or semi-random data to functions to discover edge cases, panics, and potential security vulnerabilities. For a cryptographic library like `shamir_share`, fuzzing helps ensure robustness against malformed inputs and adversarial data.

## Fuzz Targets

### `fuzz_reconstruct`
Tests the `ShamirShare::reconstruct` method with arbitrary share data:
- Invalid share indices (0, duplicates, out of range)
- Inconsistent share metadata (threshold, total_shares, integrity_check)
- Malformed share data (empty, inconsistent lengths)
- Corrupted share data
- Edge cases with threshold values

**Goal**: Ensure `reconstruct` never panics and always returns a proper `Result`.

### `fuzz_share_from_bytes`
Tests the `Share::from_bytes` canonical binary deserialization with arbitrary byte content:
- Invalid magic numbers and version numbers
- Truncated bytes and partial headers
- Invalid metadata fields (index 0, threshold > total_shares)
- Corrupted data length fields
- Byte arrays with extra trailing data
- Empty byte slices

**Goal**: Ensure canonical wire parsing never panics, handles malformed bytes gracefully, and enforces roundtrip idempotence.

### `fuzz_reconstruct_stream`
Tests the `ShamirShare::reconstruct_stream` and `reconstruct_stream_with_scheme` methods with arbitrary streaming chunks:
- Invalid magic headers and version mismatch
- Truncated stream chunks and partial headers
- Mismatched stream parameters across sources
- Compression bomb limits and multi-chunk decompression ceilings
- Corrupted payload chunks and invalid integrity hashes

**Goal**: Ensure stream reconstruction never panics, handles malformed streams gracefully with `Result::Err`, and protects against unbounded memory amplification.

## Prerequisites

Install `cargo-fuzz`:
```bash
cargo install cargo-fuzz
```

## Running Fuzzing

### Quick Start
```bash
# Run all targets for 60 seconds each
./run_fuzz.sh

# Run specific target for 300 seconds
./run_fuzz.sh reconstruct 300

# Run wire format fuzzing for 120 seconds
./run_fuzz.sh wire 120
```

### Manual Execution
```bash
# Run reconstruct fuzzing
cargo fuzz run fuzz_reconstruct

# Run wire format fuzzing
cargo fuzz run fuzz_share_from_bytes

# Run with specific options
cargo fuzz run fuzz_reconstruct -- -max_total_time=300 -max_len=1000
```

## Analyzing Results

### View Crashes
```bash
# List any crashes found
ls fuzz/artifacts/

# Format and view a specific crash
cargo fuzz fmt fuzz_reconstruct artifacts/fuzz_reconstruct/crash-<hash>
```

### Reproduce Crashes
```bash
# Reproduce a specific crash
cargo fuzz run fuzz_reconstruct artifacts/fuzz_reconstruct/crash-<hash>
```

### Coverage Information
```bash
# Generate coverage report
cargo fuzz coverage fuzz_reconstruct
```

## Continuous Integration

For CI/CD pipelines, you can run fuzzing for a limited time:

```bash
# Run each target for 30 seconds in CI
timeout 30 cargo fuzz run fuzz_reconstruct || true
timeout 30 cargo fuzz run fuzz_share_from_bytes || true
```

## Expected Behavior

The fuzzing targets should:
- ✅ **Never panic** - All functions should handle invalid input gracefully
- ✅ **Return proper Results** - Use `Result<T, ShamirError>` for error handling
- ✅ **Maintain security properties** - No information leakage through timing or errors
- ✅ **Handle edge cases** - Gracefully reject malformed data

## Common Issues Found by Fuzzing

Fuzzing typically discovers:
- **Integer overflow/underflow** in length calculations
- **Buffer overruns** when reading file data
- **Panic conditions** with unexpected input combinations
- **Memory safety issues** (though Rust prevents most of these)
- **Logic errors** in validation code

## Performance Considerations

- Fuzzing is CPU-intensive and may take significant time
- Limit input size (`-max_len`) for faster iteration
- Use shorter durations for development, longer for thorough testing
- Consider running overnight for comprehensive coverage

## Integration with Development

1. **Before releases**: Run extended fuzzing sessions
2. **After major changes**: Quick fuzz runs to catch regressions
3. **CI/CD**: Short fuzz runs as part of test suite
4. **Security audits**: Extended fuzzing with multiple targets