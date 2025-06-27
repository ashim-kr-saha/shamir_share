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

### `fuzz_share_storage`
Tests the `FileShareStore::load_share` method with arbitrary file content:
- Invalid magic numbers and version numbers
- Truncated files and partial headers
- Invalid metadata fields
- Corrupted data length fields
- Files with extra trailing data
- Mismatched indices

**Goal**: Ensure share parsing never panics and handles malformed files gracefully.

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

# Run storage fuzzing for 120 seconds
./run_fuzz.sh storage 120
```

### Manual Execution
```bash
# Run reconstruct fuzzing
cargo fuzz run fuzz_reconstruct

# Run storage fuzzing
cargo fuzz run fuzz_share_storage

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
timeout 30 cargo fuzz run fuzz_share_storage || true
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