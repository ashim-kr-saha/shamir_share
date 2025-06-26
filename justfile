#!/usr/bin/env just --justfile

# List all available commands
default:
    @just --list

# Run all tests with logging enabled
test:
    RUST_LOG=info cargo test --release -- --test-threads=1

# Run tests with coverage report
coverage:
    cargo install cargo-tarpaulin
    cargo tarpaulin --out Html

# Run benchmarks
bench:
    cargo bench

bench-streaming:
    cargo bench --bench streaming_benchmarks

bench-shamir:
    cargo bench --bench shamir_benchmarks

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Build documentation
docs:
    cargo doc --no-deps --document-private-items
    @echo "Documentation built at target/doc/security/index.html"

# Run security audit
audit:
    cargo install cargo-audit
    cargo audit

# Run security checks for side-channel vulnerabilities
security-scan:
    @echo "Checking for potential side-channel vulnerabilities..."
    @echo "Looking for lookup tables indexed by secret data..."
    @grep -r --include="*.rs" "\\[.*\\.0.*\\]\\[.*\\.0.*\\]" src || echo "No suspicious table lookups found."
    @echo "Looking for non-constant-time comparisons of secret data..."
    @grep -r --include="*.rs" "if.*==.*secret" src || echo "No suspicious comparisons found."

# Clean build artifacts
clean:
    cargo clean

# Build in release mode
build-release:
    cargo build --release

# Run all checks (format, lint, test)
check: fmt lint test

# Generate and view test coverage report
coverage-report: coverage
    @echo "Opening coverage report..."
    open tarpaulin-report.html

# Run fuzzing tests (requires cargo-fuzz)
fuzz:
    cargo install cargo-fuzz
    cargo fuzz run fuzz_target_1 -- -max_total_time=3600

# Install development dependencies
setup-dev:
    cargo install cargo-audit cargo-tarpaulin cargo-fuzz cargo-watch just

# Watch for changes and run tests
watch:
    cargo watch -x test

# Generate documentation and open in browser
docs-open: docs
    @echo "Opening documentation..."
    open target/doc/security/index.html

# Run performance profiling
profile:
    cargo install flamegraph
    CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --bench benchmark

# Run custom performance test
perf-test:
    @echo "Building and running performance test..."
    rustc --edition 2024 -O performance_test.rs -L target/release/deps --extern shamir_share=$(find target/release/deps -name "libshamir_share*.rlib" | head -n 1)
    ./performance_test

# Build release and run performance test
perf-test-full: build-release
    @echo "Building and running performance test with latest release build..."
    rustc --edition 2024 -O performance_test.rs -L target/release/deps --extern shamir_share=$(find target/release/deps -name "libshamir_share*.rlib" | head -n 1)
    ./performance_test

# Run performance comparison across different configurations
perf-compare: build-release
    @echo "Building and running performance comparison..."
    rustc --edition 2024 -O performance_compare.rs -L target/release/deps --extern shamir_share=$(find target/release/deps -name "libshamir_share*.rlib" | head -n 1)
    ./performance_compare

# Run all performance tests and generate a report
perf-report: perf-test-full perf-compare
    @echo "\n=== Performance Report Summary ==="
    @echo "See above for detailed results"
    @echo "The implementation prioritizes security over raw performance"
    @echo "All cryptographic operations use constant-time algorithms to prevent side-channel attacks"

# Check for outdated dependencies
outdated:
    cargo install cargo-outdated
    cargo outdated

# Update dependencies
update:
    cargo update

# Run security checks
security-check: audit security-scan
    cargo deny check advisories

# Generate and view documentation with examples
docs-with-examples: docs
    cargo test --doc
    open target/doc/security/index.html

# Run all CI checks
ci: fmt lint test audit security-check

# Create a new release
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating release {{version}}"
    cargo test
    cargo clippy -- -D warnings
    cargo fmt -- --check
    cargo build --release
    git tag -a v{{version}} -m "Release {{version}}"
    echo "Release v{{version}} created"