#!/usr/bin/env just --justfile

# List all available commands
default:
    @just --list

# Run all tests with logging enabled
test:
    RUST_LOG=info cargo test --release --locked -- --test-threads=1

# Run tests with coverage report
coverage:
    cargo install cargo-tarpaulin
    cargo tarpaulin --out Html

# Run benchmarks
bench:
    cargo bench --locked

bench-streaming:
    cargo bench --bench streaming_benchmarks

bench-shamir:
    cargo bench --bench in_memory_benchmarks

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Build documentation
docs:
    cargo doc --no-deps --document-private-items
    @echo "Documentation built at target/doc/shamir_share/index.html"

# Run security audit
audit:
    cargo install cargo-audit
    cargo audit

# Run security checks and static analysis
security-scan:
	@echo "Checking that unsafe code is forbidden..."
	@grep -rn "#!\[forbid(unsafe_code)\]" src/lib.rs
	@echo "Running clippy security lints..."
	cargo clippy --all-targets --all-features -- -D warnings

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
    cargo fuzz run fuzz_reconstruct -- -max_total_time=3600

# Run stream reconstruction fuzzing
fuzz-stream:
    cargo fuzz run fuzz_reconstruct_stream -- -max_total_time=3600

# Run storage fuzzing
fuzz-storage:
    cargo fuzz run fuzz_share_storage -- -max_total_time=3600

# Install development dependencies
setup-dev:
    cargo install cargo-audit cargo-tarpaulin cargo-fuzz cargo-watch cargo-deny just

# Watch for changes and run tests
watch:
    cargo watch -x test

# Generate documentation and open in browser
docs-open: docs
    @echo "Opening documentation..."
    open target/doc/shamir_share/index.html

# Run performance profiling
profile:
    cargo install flamegraph
    CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --bench benchmark

# Run custom performance test
perf-test:
    @echo "Running performance test example..."
    cargo run --release --example performance_test

# Build release and run performance test
perf-test-full: build-release
    @echo "Running performance test with release build..."
    cargo run --release --example performance_test

# Run performance comparison across different configurations
perf-compare: build-release
    @echo "Running performance comparison..."
    cargo run --release --example performance_compare

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
    cargo deny check

# Generate and view documentation with examples
docs-with-examples: docs
    cargo test --doc --locked
    open target/doc/shamir_share/index.html

# Run all CI checks
ci: fmt lint test audit security-check

# Create a new release
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating release {{version}}"
    git diff --quiet && git diff --cached --quiet || { echo "Working tree is dirty"; exit 1; }
    grep -q '^version = "{{version}}"' Cargo.toml || { echo "Cargo.toml version mismatch with release version {{version}}"; exit 1; }
    cargo test --locked
    cargo clippy --all-targets --all-features --locked -- -D warnings
    cargo fmt -- --check
    cargo build --release --locked
    git tag -a v{{version}} -m "Release {{version}}"
    echo "Release v{{version}} created"