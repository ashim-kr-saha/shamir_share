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
    @which cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
    cargo audit

# Run complete pre-release verification pipeline
audit-full:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> 1/13: fmt check"
    cargo fmt --all -- --check
    echo "==> 2/13: clippy all-targets all-features"
    cargo clippy --locked --all-targets --all-features -- -D warnings
    echo "==> 3/13: clippy all-targets no-default-features"
    cargo clippy --locked --all-targets --no-default-features -- -D warnings
    echo "==> 4/13: rustdoc deny warnings"
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
    echo "==> 5/13: test all-features"
    cargo test --locked --all-features
    echo "==> 6/13: test no-default-features"
    cargo test --locked --no-default-features
    echo "==> 7/13: feature combinations check"
    for f in "" "std" "zeroize" "std,zeroize" "std,streaming" "std,hsss" "hsss" "std,refresh" \
             "refresh" "std,parallel" "std,compress" "std,serde" "serde" "hsss,refresh" \
             "std,hsss,refresh,parallel,compress,serde,zeroize"; do
        if [ -z "$f" ]; then
            echo "    features: (none)"
            cargo check --locked --no-default-features
        else
            echo "    features: $f"
            cargo check --locked --no-default-features --features "$f"
        fi
    done
    echo "==> 8/13: wasm32-unknown-unknown checks"
    cargo check --locked --target wasm32-unknown-unknown --no-default-features
    cargo check --locked --target wasm32-unknown-unknown --no-default-features --features "hsss,refresh,serde"
    echo "==> 9/13: fuzz manifest check"
    cargo check --locked --manifest-path fuzz/Cargo.toml
    echo "==> 10/13: package exclusions check"
    cargo package --list --allow-dirty | grep -E '(deny\.toml|\.gitignore|CONTRIBUTING\.md|AUDIT\.md)' && { echo "Package contains excluded files!"; exit 1; } || true
    echo "==> 11/13: cargo audit & cargo deny"
    cargo audit
    cargo deny check
    echo "==> 12/13: subtle and fuzz feature assertions"
    cargo tree -e features -i subtle | grep -q 'core_hint_black_box' || { echo "subtle missing core_hint_black_box!"; exit 1; }
    cargo tree --manifest-path fuzz/Cargo.toml -e features -i shamir_share | grep -q 'feature "compress"' || { echo "fuzz crate missing compress feature!"; exit 1; }
    echo "==> 13/13: heavy ignored tests"
    cargo test --locked --all-features -- --ignored
    echo "==> audit-full PASSED cleanly!"

# Run Miri on finite field arithmetic
audit-miri:
    cargo +nightly miri test --lib finite_field --no-default-features

# Verify constant-time release codegen of GF(2^8) arithmetic
audit-asm:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v objdump >/dev/null 2>&1; then
        echo "objdump not found; skipping audit-asm"
        exit 0
    fi
    cargo build --release --locked
    RLIB=$(ls target/release/deps/libshamir_share-*.rlib 2>/dev/null | head -n 1 || true)
    [ -n "$RLIB" ] && [ -f "$RLIB" ] || RLIB="target/release/libshamir_share.rlib"
    echo "Disassembling $RLIB..."
    ASM_OUTPUT=$(objdump -d --no-show-raw-insn "$RLIB" | awk '/^[0-9a-f]+ <.*(gf256_multiply_const_time|FiniteField.*multiply).*>:/{p=1; print; next} /^[0-9a-f]+ <.*>:/{p=0} p{print}')
    if [ -z "$ASM_OUTPUT" ]; then
        echo "ERROR: symbol not found in $RLIB (was it inlined?)"
        exit 1
    fi
    echo "Disassembled instructions preview:"
    echo "$ASM_OUTPUT" | head -n 15
    BRANCHES=$(echo "$ASM_OUTPUT" | grep -cE '\b(b\.[a-z]+|cbz|cbnz|tbz|tbnz|call|bl|blr)\b' || true)
    BLACK_BOX_CALLS=$(echo "$ASM_OUTPUT" | grep -c 'subtle.*black_box' || true)
    echo "Conditional branches: $BRANCHES"
    echo "Calls to subtle::black_box: $BLACK_BOX_CALLS"
    if [ "$BRANCHES" -ne 0 ] || [ "$BLACK_BOX_CALLS" -ne 0 ]; then
        echo "ERROR: Branching or black_box call detected in gf256_multiply_const_time!"
        exit 1
    fi
    echo "asm check PASSED: 0 conditional branches and 0 black_box calls."

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

# Run canonical wire format deserialization fuzzing
fuzz-wire:
    cargo fuzz run fuzz_share_from_bytes -- -max_total_time=3600

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