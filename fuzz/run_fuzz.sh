#!/bin/bash

# Fuzzing script for shamir_share library
# Usage: ./run_fuzz.sh [target] [duration]
# 
# Targets:
#   reconstruct - Fuzz the ShamirShare::reconstruct method
#   storage     - Fuzz the FileShareStore::load_share method
#   all         - Run both targets sequentially
#
# Duration: Time to run each target (default: 60s)

set -e

TARGET=${1:-all}
DURATION=${2:-60}

echo "=== Shamir Share Fuzzing ==="
echo "Target: $TARGET"
echo "Duration: ${DURATION}s per target"
echo

# Ensure cargo-fuzz is installed
if ! command -v cargo-fuzz &> /dev/null; then
    echo "Installing cargo-fuzz..."
    echo "Note: cargo-fuzz requires nightly Rust"
    echo "Run: rustup install nightly && cargo +nightly install cargo-fuzz"
    exit 1
fi

# Function to run a single fuzz target
run_target() {
    local target_name=$1
    local duration=$2
    
    echo "Running fuzz target: $target_name"
    echo "Duration: ${duration}s"
    echo "Command: cargo fuzz run $target_name -- -max_total_time=$duration"
    echo
    
    cargo fuzz run "$target_name" -- -max_total_time="$duration" || {
        echo "Fuzzing target $target_name completed (may have found issues)"
    }
    
    echo
    echo "=== Fuzz target $target_name completed ==="
    echo
}

# Change to fuzz directory
cd "$(dirname "$0")"

case $TARGET in
    reconstruct)
        run_target "fuzz_reconstruct" "$DURATION"
        ;;
    storage)
        run_target "fuzz_share_storage" "$DURATION"
        ;;
    all)
        run_target "fuzz_reconstruct" "$DURATION"
        run_target "fuzz_share_storage" "$DURATION"
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Available targets: reconstruct, storage, all"
        exit 1
        ;;
esac

echo "=== Fuzzing completed ==="
echo
echo "To view any crashes found:"
echo "  cargo fuzz fmt fuzz_reconstruct"
echo "  cargo fuzz fmt fuzz_share_storage"
echo
echo "To reproduce a specific crash:"
echo "  cargo fuzz run fuzz_reconstruct fuzz/artifacts/fuzz_reconstruct/crash-<hash>"
echo "  cargo fuzz run fuzz_share_storage fuzz/artifacts/fuzz_share_storage/crash-<hash>"