#!/bin/bash

# Script to run the streaming benchmarks and generate reports
# This demonstrates how to use the new streaming benchmark suite

echo "Running Shamir Secret Sharing Streaming Benchmarks"
echo "=================================================="

# Run the streaming benchmarks
echo "1. Running streaming benchmarks..."
cargo bench --bench streaming_benchmarks

echo ""
echo "2. Running comparison with existing benchmarks..."
cargo bench --bench shamir_benchmarks

echo ""
echo "3. Running basic benchmarks..."
cargo bench --bench benchmark

echo ""
echo "Benchmark Results Summary:"
echo "========================="
echo "- split_stream: Tests streaming split performance across data sizes"
echo "- reconstruct_stream: Tests streaming reconstruction performance"
echo "- Streaming vs In-Memory: Direct comparison of approaches"
echo "- Chunk size analysis: Impact of different chunk sizes on performance"
echo "- Integrity check impact: Performance difference with/without integrity checking"
echo ""
echo "Results are saved in target/criterion/ directory"
echo "Open target/criterion/report/index.html for detailed HTML reports"