# Streaming Benchmarks Documentation

This document explains the streaming benchmark suite for the Shamir Secret Sharing library and how to interpret the results.

## Overview

The `benches/streaming_benchmarks.rs` file contains a comprehensive benchmark suite that measures the performance of the new streaming I/O methods (`split_stream` and `reconstruct_stream`) compared to the original in-memory methods.

## Benchmark Groups

### 1. `split_stream`
Tests the performance of splitting data using streaming I/O across different data sizes:
- **10KB**: Small data size for baseline performance
- **100KB**: Medium data size for typical use cases  
- **1MB**: Large data size to test scalability

**What it measures**: Time to split data from a source `Cursor` into multiple destination `Cursor`s using chunk-based processing.

### 2. `reconstruct_stream`
Tests the performance of reconstructing data from share streams across the same data sizes.

**What it measures**: Time to reconstruct original data from share streams using the minimum threshold of shares.

### 3. `Streaming vs In-Memory Comparison`
Direct comparison between streaming and in-memory approaches using 100KB test data.

**Key metrics to compare**:
- **Throughput**: Operations per second
- **Memory efficiency**: Peak memory usage (streaming should be lower)
- **Latency**: Time per operation

### 4. `split_stream_chunk_sizes`
Tests the impact of different chunk sizes on streaming performance:
- **1KB chunks**: High overhead, many small operations
- **4KB chunks**: Balanced approach
- **16KB chunks**: Larger chunks, fewer operations
- **64KB chunks**: Large chunks, minimal overhead

**Expected results**: Performance should improve with larger chunk sizes up to a point, then plateau or slightly decrease due to memory pressure.

### 5. `streaming_integrity_check`
Compares performance with and without integrity checking enabled.

**Expected results**: Integrity checking adds SHA-256 hashing overhead, so performance should be lower when enabled.

## Running the Benchmarks

### Quick Run
```bash
cargo bench --bench streaming_benchmarks
```

### Full Benchmark Suite
```bash
./run_streaming_benchmarks.sh
```

### Individual Benchmark Groups
```bash
# Run only streaming vs memory comparison
cargo bench --bench streaming_benchmarks -- "Streaming vs In-Memory"

# Run only chunk size analysis
cargo bench --bench streaming_benchmarks -- "chunk_sizes"
```

## Interpreting Results

### Sample Expected Output

```
split_stream/split_stream_10240_bytes
                        time:   [45.2 µs 46.1 µs 47.3 µs]

split_stream/split_stream_102400_bytes  
                        time:   [421.8 µs 428.9 µs 437.2 µs]

split_stream/split_stream_1048576_bytes
                        time:   [4.12 ms 4.18 ms 4.25 ms]

Streaming vs In-Memory Comparison/in_memory_workflow_100KB
                        time:   [398.2 µs 405.1 µs 413.8 µs]

Streaming vs In-Memory Comparison/streaming_workflow_100KB
                        time:   [445.7 µs 452.3 µs 460.1 µs]
```

### What the Results Tell Us

#### Performance Scaling
- **Linear scaling**: If streaming performance scales linearly with data size, it indicates good algorithmic efficiency
- **Sub-linear scaling**: Better than expected, suggests optimizations are working
- **Super-linear scaling**: May indicate memory pressure or inefficient algorithms

#### Streaming vs In-Memory Trade-offs

**When Streaming is Better**:
- Lower memory usage (constant memory vs. proportional to data size)
- Better for large files that don't fit in memory
- Enables processing of data as it arrives

**When In-Memory is Better**:
- Lower latency for small to medium data sizes
- Simpler error handling
- Better CPU cache utilization

#### Chunk Size Optimization
The optimal chunk size balances:
- **I/O overhead**: Smaller chunks = more I/O operations
- **Memory usage**: Larger chunks = higher peak memory
- **Processing efficiency**: Medium chunks often optimal

#### Integrity Check Impact
Typical overhead from integrity checking:
- **10-20% performance decrease**: Normal for cryptographic hashing
- **Higher overhead**: May indicate inefficient implementation
- **Lower overhead**: Good optimization of hash computation

## Performance Targets

Based on the implementation, reasonable performance targets:

### Throughput Targets
- **Small data (10KB)**: > 200 MB/s
- **Medium data (100KB)**: > 200 MB/s  
- **Large data (1MB)**: > 200 MB/s

### Memory Efficiency
- **Streaming memory usage**: Should remain constant regardless of input size
- **In-memory memory usage**: Should scale linearly with input size

### Latency Targets
- **Streaming overhead**: < 20% compared to in-memory for 100KB data
- **Chunk processing**: < 1ms per chunk for typical chunk sizes

## Troubleshooting Performance Issues

### High Latency
- Check chunk size (try larger chunks)
- Verify integrity checking overhead
- Profile memory allocations

### Poor Scaling
- Look for memory pressure indicators
- Check for algorithmic inefficiencies
- Verify parallel processing is working

### Memory Issues
- Monitor peak memory usage
- Check for memory leaks in streaming code
- Verify buffer reuse is working

## Benchmark Limitations

### What These Benchmarks Don't Test
- **Real I/O performance**: Uses `Cursor` to avoid disk/network overhead
- **Concurrent access**: Single-threaded benchmarks only
- **Error handling**: Only tests success paths
- **Memory pressure**: Limited by available system memory

### Real-World Considerations
- Actual I/O will be slower than `Cursor` operations
- Network latency affects streaming performance
- Disk seek times impact random access patterns
- Memory fragmentation affects large data processing

## Extending the Benchmarks

To add new benchmark scenarios:

1. **Different share configurations**: Test various threshold/total combinations
2. **Error scenarios**: Benchmark error handling and recovery
3. **Concurrent operations**: Multi-threaded splitting/reconstruction
4. **Different data patterns**: Test with various data characteristics
5. **Memory pressure**: Test with limited available memory

## Conclusion

The streaming benchmark suite provides comprehensive performance analysis of the streaming I/O implementation. Use these results to:

1. **Optimize configuration**: Choose appropriate chunk sizes and settings
2. **Validate performance**: Ensure streaming meets application requirements  
3. **Compare approaches**: Decide between streaming and in-memory based on use case
4. **Monitor regressions**: Track performance changes over time