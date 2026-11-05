#![no_main]

use libfuzzer_sys::fuzz_target;
use shamir_share::ShamirShare;
use std::io::Cursor;

// Fuzzing target for ShamirShare::reconstruct_stream method
//
// This fuzzer feeds arbitrary bytes and fragmented/corrupted stream data
// into `reconstruct_stream` to verify that it never panics, handles short reads,
// invalid magic headers, mismatched thresholds, oversized chunk lengths,
// and truncated streams gracefully with `Result::Err`.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        // Test empty sources slice
        let mut empty_sources: Vec<Cursor<&[u8]>> = Vec::new();
        let mut out = std::io::sink();
        let _ = ShamirShare::reconstruct_stream(&mut empty_sources, &mut out);
        return;
    }

    // Determine number of stream sources from fuzzer input (1 to 6)
    let num_sources = ((data[0] % 6) + 1) as usize;
    let payload = &data[1..];

    if payload.is_empty() {
        return;
    }

    // Partition payload among the sources
    let chunk_size = (payload.len() / num_sources).max(1);
    let mut sources: Vec<Cursor<&[u8]>> = payload
        .chunks(chunk_size)
        .take(num_sources)
        .map(Cursor::new)
        .collect();

    let mut out = std::io::sink();
    let _ = ShamirShare::reconstruct_stream(&mut sources, &mut out);

    // If payload has enough bytes, construct a valid stream, then mutate it
    if payload.len() >= 16 {
        let secret = &payload[..payload.len().min(512)];
        if let Ok(mut scheme) = ShamirShare::builder(3, 2).build() {
            let mut share_writers = vec![Cursor::new(Vec::new()), Cursor::new(Vec::new()), Cursor::new(Vec::new())];
            if scheme.split_stream(&mut Cursor::new(secret), &mut share_writers).is_ok() {
                let mut share_bufs: Vec<Vec<u8>> = share_writers.into_iter().map(|c| c.into_inner()).collect();

                // Mutate share bytes using remaining fuzzer data
                if payload.len() > 16 {
                    let mut cursor_idx = 0;
                    for byte in &payload[16..] {
                        if !share_bufs.is_empty() {
                            let buf_idx = (cursor_idx % share_bufs.len()) as usize;
                            if !share_bufs[buf_idx].is_empty() {
                                let offset = (*byte as usize) % share_bufs[buf_idx].len();
                                share_bufs[buf_idx][offset] ^= *byte;
                            }
                            cursor_idx += 1;
                        }
                    }
                }

                let mut corrupted_sources: Vec<Cursor<Vec<u8>>> = share_bufs.into_iter().map(Cursor::new).collect();
                let mut sink = std::io::sink();
                let _ = ShamirShare::reconstruct_stream(&mut corrupted_sources, &mut sink);
            }
        }
    }
});

