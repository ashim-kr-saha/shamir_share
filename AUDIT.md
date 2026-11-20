# Security & Production-Readiness Audit — `shamir_share` v0.3.0

| | |
|---|---|
| **Crate** | `shamir_share` 0.3.0 ([crates.io](https://crates.io/crates/shamir_share), [repo](https://github.com/ashim-kr-saha/shamir_share)) |
| **Commit audited** | `5e98c58f13024b72712f5ead02dc30af33997c04` — *"fix(security): resolve audit findings FIND-01 through FIND-08 and harden v0.3.0"* |
| **Working tree at audit time** | clean (`git status --porcelain` empty) |
| **Audit date** | 2026-11-20 |
| **Toolchain** | `cargo 1.100.0`, `rustc 1.100.0`, `miri 0.1.0 (65ce8611fe 2026-11-18)`, macOS aarch64 |
| **Verdict** | **READY WITH FIXES** — no memory-safety, `no_std`, MSRV or cryptographic-correctness defect found; 2 High, 8 Medium, 14 Low (12 open, 2 suspected), 4 Info |
| **Re-run** | `../shamir_share_audit/run_audit.sh` (see [Appendix A](#appendix-a--the-repeatable-audit-process) and [F-28](#f-28)) |

This document is both the **report** and the **tracker**. Each finding has an ID, a severity, a
status, a reproduction you can run, and the status markers the automated runner looks for.

---

## 1. Executive summary

| Severity | Count | Open | Suspected |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 2 | 2 | 0 |
| Medium | 8 | 8 | 0 |
| Low | 14 | 12 | 2 |
| Info | 4 | 4 | 0 |

The GF(2⁸) core is correct and branchless, and I could not defeat the reconstruction validation.
The problems sit at the seams: the *default* integrity mode authenticates nothing, one documented
config setter produces wrong output, one security control can be silently disabled, a large part of
the compressed code path is never fuzzed, and several README/CHANGELOG claims are not delivered by
the code.

**Top risks in plain language**

1. **F-01 — The default share set is not authenticated, and one share is enough to forge the
   plaintext.** Holding 1 of 3 shares (strictly below threshold) I made `reconstruct` return
   `"transfer USD 10 to account MALLORY-66"` from a secret reading `"…ALICE-1111"`, with the
   victim's own share left byte-for-byte unchanged and the SHA-256 check passing. Inherent to an
   unkeyed digest — the crate *does* say authenticity needs `with_authentication_key` — but the
   README also promises "Tamper Detection" and "any inconsistent or rogue share will cause
   reconstruction to immediately fail", which is false in the default configuration.
2. **F-02 — `with_max_decompressed_stream_size(u64::MAX)` corrupts output.** `decoder.take(max_limit + 1)`
   overflows: debug builds panic at `src/shamir.rs:708`; release builds return `Ok(())` with
   `0` of `8` bytes written. A caller using `u64::MAX` for "no limit" gets silent truncation.
3. **F-03 — An authentication key is silently inert if integrity checking is also off.** `build()`
   accepts the combination; every share is then accepted unauthenticated.
4. **F-04 — The whole library runs 2.3–2.7× slower than it needs to.** `subtle`'s
   `core_hint_black_box` feature is off, so each of the 8 bit-steps in the GF multiply is an
   out-of-line call to `#[inline(never)] subtle::black_box`. One line in `Cargo.toml` recovers it
   with no `no_std` or constant-time cost.
5. **F-05 — Cost grows as O(n·k·len) and the documented memory budget understates peak.**
   n=255, k=128, 64 KiB secret: split took **31.3 s** in release; reconstructing with all 255
   shares took **14.9 s**. The advertised "256 MiB allocation limit" covers only
   `chunk_size × total_shares`; true peak is roughly 2–3× that.

**Tracking legend.** Status column: `OPEN` (defect present at the audited commit), `SUSPECTED`
(code-review finding needing dynamic/runtime confirmation), `FIXED` (marker flipped), `MANUAL`
(no automated marker — verify by reading), `INFRA` (process/CI gap).

---

## 2. Findings tracker

Tick a row when its fix lands **and** `../shamir_share_audit/run_audit.sh` reports the finding `FIXED`.

| ID | Sev | Status | Area | Location | One-line summary | Verify |
|---|---|---|---|---|---|---|
| [F-01](#f-01) | High | OPEN | Authentication | `src/shamir.rs:646,855,1224` | Unkeyed SHA-256 default: `k-1` shares let an attacker choose the reconstructed plaintext | `run_audit.sh` → `forge` |
| [F-02](#f-02) | High | OPEN | Streaming/compress | `src/shamir.rs:708` | `take(max_limit + 1)` overflows → debug panic, release silent empty output | `stream` |
| [F-03](#f-03) | Medium | OPEN | Config | `src/config.rs:167`, `src/shamir.rs:855` | `with_authentication_key` silently inert when `integrity_check` is off | `authkey` |
| [F-04](#f-04) | Medium | OPEN | Performance | `Cargo.toml:38` | `subtle` without `core_hint_black_box`: 2.3–2.7× slowdown | `cargo tree -e features -i subtle` |
| [F-05](#f-05) | Medium | OPEN | Performance/limits | `src/shamir.rs:1208,1356,1974` | O(n·k·len); excess-share verification amplifies n×; memory budget understated | `perf` (manual) |
| [F-06](#f-06) | Medium | OPEN | Docs | `README.md:123`, `CHANGELOG.md:65,73,77` | Four claims the code does not deliver | `grep` (manual) |
| [F-17](#f-17) | Medium | OPEN | Test coverage | `fuzz/Cargo.toml:12` | Fuzz crate enables no `compress`/`serde`: decompression & serde paths are never fuzzed | `cargo tree --manifest-path fuzz/Cargo.toml` |
| [F-21](#f-21) | Medium | OPEN | Refresh / Hygiene | `src/shamir.rs:1994-2008` | `refresh_shares_with_rng` materializes plaintext `P(0)` (contradicting comment) and skips MAC verification | manual |
| [F-22](#f-22) | Medium | OPEN | Compress / 32-bit | `src/shamir.rs:700-728` | `max_limit as usize` truncates on 32-bit targets; `capacity * 2` overflow & panicking `Vec::with_capacity` | manual |
| [F-23](#f-23) | Medium | OPEN | Memory hygiene | `src/lib.rs:94-152`, `src/hsss.rs:58-92` | Non-`zeroize` fallback skips spare `Vec` capacity, exposes `Zeroizing(pub T)`, omits HSSS `Drop`; `to_bytes` unzeroized | manual |
| [F-07](#f-07) | Low | OPEN | Wire format | `src/shamir.rs:258-304` | `from_bytes` accepts a zero-length payload share (13-byte input) | `api` |
| [F-08](#f-08) | Low | OPEN | API | `src/shamir.rs:91-109` | `#[non_exhaustive]` blocks literals but all fields stay `pub` and mutable | manual |
| [F-09](#f-09) | Low | OPEN | CI | `.github/workflows/ci.yml` | No `cargo deny`/`audit`, Miri, fuzz-smoke or wasm *test* job; `deny.toml` unused | `recon/ci-security-jobs` |
| [F-10](#f-10) | Low | OPEN | Packaging | `Cargo.toml:13-20` | Package ships `deny.toml`, `.gitignore`, `Cargo.lock`, `CONTRIBUTING.md` | `package --list` |
| [F-11](#f-11) | Low | OPEN | Error taxonomy | `src/error.rs:34,55,58,66` | Unused `ShareNotFound`; stringly-typed `(String)` payloads on 3 variants | `grep` |
| [F-12](#f-12) | Low | OPEN | API | `src/config.rs:127,139,145,151,161` | `with_*` setters lack `#[must_use]`; `config.with_compression(true);` silently does nothing | `clippy-must-use` |
| [F-13](#f-13) | Low | SUSPECTED | Memory hygiene | `src/shamir.rs:121-130` | serde `ShareHelper` holds share bytes in a non-zeroizing intermediate | manual |
| [F-18](#f-18) | Low | SUSPECTED | Streaming/compress | `src/shamir.rs:48,1757` | `MAX_STREAM_CHUNK_SIZE` margin (256 KiB + 256 B) is not provably ≥ zstd's worst-case expansion | `stream --heavy` |
| [F-19](#f-19) | Low | OPEN | Hygiene / CI | `tests/wire_format_test.rs:195` | `cargo fmt --check` fails: trailing blank line; CI's fmt gate would fail on this commit | `fmt/check` |
| [F-24](#f-24) | Low | OPEN | Streaming DoS | `src/shamir.rs:1604-1620` | `reconstruct_stream_internal` allocates and reads headers from all `sources` before checking `sources.len() > 255` | manual |
| [F-25](#f-25) | Low | OPEN | Refresh / Format | `src/shamir.rs:1919` | `generate_refresh_deltas_with_rng` allows `data_length == 0` and up to `64 MiB + 64` (exceeds `MAX_SHARE_DATA_LEN`) | manual |
| [F-26](#f-26) | Low | OPEN | Streaming / Parallel | `src/shamir.rs:1726,1251-1261` | Streaming ignores `SplitMode::Parallel` (undocumented); dead unauthenticated decompression branch remains | manual |
| [F-27](#f-27) | Low | OPEN | HSSS API & Docs | `src/hsss.rs:88-104,212,422` | `HierarchicalShare` fields `pub`/mutable, no `serde`, `with_config` lacks `#[must_use]`, stale `reconstruct` doc | manual |
| [F-28](#f-28) | Low | OPEN | Audit harness | `../shamir_share_audit/run_audit.sh` | Inverted `F-09` check (`open_if` → falsely `FIXED`), broken `audit/` paths, `doc` quoting bug, whole-binary `asm-dump` | manual |
| [F-20](#f-20) | Info | OPEN | Build | `fuzz/Cargo.toml` | `tempfile` declared but unused (`warning: unused dependency`) | `fuzz/compile-targets` |
| [F-14](#f-14) | Info | OPEN | Docs | `CHANGELOG.md:77` | "Decompressed buffers shrink to fit" — no `shrink_to_fit` in `src/` | `grep` |
| [F-15](#f-15) | Info | OPEN | Refresh | `src/shamir.rs:96-109,333-352` | No epoch/version field; old/new mixing is caught only by the (unkeyed) digest | `refresh` (manual) |
| [F-16](#f-16) | Info | OPEN | Streaming I/O | `src/shamir.rs:1918-1921` | Trailing-byte probe does not retry on `ErrorKind::Interrupted` | manual |

Fix order and effort estimates: [§7](#7-remediation-plan).

---

## 3. Detailed findings

### F-01
**The default configuration authenticates nothing; one share forges the plaintext.**
Status **OPEN** · Severity **High** · Evidence **CONFIRMED** (reproduced) · Owner `@ashim-kr-saha`

**Summary.** With no `authentication_key`, the "integrity" value inside each share is unkeyed
SHA-256 over `domain ‖ [flags, threshold, total_shares] ‖ salt ‖ payload`. Every input is public or
attacker-chosen, so an attacker holding *fewer than k shares* can compute a share set that
reconstructs to a plaintext of their choosing, leaving the victim's own share untouched.

**Location.** `src/shamir.rs:646-681`:

```rust
fn compute_digest(domain: &[u8], meta: &[u8], salt: &[u8], payload: &[u8],
                  auth_key: Option<&[u8; 32]>) -> [u8; 32] {
    if let Some(key) = auth_key { /* HMAC-SHA256 */ } else {
        let mut hasher = Sha256::new();
        hasher.update(domain); hasher.update(meta);
        hasher.update(salt);  hasher.update(payload);
        hasher.finalize().into()
    }
}
```

Digest created at `src/shamir.rs:855-874` (with public `flags/threshold/total_shares`), verified at
`src/shamir.rs:1224-1250`.

**Impact.** For (k=2, n=3), an attacker who obtains share 1 (below threshold — learns nothing about
the secret) computes share 2 so that interpolation yields their payload. `reconstruct` returns `Ok`,
`Config::integrity_check()` is `true`, and nothing in the return type says the plaintext was never
authenticated. Any protocol built on `reconstruct` — key unlock, signed-message store, password
vault — is subverted. This is a forgery primitive that the severity guide would normally call
Critical; I rate it **High** because `Config::with_authentication_key` and `reconstruct`'s own docs do
state that authenticity requires a key — the defect is that the README says the opposite (F-06).

**Reproduction.** `cd audit/probe && cargo run --release --bin forge`

```
attacker holds: index=1 threshold=2 total=3 len=101
L(0) for {1,2} = [f7, f6]
reconstructed = "transfer USD 10 to account MALLORY-66"
expected      = "transfer USD 10 to account MALLORY-66"
victim share unchanged = true
FORGERY SUCCEEDED: integrity check passed on attacker-chosen plaintext
authenticated mode with tampered share -> Some(IntegrityCheckFailed)
```

Run it in a **debug** build as well to show the parser is not involved: the result is identical.

**Recommended fix (minimal — documentation first, because the code matches its own contract).**

```diff
--- a/README.md
+++ b/README.md
-- **Active Excess Share Verification**: When more than $k$ shares are provided, all excess shares are
-  actively cross-verified … Any inconsistent or rogue share will cause reconstruction to
-  immediately fail with `IntegrityCheckFailed`.
+- **Excess Share Cross-Verification**: When *more* than $k$ shares are supplied, every excess share
+  is checked against the polynomial interpolated from the first $k$. This catches accidental
+  corruption of the extras only. It does **not** authenticate the secret: with the default unkeyed
+  digest, anyone holding $k-1$ shares can produce a share set that reconstructs to a plaintext of
+  their choosing, leaving your shares untouched.
```

```diff
--- a/src/shamir.rs
+++ b/src/shamir.rs
+    /// # Authenticity
+    /// The returned bytes are **not** authenticated unless the scheme was built with
+    /// [`Config::with_authentication_key`]; in that case prefer `reconstruct_with_scheme`.
+    #[must_use = "the reconstructed secret is unauthenticated without an authentication key"]
     pub fn reconstruct(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
```

Stronger option (still small, and the only one that makes misuse impossible): return a
`Secret { data, authenticated: bool }` so callers must acknowledge the flag, or require a key for a
new `reconstruct_authenticated` and deprecate the unkeyed path.

**Regression test to add.** `tests/authenticity_test.rs`: assert the forged share set from `forge`
is rejected when a key is configured, and that the unkeyed API surfaces `authenticated == false`.

---

### F-02
**`with_max_decompressed_stream_size(u64::MAX)` overflows: debug panic, release silent data loss.**
Status **OPEN** · Severity **High** · Evidence **CONFIRMED** · Owner `@ashim-kr-saha`

**Location.** `src/shamir.rs:708`; caller at `src/shamir.rs:1868-1870`.

```rust
let mut limited_reader = decoder.take(max_limit + 1);          // :708
...
let remaining_limit = max_stream_output_bytes.saturating_sub(total_decompressed_bytes);
let decompressed = Self::decompress_bounded(payload, remaining_limit)?;   // :1868
```

**Impact.** Debug/`overflow-checks` builds: `attempt to add with overflow` panic — a DoS from library
code, triggered by a documented setter. Release builds: wraps to `take(0)`, so every chunk
decompresses to zero bytes and `reconstruct_stream_with_scheme` returns **`Ok(())` with an empty
destination** — silent wrong output.

**Reproduction.** `cargo run --release --bin stream` (release), then `cargo run --bin stream` (debug):

```
--- A: with_max_decompressed_stream_size(u64::MAX) ---
result      = Ok(())
input len   = 8 bytes
output len  = 0 bytes
*** BUG: silent data loss, 8 of 8 bytes lost ***
control (limit=1024): result=Ok(()) output_len=8 match=true
```
```
thread 'main' panicked at .../src/shamir.rs:708:47:
attempt to add with overflow
```

**Fix.**

```diff
-        let mut limited_reader = decoder.take(max_limit + 1);
+        // `max_limit == u64::MAX` is the caller's way of saying "no cap"; `+ 1` must not wrap.
+        let mut limited_reader = decoder.take(max_limit.saturating_add(1));
```

**Regression test.** Split 8 bytes with `chunk_size = 4`, `compression = true`,
`max_decompressed_stream_size(u64::MAX)`, reconstruct, assert output == input.

---

### F-03
**An authentication key silently does nothing when integrity checking is off.**
Status **OPEN** · Severity **Medium** · Evidence **CONFIRMED**

**Location.** `src/config.rs:167-189` (`validate` cross-checks compression but not the key);
`src/shamir.rs:855` gates the only consumer of the key on `integrity_check`.

**Impact.** `Config::new().with_authentication_key(key).with_integrity_check(false)` builds, produces
shares with no digest, and `reconstruct_with_scheme` returns attacker-modified plaintext. The caller
believes authentication is on; it is not. The combination is meaningless and should be
unrepresentable.

**Reproduction.** `cargo run --release --bin authkey`:

```
build() accepted auth-key + integrity_check=false
share.integrity_check = false (no digest is embedded)
tampered share accepted -> "key0d-but-unchecked secret"  (authentication key had no effect)
integrity on + key, tampered -> Err("Data integrity check failed")
```

**Fix.**

```diff
--- a/src/config.rs
@@ -186,6 +186,13 @@
         #[cfg(not(feature = "compress"))]
         if self.compression { … }
+
+        if self.authentication_key.is_some() && !self.integrity_check {
+            return Err(ShamirError::InvalidConfig(
+                "An authentication key requires integrity checking; \
+                 without it no digest is produced and the key is never used".into(),
+            ));
+        }
         Ok(())
```

**Regression test.** `assert!(Config::new().with_authentication_key([0; 32]).with_integrity_check(false).validate().is_err())`.

---

### F-04
**`subtle`'s `core_hint_black_box` is off, so every GF bit-step is an out-of-line call.**
Status **OPEN** · Severity **Medium** · Evidence **CONFIRMED** (measured + disassembly)

**Location.** `Cargo.toml:38` — `subtle = { version = "2.6", default-features = false }`. In
`subtle` 2.6.1, `core_hint_black_box` is **not** in `default`; without it `black_box` is
`#[inline(never)]` with a volatile read, and `Choice::from` / `conditional_select` call it once per
bit. Confirmed: `cargo tree -e features -i subtle` lists no `subtle feature "core_hint_black_box"`.

**Impact.** Release build, 1 MiB secret, same machine (`cargo run --release --bin perf`):

| case | baseline | with `core_hint_black_box` | speed-up |
|---|---|---|---|
| split n=5 k=3 | 159.53 ms | 63.96 ms | 2.5× |
| reconstruct (k=3) | 44.54 ms | 19.72 ms | 2.26× |
| split n=64 k=2 | 962.66 ms | 351.15 ms | 2.74× |
| reconstruct (n=64, excess check) | 1906.02 ms | 832.13 ms | 2.29× |

Assembly: `gf256_multiply_const_time` in the current build contains 16 `bl …subtle…black_box…`
calls (otherwise fully unrolled, mask-only arithmetic). With the feature on, the same function has
**0** conditional branches and no calls.

**Fix.**

```diff
-subtle = { version = "2.6", default-features = false }
+subtle = { version = "2.6", default-features = false, features = ["core_hint_black_box"] }
```

`core_hint_black_box` maps to `core::hint::black_box` — no `std`, no `unsafe` in this crate, works on
wasm32. Constant-time is preserved in both configurations (verified branch-free in each).

**Regression test / guard.** A CI step asserting the feature is enabled
(`cargo tree -e features -i subtle | grep -q core_hint_black_box`) plus the `asmcheck` branch scan in
[Appendix A phase 3](#phase-3--side-channels-and-codegen).

---

### F-05
**Cost model is O(n·k·len); excess verification multiplies it by n; the memory budget understates peak.**
Status **OPEN** · Severity **Medium** · Evidence **CONFIRMED** (measured)

**Location.** Split evaluation `src/shamir.rs:1974-1987` and `Dealer::next` `src/shamir.rs:2394-2404`
(Horner per share, per byte). Excess verification `src/shamir.rs:1208-1222` (one full
re-interpolation per excess share). Budget `src/shamir.rs:1356-1367`.

**Measurements** (release; `cargo run --release --bin perf`, plus the n=255 rows from the audit run):

| secret | n | k | split | reconstruct (k shares) | reconstruct (all n) |
|---|---|---|---|---|---|
| 1 KiB | 255 | 128 | 511 ms | 2.2 ms | 280 ms |
| 64 KiB | 255 | 128 | **31,266 ms** | 122 ms | **14,901 ms** |
| 1 MiB | 64 | 2 | 963 ms | 30 ms | **1,946 ms** |

**Impact.** (a) `split` at n=255, k=128 on a 64 KiB secret takes half a minute — the
"high-performance" framing is not supportable at the parameter extremes. (b) A service that accepts
a caller-supplied share set pays up to n extra interpolations of the full secret length — cheap
amplification for an attacker submitting 255 junk shares. (c) `MAX_TOTAL_STREAM_BUFFER_BUDGET`
(256 MiB) is checked against `chunk_size × total_shares` only, while real peak also holds
`current_chunk_buf` + `next_chunk_buf` (2 × chunk_size), the digest/payload copies, and per-share
buffers — roughly 2–3× the advertised figure. (d) `split` with the default 1 MiB secret and k=128
fails outright: `InvalidConfig("Total coefficient memory 133177280 bytes exceeds maximum allowed
buffer size of 67108864 …")`.

**Fix (minimal first).** Do **not** cap excess verification to a fixed prefix (skipping trailing
shares would silently ignore corrupted or rogue excess shares). Instead, reuse
`compute_lagrange_basis_at_target` (already implemented at `src/shamir.rs:1803` for streaming) to
evaluate the polynomial directly at each excess share's `x_e` in one pass rather than cloning
`active_views` and re-interpolating `P(0)` from scratch, document the cost model, and correct the
budget formula to `(total_shares + 3) * chunk_size + digest overhead`. Longer term: bit-sliced
evaluation (8 bytes per pass) or caching the interpolation per byte.

**Regression test.** A latency guard (e.g. 64 KiB at n=255, k=128 completes < 2 s) so a regression is
visible in CI.

---

### F-06
**README/CHANGELOG claims the code does not deliver.**
Status **OPEN** · Severity **Medium** · Evidence **CONFIRMED** — see [§4](#4-docs-vs-code-mismatches)
for the full table with line numbers. This finding exists separately from F-01 because it is the
finding that turns F-01 from "documented limitation" into "a caller following the docs is exposed".

---

### F-17
**The fuzz crate never enables `compress` or `serde`, so the decompression and serde paths are unfuzzed.**
Status **OPEN** · Severity **Medium** · Evidence **CONFIRMED** (`cargo tree`)

**Location.** `fuzz/Cargo.toml:12` — `shamir_share = { path = ".." }` (default features only:
`std, zeroize, streaming, hsss, refresh`). No `compress`, no `serde`.

**Impact.** `fuzz_reconstruct_stream.rs:52-57` builds a config with `.with_compression(compression)`,
but with `compress` off `Config::validate` rejects it (`"Compression requested but crate was compiled
without 'compress' feature"`), so `build()` fails and the whole valid-stream branch is skipped for
those inputs. Net effect: `decompress_bounded` — the function at the centre of F-02 and F-18 — and the
`serde` `TryFrom` path have **no fuzzing at all**. This is a coverage gap in exactly the code that
handles attacker-supplied compressed data.

**Reproduction.**
```bash
cargo tree --manifest-path fuzz/Cargo.toml -e features -i shamir_share
# → shows shamir_share feature "default"/"hsss"/"refresh"/"std"/"streaming"/"rand" only,
#   no "compress", no "serde"
```

**Fix.**
```diff
--- a/fuzz/Cargo.toml
@@
-shamir_share = { path = ".." }
+shamir_share = { path = "..", features = ["compress", "serde", "parallel"] }
```
and add `fuzz_share_from_json` (serde) and a compressed-stream variant of
`fuzz_reconstruct_stream` that asserts round-trip fidelity, not just absence of panic.

**Regression test.** CI job: `cargo tree --manifest-path fuzz/Cargo.toml -e features | grep -q 'feature "compress"'`.

---

### F-07
**`from_bytes` accepts a zero-length payload share.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED**

`Share::from_bytes` on the 13-byte header with `DataLen = 0` returns `Ok` with `data.len() == 0`, and
`to_bytes` reproduces the same bytes (canonical). Not exploitable against integrity-checked schemes
(`reconstruct` rejects `len < 64`), but with `integrity_check(false)` two such shares reconstruct to
an empty `Vec` reported as "the secret". `Share::new` has the same gap (`data.len()` only
upper-bounded).

**Reproduction.** `cargo run --release --bin api` → `from_bytes(len=0 payload) = Ok(0)`.

**Fix.**
```diff
-        if data.len() > MAX_SHARE_DATA_LEN {
+        if data.is_empty() || data.len() > MAX_SHARE_DATA_LEN {
             return Err(ShamirError::InvalidShareFormat);
         }
```
in `Share::new`, `Share::from_bytes`, and the serde `TryFrom`.

---

### F-08
**`#[non_exhaustive]` blocks literals, but every `Share` field is `pub` and mutable.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED**

`Share` (`src/shamir.rs:91-109`) cannot be built with a struct literal outside the crate, but its
fields are `pub`, so any holder can rewrite `index`, `threshold` or flip a `data` byte after
construction, bypassing every invariant `Share::new` enforces. `reconstruct` re-validates metadata,
which is why this is Low; the honest fix is private fields + accessors (breaking → 0.4.0).

---

### F-09
**CI gaps.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (file inspection)

`ci.yml` covers a good feature matrix, wasm32 *check*, MSRV, doc-tests, fmt, clippy (2 profiles),
`cargo package`, and a fuzz-target *compile* check. Missing: any `cargo audit` / `cargo deny` job
(`deny.toml` is referenced by no workflow), Miri, an actual fuzz smoke run, `cargo test --target
wasm32` (tests never run on the 32-bit target), and `--locked` on the matrix. `publish.yml` gates on
tag/version match and re-runs tests, but also skips audit.

```bash
grep -c "cargo audit\|cargo deny\|miri" .github/workflows/*.yml   # → 0 in all files
```

**Fix.** Add `security` (`cargo audit`, `cargo deny check --all-features`), `miri` (`--lib`),
`fuzz-smoke` (60 s per target on PRs), `wasm32 test`, and `--locked` everywhere.

---

### F-10
**Packaging contents.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED**

`cargo package --list` (39 files) ships `deny.toml`, `.gitignore`, `Cargo.lock`, `CONTRIBUTING.md`.
Nothing harmful; `.docs/`, `.github/`, `AUDIT.md`, `fuzz/`, `justfile` are correctly excluded. Add
the leftovers to `exclude`. (The audit harness lives in the sibling `../shamir_share_audit/`
repository rather than an in-repo `audit/` directory.)

---

### F-11
**Error taxonomy: one unused variant, three stringly-typed payloads.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (`grep`)

* `ShamirError::ShareNotFound(u8)` (`src/error.rs:34`) is **never constructed** anywhere in `src/` —
  dead since `storage.rs` was removed in 0.3.0.
  (`InvalidShareCount` *is* used — `src/shamir.rs:623`, `src/hsss.rs:321,340` — so it stays.)
* `StorageError(String)` (`:66`), `CompressionError(String)` (`:55`), `DecompressionError(String)`
  (`:58`) carry `alloc::String` payloads, the last stringly-typed errors in an otherwise structured
  `#[non_exhaustive]` enum; `StorageError` is also misnamed for what it now reports (chunk too large,
  allocation failure).

**Fix.** Delete `ShareNotFound` (breaking → group with 0.4.0 or accept a minor); replace the `String`
payloads with typed variants (`ChunkTooLargeEarly`, `AllocationFailed { requested: usize }`,
`Zstd { detail: ZstdError }` — the last optionally behind `compress`).

---

### F-12
**Builder setters are not `#[must_use]`.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (clippy `return_self_not_must_use`)

`src/config.rs:127,139,145,151,161` (also `ShamirShareBuilder::with_config`, `HsssBuilder::add_level`).
`config.with_compression(true);` compiles silently and discards the change, because `Config` is not
`#[must_use]` and the method returns `Self`.

**Fix.** `#[must_use]` on `Config`, `ShamirShareBuilder`, `HsssBuilder` and on every consuming builder
method.

---

### F-13
**serde intermediate holds unzeroized share bytes.**
Status **SUSPECTED** · Severity **Low**

`ShareHelper` (`src/shamir.rs:121-130`) owns `data: Vec<u8>` through deserialization; if `try_from`
rejects (`InvalidShareFormat`), the `Vec` is dropped without clearing. Under `--features serde` with
zeroization active, share bytes can be left on the heap on the error path. **What would confirm it:**
a heap-inspection test (`MALLOC_PERTURB_`/`valgrind`/`miri` with a custom allocator) that samples the
freed block after a rejected `ShareHelper`. Reading code alone is why this is SUSPECTED, not
CONFIRMED.

**Fix.** `#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]` on `ShareHelper`.

---

### F-18
**The stream chunk size limit's margin over zstd's worst case is not provably sufficient.**
Status **SUSPECTED** · Severity **Low**

`MAX_STREAM_CHUNK_SIZE = (64 MiB) + (256 KiB) + 256` (`src/shamir.rs:48`), checked at
`src/shamir.rs:1757`. The margin above the 64 MiB chunk is exactly `srcSize>>8` (256 KiB) plus 256
bytes, while `ZSTD_compressBound()` adds `srcSize>>8` **plus** a block-header term. If
`ZSTD_compressBound(64 MiB) + 49 > MAX_STREAM_CHUNK_SIZE`, then a valid split could be rejected at
reconstruction.

**Measured:** 64 MiB of incompressible data compresses to a 67,110,458-byte share chunk
(64 MiB + 1,545 bytes of frame/block overhead), well under the 67,371,264 limit — so the common worst
case is fine. **What would confirm it:** compute `ZSTD_compressBound(64*1024*1024)` with the zstd
version actually vendored and compare against the constant; the argument rests on the size of the
block-header term, which I did not read from the zstd source.

**Fix (cheap and definitive).** Assert it at build/test time:
```rust
#[test]
fn stream_chunk_limit_covers_zstd_worst_case() {
    let bound = zstd::zstd_safe::compress_bound(MAX_CONFIG_CHUNK_SIZE);
    assert!(bound + 64 <= MAX_STREAM_CHUNK_SIZE - MAX_CONFIG_CHUNK_SIZE);
}
```

---

### F-19
**`cargo fmt --check` fails on the audited commit.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (`audit/results/logs/fmt_check.log`)

```
Diff in tests/wire_format_test.rs:195:
          Err(ShamirError::InvalidShareFormat)
      ));
  }
-
```

`ci.yml` runs `cargo fmt --all -- --check` as a hard gate, so the commit fails CI's lint job as
written. Harmless to behaviour; it is a process finding — the release gate was not run before the
last commit.

**Fix.** `cargo fmt --all` (one trailing blank line removed). Then re-run `./audit/run_audit.sh`.

---

### F-20
**`tempfile` is an unused dependency of the fuzz crate.**
Status **OPEN** · Severity **Info** · Evidence **CONFIRMED** (`audit/results/logs/fuzz_compile-targets.log`)

```
warning: unused dependency `tempfile`
warning: `shamir_share-fuzz` (manifest) generated 1 warning
```

No fuzz target imports `tempfile`. Remove it from `fuzz/Cargo.toml`. Cosmetic, but it is the only
warning the fuzz crate emits, and a warning-free build makes future regressions visible.

---

### F-21
**`refresh_shares_with_rng` materializes the full plaintext secret `P(0)` and skips MAC verification.**
Status **OPEN** · Severity **Medium** · Evidence **CONFIRMED** (code review)

**Location.** `src/shamir.rs:1994-2008`.

```rust
// Verify share consistency across ALL shares directly in GF(2^8) before refreshing so corrupted shares are not silently masked,
// without materializing or decompressing the secret into plaintext buffers (MAS-05, MAS-08).
let base_poly_0 =
    Self::reconstruct_chunk_from_views_with_mode(active_views, self.config.mode())?;
for excess_view in &views[self.threshold as usize..] {
    let mut alt_views = active_views.to_vec();
    alt_views[0] = *excess_view;
    let alt_poly_0 = Self::reconstruct_chunk_from_views_with_mode(&alt_views, self.config.mode())?;
    ...
}
```

**Impact.** (a) Contrary to its own comment, `reconstruct_chunk_from_views_with_mode` interpolates
`P(0)` — the complete plaintext secret (plus salt and digest) — in memory for `base_poly_0` and
again for every excess share, breaking the proactive-refresh invariant that the secret is never
reconstructed during refresh. (b) It never verifies the SHA-256/HMAC digest: if `k == n` (any
single-bit flip) or if all `n` shares lie on a forged/corrupted degree-`(k-1)` polynomial, refresh
succeeds even when an `authentication_key` is configured.

**Fix.** Remove the `#[cfg(feature = "streaming")]` gate on `compute_lagrange_basis_at_target`
(`src/shamir.rs:1803`) and evaluate the polynomial directly at each excess share's `x_e` in the share
domain so `P(0)` is never reconstructed. Explicitly document that `refresh_shares` checks polynomial
consistency without verifying the MAC (and cannot detect corruption at `k == n`).

**Regression test.** Assert `refresh_shares` rejects a corrupted excess share without calling
`P(0)` interpolation, and document `k == n` behavior.

---

### F-22
**`decompress_bounded` truncates `max_limit as usize` on 32-bit targets and can panic on OOM or overflow.**
Status **OPEN** · Severity **Medium** · Evidence **CONFIRMED** (code review)

**Location.** `src/shamir.rs:700-728`.

```rust
let initial_capacity = expected_size
    .map(|s| s as usize)
    .unwrap_or(4096)
    .min(64 * 1024)
    .min(max_limit as usize);
...
let new_cap = (decompressed.capacity() * 2)
    .max(decompressed.len() + n)
    .min(max_limit as usize);
let mut new_decompressed = Zeroizing::new(Vec::with_capacity(new_cap));
```

**Impact.** On 32-bit targets (`wasm32`, `i686`, `armv7`), `max_limit as usize` truncates `u64`:
if `max_limit` is a multiple of `2^32` (e.g., `4 GiB`), `max_limit as usize` becomes `0`, clamping
`new_cap` to `0` and forcing standard unzeroized `Vec` reallocation on `extend_from_slice`.
Additionally, `decompressed.capacity() * 2` can overflow `usize`, and `Vec::with_capacity` aborts on
OOM instead of returning `ShamirError::StorageError` (unlike `try_reserve` in streaming).

**Fix.**
```diff
+        let max_limit_usize = usize::try_from(max_limit).unwrap_or(usize::MAX);
         let initial_capacity = expected_size
-            .map(|s| s as usize)
+            .map(|s| usize::try_from(s).unwrap_or(usize::MAX))
             .unwrap_or(4096)
             .min(64 * 1024)
-            .min(max_limit as usize);
+            .min(max_limit_usize);
...
-            let new_cap = (decompressed.capacity() * 2)
+            let new_cap = decompressed.capacity().saturating_mul(2)
                 .max(decompressed.len() + n)
-                .min(max_limit as usize);
-            let mut new_decompressed = Zeroizing::new(Vec::with_capacity(new_cap));
+                .min(max_limit_usize);
+            let mut buf = Vec::new();
+            buf.try_reserve_exact(new_cap)
+                .map_err(|_| ShamirError::StorageError("Memory allocation failed for decompression".into()))?;
+            let mut new_decompressed = Zeroizing::new(buf);
```

**Regression test.** Test `decompress_bounded` with `max_limit = 1u64 << 32` and `u64::MAX`.

---

### F-23
**Non-`zeroize` fallback (`--no-default-features`) has incomplete memory hygiene and API parity gaps.**
Status **OPEN** · Severity **Medium** · Evidence **CONFIRMED** (code review)

**Location.** `src/lib.rs:94-152`, `src/hsss.rs:58-92`, `src/shamir.rs:212`.

**Impact.**
1. `ZeroizeFallback` (`src/lib.rs:94-103`) zeroes only `self.as_mut()` (`0..len`), leaving `Vec<u8>`
   spare capacity (`len..capacity`) uncleared after `clear()`/`truncate()`/reallocation.
2. Fallback `pub struct Zeroizing<T: ZeroizeFallback>(pub T);` exposes `.0` publicly, breaking API
   parity with `zeroize::Zeroizing` and allowing callers to move `T` out without zeroizing.
3. `AccessLevel` and `HierarchicalShare` (`src/hsss.rs:58-92`) have no `#[cfg(not(feature = "zeroize"))]`
   `Drop` impl (unlike `Share` and `Dealer`), leaving `level_name`/`name` uncleared when `zeroize` is off.
4. `Share::to_bytes()` returns plain `Vec<u8>` instead of `Zeroizing<Vec<u8>>`, so serialized share
   bytes remain on the heap unless callers wrap them.

**Fix.** Make fallback `Zeroizing`'s inner field private (`struct Zeroizing<T>(T)`), add fallback
`Drop` to `HierarchicalShare` and `AccessLevel`, document that full spare-capacity zeroization
requires the `zeroize` feature, and consider returning `Zeroizing<Vec<u8>>` from `to_bytes()` in
0.4.0 (breaking).

---

### F-24
**`reconstruct_stream_internal` allocates and reads headers from all `sources` before bounding `sources.len()`.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (code review)

**Location.** `src/shamir.rs:1604-1620`.

**Impact.** If a caller passes more than 255 stream readers, `reconstruct_stream_internal` allocates
`Vec::with_capacity(sources.len())` and executes `read_exact(&mut header)` on every reader before
checking `sources.len() > total_shares as usize` at line 1666.

**Fix.**
```diff
         if sources.len() < 2 {
             return Err(ShamirError::InsufficientShares {
                 needed: 2,
                 got: sources.len() as u8,
             });
         }
+        if sources.len() > u8::MAX as usize {
+            return Err(ShamirError::InvalidShareFormat);
+        }
```

---

### F-25
**`generate_refresh_deltas_with_rng` permits empty deltas and sizes exceeding `MAX_SHARE_DATA_LEN`.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (code review)

**Location.** `src/shamir.rs:1919`.

**Impact.** `data_length` is checked against `MAX_CONFIG_CHUNK_SIZE + 64` (64 MiB + 64 B), which
exceeds `MAX_SHARE_DATA_LEN` (64 MiB) — producing `Share` values that `Share::to_bytes()` and
`ShamirShare::reconstruct()` reject with `InvalidShareFormat`. It also allows `data_length == 0`
(same class as [F-07](#f-07)).

**Fix.**
```diff
-        if data_length > crate::config::MAX_CONFIG_CHUNK_SIZE + 64 {
+        if data_length == 0 || data_length > MAX_SHARE_DATA_LEN {
```

---

### F-26
**Streaming ignores `SplitMode::Parallel`; `reconstruct` retains a dead unauthenticated-decompression branch.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (code review)

**Location.** `src/shamir.rs:1726` (`split_chunk_into`), `src/shamir.rs:1600` (`reconstruct_stream_internal`),
`src/shamir.rs:1251-1261` (`reconstruct_from_views_with_mode`).

**Impact.** (a) Configuring `SplitMode::Parallel` has no effect on `split_stream` or
`reconstruct_stream`, which is undocumented. (b) `reconstruct_from_views_with_mode` contains an
`else if compression` branch that would decompress unauthenticated bytes if `!integrity_check &&
compression` ever bypassed validation.

**Fix.** Document that streaming is sequential (or parallelize chunk splitting), and replace lines
1251–1261 with `Err(ShamirError::InvalidShareFormat)`.

---

### F-27
**HSSS API, `serde`, and documentation parity gaps.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (code review)

**Location.** `src/hsss.rs:88-104`, `src/hsss.rs:212`, `src/hsss.rs:422`.

**Impact.** (a) `HierarchicalShare` exposes `pub` mutable `level_name` and `shares` (same issue as
[F-08](#f-08) for `Share`). (b) `HierarchicalShare` and `AccessLevel` do not derive
`Serialize`/`Deserialize` under `--features serde`. (c) `HsssBuilder::with_config` lacks
`#[must_use]` (missed by [F-12](#f-12)). (d) `Hsss::reconstruct` doc comment (`src/hsss.rs:422`)
still claims it calls `ShamirShare::reconstruct()` rather than `reconstruct_from_views_with_scheme`.

**Fix.** Add `#[must_use]` to `HsssBuilder::with_config` and update the doc comment in 0.3.1;
align field visibility with [F-08](#f-08) in 0.4.0 and decide whether `serde` should cover HSSS.

---

### F-28
**Audit harness (`../shamir_share_audit/`) has an inverted finding check, broken paths, and coverage gaps.**
Status **OPEN** · Severity **Low** · Evidence **CONFIRMED** (harness review)

**Location.** `../shamir_share_audit/run_audit.sh:19,40,91,124,137-141,170`,
`../shamir_share_audit/probe/Cargo.toml:10`, `../shamir_share_audit/results/SUMMARY.md`.

**Impact.**
1. **Inverted `F-09` check (`run_audit.sh:170`)**: `check F-09 Low recon/ci-security-jobs open_if 'cargo audit'`
   uses `open_if` instead of `fixed_if`. Because `ci.yml` has no `cargo audit`, the log is empty and
   the runner falsely reports `F-09` as **FIXED**.
2. **Broken relative paths**: `run_audit.sh` (`REPO_ROOT=..`, `RESULT_DIR="audit/results"`,
   `PROBE="audit/probe"`) and `probe/Cargo.toml` (`path = "../.."`) assume the harness lives inside
   `shamir_share/audit/`, so running from the sibling `shamir_share_audit/` directory fails.
3. **`doc/deny-warnings` failed in the recorded run**: `results/logs/doc_deny-warnings.log` shows
   `env: warnings: No such file or directory` and `SUMMARY.md` records `FAIL`, contradicting
   Appendix C's `PASS`.
4. **Whole-binary `asm-dump` branch count (`run_audit.sh:137-141`)**: counts branches across the
   entire compiled binary (including `std::io` / `println!`) rather than isolating `gf_mul_probe` /
   `gf_inv_probe`.
5. **Missing probes/markers**: `F-19` and `F-20` are omitted from `FINDINGS.md`; `probe/Cargo.toml`
   omits `serde`; there are no probes for `Hsss`, `serde`, or `refresh_shares` with `authentication_key`.

**Fix.** Change `F-09` to `fixed_if`, parameterize `TARGET_REPO` (default `../shamir_share`),
scope `asm-dump` to the probe symbols, add `F-19`/`F-20`/`F-21`–`F-27` checks, and add `Hsss` +
`serde` probes.

---

### F-14, F-15, F-16
Status **OPEN** · Severity **Info**

* **F-14** `CHANGELOG.md:77` claims decompressed buffers "shrink to fit"; `grep -rn shrink_to_fit src/`
  finds nothing. Delete the sentence or implement it.
* **F-15** No epoch/version field on `Share` (`src/shamir.rs:96-109`) or in the wire header, so refresh
  epochs are unrepresentable. Mixing old/new epoch shares *is* detected (`Err(Data integrity check
  failed)`, see `refresh` probe) but only by the digest — which under F-01 is unkeyed. Refresh at
  `k == n` cannot detect corruption before or after refresh (information-theoretically unavoidable;
  verified by the `refresh` probe, section D). Worth one doc sentence.
* **F-16** `src/shamir.rs:1918-1921`: the trailing-byte probe treats `ErrorKind::Interrupted` as a hard
  error. Harmless for `Cursor`/files; incorrect for a signal-interrupted reader.

---

## 3a. Corrections to the first-pass verbal report

Recorded for honesty — these were in the initial summary and are wrong or overstated here:

| Claim in the first pass | Correct position |
|---|---|
| "271 tests" | **196**: 163 unit/integration + 33 doc-tests. |
| "Miri found no UB on the field **and wire-format** paths" | Miri ran on the `finite_field` tests only (11 tests). The wire-format parsers were not Miri'd. |
| "compressed streams are only fuzzed in the integrity-on configuration" | They are **not fuzzed at all** — the fuzz crate enables no `compress` (this became [F-17](#f-17), Medium). |
| "`ShareNotFound`, `InvalidShareCount`, `StorageError` are dead" | Only `ShareNotFound` is unused; `InvalidShareCount` and `StorageError` are constructed ([F-11](#f-11)). |
| "the 256 KiB margin is fine" | Measured fine on incompressible input at the maximum chunk; the *proof* for zstd's worst case is missing ([F-18](#f-18)). |
| "no secret bytes in any error message" | Verified for `Debug` (canary) and by reading the error formats; not exhaustively measured. |

---

## 4. Docs vs code mismatches

| Claim | Location | Reality |
|---|---|---|
| "Any inconsistent or rogue share will cause reconstruction to immediately fail with `IntegrityCheckFailed`" | `README.md:123` | True only for *excess* shares above k, and only for accidental corruption. A rogue share inside the first k, or any set at exactly k, reconstructs to attacker-chosen plaintext (F-01). |
| "Tamper Detection … prevents modifications, flag stripping, and truncation" | `CHANGELOG.md:73` | Unkeyed → no tamper detection. Flag stripping and truncation *are* caught (metadata is in the digest); "modification" is not. |
| "Arithmetic routines are **verified branchless**" | `README.md:122` | No artifact in the repo verifies this (no asm check, no dudect, no CI job). I verified it manually (§5 item 2). |
| "100% Safe Rust … across the entire library" | `README.md:23` | True for `shamir_share` (`geiger`: 0 unsafe). `--features compress` pulls `zstd-sys`, which is C. Say "no `unsafe` in this crate". |
| "Enforced 256 MiB allocation limit on `chunk_size * total_shares`" | `CHANGELOG.md:65` | Exact as worded, but reads as a peak-memory guarantee; real peak is 2–3× (F-05). |
| "Decompressed buffers shrink to fit without unzeroized heap residue" | `CHANGELOG.md:77` | No `shrink_to_fit` in `src/` (F-14). |
| "~64 MiB max peak memory" for streaming | `CHANGELOG.md:64` | Understated for k=255: active block buffers alone are 255 × 64 KiB ≈ 16 MiB, plus a chunk buffer up to `MAX_STREAM_CHUNK_SIZE` ≈ 64 MiB. |
| `#![no_std]` example uses `rand_chacha` with a fixed seed | `README.md:89-104` | The warning is present, but `rand_chacha` is not listed as a dependency the reader must add; a copy-paste hazard. |
| Duplicated doc block | `src/shamir.rs:786-800` | The `try_dealer` doc (with its own `# Example`) is glued above `try_dealer_with_rng`'s doc, so docs.rs shows two examples for one method. |

Accurate and verified: the wire format (`README.md:13` — `b"SHS1"`, version 3, 13-byte header
`[magic(4)][ver(1)][flags(1)][index(1)][threshold(1)][total(1)][len LE(4)]`), the feature matrix
(`README.md:106-117` vs `Cargo.toml:22-35`), the information-theoretic claim for the payload
(`README.md:121`), and the compression side-channel warning (`README.md:125`).

---

## 5. Areas reviewed with no issues found

Each entry states what was checked and how. These are the parts of the crate that are in good shape
and should not be disturbed by the fixes above.

1. **GF(2⁸) arithmetic — exact.** All 65,536 `a*b` products and all 255 inverses compared against an
   independent reference written from the field definition (carryless multiply, reduce 0x11B):
   **0 mismatches**. `inverse(0) == None`, `ct_inverse(0).is_some() == false`. `3^5 == 51`,
   `0^0 == 1`, `0^5 == 0`. Distributivity: 0 violations on a strided sweep (`gf` probe).
2. **Branchlessness — verified in optimized assembly.** `gf256_multiply_const_time` compiles to a
   fully unrolled mask-only body (`and/eor/neg/lsl`), **zero** conditional branches, in both `subtle`
   configurations; `ct_inverse` ends in `tst/cset/bic/and/csel`; `Option::from(CtOption)` is a `csel`
   (method in Appendix A phase 3).
3. **Polynomial generation.** `k-1` coefficients per byte from `rng.fill_bytes` over the full 8-bit
   range (no modulo bias); secret is the constant term; layout
   `coefficients[b*(t-1) + (t-2)]` with Horner verified by hand for `t=2`. Fresh randomness per strip
   and per chunk — no reuse. RNG failure propagated (`ChaCha20Rng::try_from_rng(&mut SysRng)` →
   `ShamirError::RngError`); no `unwrap`/`expect`/`panic!` in non-test library code.
4. **Index domain.** `x = 0` rejected in `Share::new`, `from_bytes`, serde `TryFrom`,
   `compute_lagrange_coefficients_from_indices`, both `reconstruct_*` paths and stream headers. `n ≤
   255` enforced by the `u8` type; `k ≥ 2` and `k ≤ n` enforced in `ShamirShareBuilder::build`.
   `n=255,k=255` and `k=2,n=255` with indices {254,255} round-trip correctly (reference `L(0)` for
   {254,255} = `[0xFF, 0xFE]` matches the crate).
5. **Reconstruction validation — could not be defeated.** Duplicate indices, mixed threshold, mixed
   integrity flags, inconsistent lengths and insufficient shares are all rejected. Empty and 1-byte
   secrets round-trip. The **excess-share check** (`src/shamir.rs:1208-1222`) is *sound*: replacing
   `active[0]` with the excess view makes the reconstructed value an injective function of that
   view's data, so any deviation is caught with probability `1 - 256^-len`; a corrupted excess share
   is rejected and a clean one accepted (`api` probe).
6. **Wire-format canonicalisation.** 752 single-byte mutations of a valid share: 655 accepted,
   **0 non-canonical** (`from_bytes` → `to_bytes` is the identity on every accepted input). Reserved
   flag bits, version, magic, trailing bytes and exact-length prefix all enforced. Allocation is
   bounded by input length — no length-prefix amplification.
7. **Fuzzing.** 16,086,443 execs of `fuzz_share_from_bytes`, 932,075 of `fuzz_reconstruct`, 75,089 of
   `fuzz_reconstruct_stream` — no crashes or hangs. Corpus replay (`corpus` probe): 133 stream inputs
   with no panic; 15 accepted share inputs, 0 non-canonical; 306 single-byte stream mutations with no
   panic.
8. **Streaming integrity (integrity-check-on path).** Per-chunk digest binds
   `STREAM_MAGIC ‖ version ‖ flags ‖ threshold ‖ total_shares ‖ stream_id(16) ‖ is_last ‖
   chunk_index(8) ‖ salt(16) ‖ payload`. Truncation → `UnexpectedEof`; a zero length before the
   terminal frame → explicit `UnexpectedEof`; trailing data after EOS → rejected; reorder/duplicate →
   digest or index mismatch. Max-size chunk with compression verified end-to-end: 64 MiB incompressible
   → 67,110,458-byte share chunk, reconstructed byte-identically (`stream --heavy`).
9. **Refresh.** k<n corruption → `IntegrityCheckFailed`; clean refresh changes share data and still
   reconstructs; old/new epoch mixing → `IntegrityCheckFailed`; k=n corruption undetectable before and
   after refresh (inherent — see F-15).
10. **Memory hygiene.** `zeroize::Zeroizing`'s `Debug` is `Zeroizing { .. }` — I pushed a canary through
    `format!("{:?}", reconstruct(...))` and it is **absent**. `Share`/`ShareView`/`Dealer`/`Config`
    hand-write redacting `Debug` (`Config` shows `authentication_key: Some("[REDACTED]")`). All secret
    comparisons use `subtle::ConstantTimeEq`, including `PartialEq` on `Share`, `ShareView`,
    `HierarchicalShare`. `Dealer::next` zeroizes coefficients after the last share.
11. **Feature matrix / no_std / MSRV.** All 15 feature combinations and both wasm32 configurations
    compile; `cargo +1.88.0 check --all-features` passes, so `rust-version = "1.88"` is accurate;
    `streaming` correctly implies `std`; the `no_std` entry points are the `*_with_rng` family.
12. **`parallel`.** With the same seeded RNG, `SplitMode::Parallel` and `SplitMode::Sequential` produce
    **byte-identical** shares; the `par_chunks_mut(4096)` reconstruction path is correct at 40 KiB and
    identical to the serial path (`api` probe).
13. **HSSS.** Level ranges computed once and validated on reconstruct (index inside range, count equals
    `shares_count`, level must exist, duplicate names rejected in `build`); below-threshold sets fail
    with `InsufficientShares`; a level reaching the threshold alone is the documented design.
14. **No unsafe.** `#![forbid(unsafe_code)]`; `cargo geiger` reports 0 unsafe in this crate. Miri found
    no UB on the field-arithmetic tests.
15. **Dependency advisories.** `cargo audit` against the local DB (1550 advisories, 134 crates): no
    vulnerabilities reported.

---

## 6. Missing tests, fuzz targets and CI jobs (prioritized)

**Tests**

1. F-01: assert the documented trust boundary — with a key the forged set must fail; without one the
   API must surface `authenticated == false` (or require explicit unauthenticated opt-in).
2. F-02 / F-22: `with_max_decompressed_stream_size(u64::MAX)` and `1u64 << 32` round-trip.
3. F-03: key + `integrity_check(false)` must be rejected at `build()`.
4. F-05 / F-21: latency guard for n=255 at a fixed size; verify `refresh_shares` catches corrupted
   excess shares via share-domain evaluation without materializing `P(0)`.
5. F-07 / F-25: `from_bytes`/`new`/`generate_refresh_deltas_with_rng` zero-length and `> MAX_SHARE_DATA_LEN` rejection.
6. F-18: assert `ZSTD_compressBound(MAX_CONFIG_CHUNK_SIZE)` fits under the stream chunk limit.
7. F-24: `reconstruct_stream` with `> 255` sources fails immediately without reading headers.
8. Property test over `n ∈ {2,3,255} × k ∈ {2,k,n} × len ∈ {0,1,255,4 KiB}` × random index subsets —
   `tests/proptest_suite.rs` (92 lines) is thinner than that.

**Fuzz targets & probes**

- Fix F-17 first (enable `compress`, `serde`, `parallel` in `fuzz/Cargo.toml`), then:
  `fuzz_share_from_json` (serde `TryFrom`), `fuzz_stream_compressed` (round-trip fidelity, not just
  no-panic), `fuzz_config_builder` (arbitrary chunk size / flag combos → `build()`), and run +
  extend `fuzz_hsss` to feed `Hsss::reconstruct` adversarial level names.
- In `../shamir_share_audit/probe/`, add probes for `Hsss`, `serde`, and `refresh` with `authentication_key`.

**CI jobs**

`security` (`cargo audit`, `cargo deny check --all-features`), `miri` (`--lib`, default features),
`fuzz-smoke` (60 s per target on PRs), `wasm32 test`, `--locked` on the whole matrix.

---

## 7. Remediation plan

| # | Fix | Effort | Blocking release? |
|---|---|---|---|
| 1 | [F-02](#f-02) & [F-22](#f-22) `saturating_add(1)`, `usize::try_from`, `saturating_mul(2)`, `try_reserve_exact` + tests | 30 min | **Yes** |
| 2 | [F-03](#f-03) reject key-without-integrity in `validate()` + test | 20 min | **Yes** |
| 3 | [F-01](#f-01) rewrite overclaiming doc sentences; add "does not protect against"; `#[must_use]` + `# Authenticity` on `reconstruct` (or keyed API) | 1 h | **Yes** |
| 4 | [F-21](#f-21) switch `refresh_shares_with_rng` excess check to `compute_lagrange_basis_at_target` (no `P(0)` materialization) + doc | 45 min | **Yes** |
| 5 | [F-17](#f-17) enable `compress`/`serde` for the fuzz crate + 2 new targets; [F-20](#f-20) drop unused `tempfile` | 1 h | **Yes** |
| 6 | [F-04](#f-04) one-line `Cargo.toml` feature + CI assertion | 30 min | **Yes** (same release) |
| 7 | [F-07](#f-07) & [F-25](#f-25) reject empty share/delta payloads and cap deltas at `MAX_SHARE_DATA_LEN` | 20 min | **Yes** (trivial) |
| 8 | [F-19](#f-19) run `cargo fmt --all` so CI fmt gate passes | 5 min | **Yes** (CI blocker) |
| 9 | [F-09](#f-09) CI: audit/deny, Miri, fuzz-smoke, `--locked` | 2 h | **Yes** — a security release must gate on advisories |
| 10 | [F-23](#f-23) private fallback `Zeroizing` field + fallback `Drop` on HSSS types + doc (`to_bytes` → 0.4.0) | 45 min | No (0.3.1) |
| 11 | [F-24](#f-24) & [F-26](#f-26) cap `sources.len() <= 255` before header reads; remove dead unauthenticated-decompress branch; doc sequential streaming | 30 min | No (0.3.1) |
| 12 | [F-12](#f-12) & [F-27](#f-27) `#[must_use]` on `Config`/builders (`HsssBuilder::with_config`), update HSSS doc | 20 min | No (0.3.1) |
| 13 | [F-06](#f-06), [F-14](#f-14), [F-15](#f-15), [F-16](#f-16) doc + small code corrections | 1 h | No (0.3.1) |
| 14 | [F-05](#f-05) reuse `compute_lagrange_basis_at_target` for in-memory excess check; document cost model; correct budget formula | 3 h | No (0.3.1) |
| 15 | [F-18](#f-18) assert the zstd bound in a test | 30 min | No |
| 16 | [F-28](#f-28) fix `shamir_share_audit/run_audit.sh` (`F-09` `fixed_if`, paths, `asm-dump` scope, missing markers/probes) | 1 h | No (audit infra) |
| 17 | [F-10](#f-10), [F-11](#f-11) packaging excludes + error taxonomy | 1 h | No (breaking parts → 0.4.0) |
| 18 | [F-08](#f-08) & [F-27](#f-27) private `Share` & `HierarchicalShare` fields + accessors | 3 h | No — **0.4.0** (breaking) |
| 19 | [F-13](#f-13) zeroize `ShareHelper`; confirm with a heap test | 1 h | No |

**Pre-release checklist for the next crates.io version**

- [ ] `cargo test --all-features`, `--no-default-features`, and the 15-combination matrix green
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] `cargo fmt --all -- --check` clean ([F-19](#f-19))
- [ ] `cargo +1.88.0 check --all-features` (MSRV) and both wasm32 configurations
- [ ] `../shamir_share_audit/run_audit.sh` reports **no finding `OPEN`** for F-02…F-04, F-07, F-17, F-19, F-21, F-22 (after fixing [F-28](#f-28))
- [ ] `cargo audit` and `cargo deny check` in CI, not only locally
- [ ] `cargo doc` with `-D warnings`; README claims re-read against §4
- [ ] 60 s each of all four fuzz targets (including `fuzz_hsss`), plus the new compressed/serde targets
- [ ] `cargo package --list` reviewed; `cargo publish --dry-run` (needs network)
- [ ] CHANGELOG entry that states the trust boundary plainly — do not repeat "Tamper Detection"
- [ ] For [F-01](#f-01): confirm keyed `reconstruct_with_scheme` rejects forged shares (and if opting for an API change instead of docs-only, re-run `forge` to confirm `FORGERY BLOCKED`)

---

## 8. Residual risk — what this audit could not verify

- **No independent cryptographic review of the composition.** I verified GF(2⁸) arithmetic, polynomial
  shape, interpolation and framing against references and by construction; "implements Shamir over
  GF(2⁸) correctly" is not "the composition is right for your protocol". A human cryptographer should
  review the unkeyed-digest decision in F-01 against your threat model — my "High, not Critical"
  judgement is a judgement, not a proof.
- **No timing measurements.** Branchlessness was verified statically in optimized assembly; no dudect
  or statistical timing test was run. Cache effects from tables are a non-issue (there are none), but a
  full side-channel evaluation needs hardware and many samples.
- **32-bit targets not exercised.** No `i686`/`armv7` target is installed; `usize` arithmetic in the
  parsers was reviewed by reading, with `wasm32` compiling but its tests never run. The `as usize`
  casts in `decompress_bounded` are **not** benign on 32-bit targets — see [F-22](#f-22).
- **Miri coverage is partial** — field arithmetic only. `compress` cannot be Miri'd through `zstd-sys`.
- **No coverage numbers.** `cargo llvm-cov` collected profiles but failed to render a report
  ("No filenames specified!"); untested branches in security-critical paths are unquantified.
  `cargo mutants` is not installed, so mutation survival is unknown.
- **`cargo deny` did not run** in the audit sandbox (read-only advisory DB); license/advisory policy is
  unverified beyond `cargo audit`.
- **`cargo publish --dry-run`, `cargo semver-checks`, `cargo hack --feature-powerset` not run**
  (network / tooling absent); the feature matrix above is a hand-built substitute.
- **Platform-specific behaviour** (Windows I/O semantics, `SysRng` on exotic platforms) untested; only
  macOS aarch64.

Passing this audit reduces, but does not eliminate, production risk. F-01 is a property of the default
configuration rather than a bug that can be patched away: it needs a decision about whether
`reconstruct` should be able to return unauthenticated bytes at all.


---

# Appendix A — the repeatable audit process

This is the procedure that produced this report. It is written so a different engineer, or the same
one in six months, can reproduce every claim. **Read-only**: none of these steps modify `src/`; the
only writes are to `audit/probe/target/` and `audit/results/`.

## 0. Quick path (about 10 minutes)

```bash
git rev-parse HEAD                                    # record the commit
./audit/run_audit.sh                                  # phases 1–2 + all reproduction probes
cat audit/results/FINDINGS.md                         # OPEN / FIXED per finding
```

If `run_audit.sh` reports any `OPEN` for F-01…F-04, F-07, F-17, the release is **not** ready. Go to
the full procedure below to confirm nothing new appeared.

## Phase 0 — Recon (30 min, no build)

Goal: know what the crate *claims* before looking at what it does, and pin the artifact.

```bash
git rev-parse HEAD && git status --porcelain          # commit + clean tree
cargo tree -e features --all-features | head -60      # real feature graph
cargo tree -e features -i subtle                      # F-04 check
cargo tree --manifest-path fuzz/Cargo.toml -e features | grep 'feature "'   # F-17 check
```

Then read, in this order, and write down every claim that asserts a security property:

1. `Cargo.toml` — version, `rust-version`, `default` features, every optional dep.
2. `README.md` §Key Features and §Security Guarantees — these are the hypotheses to falsify.
3. `CHANGELOG.md` — the "Security" and "Fixed" sections are claims about the current code.
4. `lib.rs` crate docs — the doc-tests are executable claims.
5. `src/*.rs` in full, in this order: `finite_field.rs` (the math), `config.rs` + `error.rs` (the
   contract), `shamir.rs` (the whole protocol, 3 000 lines — read it in two passes: share/wire/
   split first, then reconstruct/streaming/refresh), `hsss.rs`.
6. `.github/workflows/*.yml`, `deny.toml`, `justfile` — what actually gates a release.

Deliverable: a table of claim → file:line → what would falsify it. The mismatches become §4 of this
document.

## Phase 1 — Automated baseline

```bash
cargo build --offline --all-features
cargo test  --offline --all-features                 # expect: 163 unit/integration + 33 doc-tests
cargo test  --offline --no-default-features

# feature matrix (cargo-hack is not installed; this is the substitute)
for f in "" std zeroize std,zeroize std,streaming std,hsss hsss std,refresh refresh \
         std,parallel std,compress std,serde serde hsss,refresh \
         std,hsss,refresh,parallel,compress,serde,zeroize; do
  if [ -z "$f" ]; then cargo check --offline --no-default-features || echo "FAIL [$f]";
  else cargo check --offline --no-default-features --features "$f" || echo "FAIL [$f]"; fi
done

cargo check --offline --target wasm32-unknown-unknown --no-default-features
cargo check --offline --target wasm32-unknown-unknown --no-default-features --features "hsss,refresh,serde"
cargo +1.88.0 check --offline --all-features          # MSRV must actually compile

cargo clippy --offline --all-targets --all-features -- -D warnings      # the CI gate
cargo clippy --offline --lib --all-features --message-format=short -- \
  -W clippy::pedantic -W clippy::indexing_slicing -W clippy::cast_possible_truncation \
  -W clippy::arithmetic_side_effects | grep -c '^src/'                  # noise count, not a gate
RUSTDOCFLAGS="-D warnings" cargo doc --offline --all-features --no-deps
cargo fmt --all -- --check
cargo package --offline --list
cargo audit --no-fetch          # drop --no-fetch when the network is available
cargo deny --offline check      # may be blocked in a sandbox; record it if so
cargo geiger --offline --all-features | head -5
cargo +nightly miri test --offline --lib finite_field
```

**Pass** = every command exits 0 except the pedantic-clippy count and (possibly) `cargo deny` in a
sandbox. Anything else is a release blocker and should get its own finding.

Fuzz (needs `cargo-fuzz` + nightly; ~1 min each):

```bash
for t in fuzz_share_from_bytes fuzz_reconstruct fuzz_reconstruct_stream fuzz_hsss; do
  CARGO_NET_OFFLINE=true cargo +nightly fuzz run $t -- -max_total_time=60
done
```

**Pass** = `Done N runs` with no `crash-` artifact in `fuzz/artifacts/`. Record the exec counts; a
sudden collapse in exec/s or in `cov:` between releases is itself a signal.

## Phase 2 — Cryptographic correctness

Not automatable in full; the harness covers what can be:

```bash
cd audit/probe
cargo run --release --bin gf        # exhaustive 65 536 products + 255 inverses vs an independent field
cargo run --release --bin api       # round-trips, k=n=255, high indices, empty/1-byte, excess shares
cargo run --release --bin refresh   # refresh consistency, epoch mixing
cargo run --release --bin corpus    # replay the checked-in fuzz corpora
```

Manual checklist (each line was performed for this audit; re-do it when the code changes):

- **Reduction polynomial** — `0x11B` in `gf256_multiply_const_time`; confirm the `0x1b` constant.
- **Inverse chain** — multiply out the chain in `gf256_inverse_const_time` and confirm it equals 254.
- **Coefficient layout** — `coefficients[b*(t-1) + (t-2)]` … `+0`, constant term = `data[b]`; check
  Horner in `Dealer::next` and in the `SplitMode::Parallel` branch agree.
- **Coefficient randomness** — one `rng.fill_bytes` per strip/chunk, full 8-bit range, no modulo, no
  reuse across shares.
- **Index domain** — `x = 0` rejected everywhere; `n ≤ 255` from the `u8` type; `k ≥ 2`, `k ≤ n` in
  `ShamirShareBuilder::build`; `n = 255` behaviour.
- **Reconstruction validation matrix** — duplicate indices, index 0, mismatched lengths, mismatched
  metadata, fewer than k, more than k, shares from different secrets.
- **Digest/AEAD coverage** — write down exactly which fields the digest covers (compare `compute_digest`
  call sites in split vs. reconstruct; a field in one and not the other is a bug).
- **Information-theoretic claim** — confirm no secret-dependent value reaches framing: the share length
  is `64 + payload.len()` (public), so state the length leak explicitly.

## Phase 3 — Side channels and codegen

```bash
cd audit/probe && cargo build --release --bin asmcheck
objdump -d --no-show-raw-insn target/release/asmcheck \
  | awk '/<_gf_mul_probe>:/{p=1} p&&/^$/{exit} p'          # tail-call thunk
# the real body, when the compiler emits it out of line:
objdump -d --no-show-raw-insn target/release/asmcheck \
  | awk '/gf256_multiply_const_time>:/{p=1} p&&/^$/{exit} p' \
  | grep -cE '\b(b\.[a-z]+|cbz|cbnz|tbz|tbnz)\b'           # expect 0
```

**Pass** = zero conditional branches in the multiply; `neg/and/eor` masks only; the inverse ends in
`tst/cset/bic/and/csel`. Also count `bl` instructions: 16 calls to `subtle::black_box` means F-04 is
open (an out-of-line call per bit, ~2.5× slowdown).

Then grep for secret-dependent control flow by hand:

```bash
grep -n "if .*data\[\|if .*secret\|\.iter().find\|\.position(\|match .*\.0 " src/*.rs
grep -rn "== " src/*.rs | grep -iv "test\|len()\|index\|threshold\|total_shares\|flags"   # non-CT compares
```

**Pass** = no branch, loop bound, early return or table index depends on a secret byte; all comparisons
of secret material use `subtle`.

## Phase 4 — Untrusted-input robustness

Attacker-facing entry points: `Share::from_bytes`, serde `Deserialize`, `reconstruct`,
`reconstruct_stream`, `Hsss::reconstruct`.

Checklist per entry point:

1. Length-prefixed allocations are bounded by *input length*, not by the declared length.
2. Every `as` cast, index and slice is preceded by a length check (or proven in-bounds by a loop).
3. No `unwrap`/`expect`/`panic!`/`unreachable!` reachable from the public API outside tests:
   `grep -n "unwrap()\|expect(\|panic!\|unreachable!" src/*.rs` and confirm each hit is a doc-test or
   under `#[cfg(test)]`.
4. Canonical encoding: two byte strings cannot parse to the same value (`corpus` + `api` probes).
5. Decompression and cumulative stream output are bounded, and the bound cannot overflow (F-02).

## Phase 5 — Feature-specific review

Run the relevant probe, then re-read the feature's code with these questions:

| Feature | Probe | Key questions |
|---|---|---|
| `streaming` | `bin/stream`, `bin/corpus` | Short reads, `Interrupted`, EOF mid-chunk, chunk 0/huge, reorder/duplicate/truncate/splice, can the final chunk be dropped undetected, is memory bounded by chunk size, is partial output on error documented |
| `compress` | `bin/stream --heavy` | Decompression bombs, cumulative limit, behaviour when compression expands data, CRIME/BREACH documented |
| `hsss` | crate tests + `fuzz_hsss` | Level/off-by-one, disjoint index ranges, can a below-policy set reconstruct, can a matching set fail |
| `refresh` | `bin/refresh` | Constant term truly zero, epoch mixing detected, k=n limitation |
| `parallel` | `bin/api` | Output identical to serial for the same RNG, no per-thread RNG reuse, panic propagation |
| `serde` | crate tests | Same invariants as `from_bytes`, human-readable vs binary |
| `zeroize` | `bin/api` leak section | Every copy of secret material, `Debug` redaction, `Drop` coverage |

## Phase 6 — API and misuse resistance

Read every public signature and ask "can this be called wrongly without a compile error or an `Err`?".
Checks used here:

```bash
grep -n "pub fn" src/*.rs | grep -c ""                  # inventory
cargo clippy --offline --lib --all-features --message-format=short -- \
  -W clippy::must_use_candidate | grep 'src/config.rs'  # F-12
grep -n "non_exhaustive" src/*.rs                        # then check field visibility underneath
```

**Pass** = invalid configurations are unrepresentable or rejected at `build()`; every secret-bearing
type has a hand-written redacting `Debug`; every consuming builder method is `#[must_use]`; errors are
a `#[non_exhaustive]` enum with structured variants.

## Phase 7 — Release and operations readiness

```bash
grep -c "cargo audit\|cargo deny\|miri\|--target wasm32-unknown-unknown" .github/workflows/*.yml
cargo package --offline --list                          # junk in the tarball?
cargo package --offline --list | grep -E "deny.toml|\.gitignore|Cargo.lock"
cargo publish --dry-run                                 # needs network; otherwise CI only
```

**Pass** = CI gates on audit/deny, Miri, fuzz smoke, fmt, clippy, doc, MSRV, wasm; the tarball contains
only source, licence, README, CHANGELOG and the test/bench/example sources; every public item is
documented and the doc-tests run.

## Cadence

| Trigger | Run |
|---|---|
| Every PR | `./audit/run_audit.sh` (phases 1–2) |
| Every release | full process, plus `--fuzz 60`, plus a manual read of `git diff` since the last audit |
| New advisory published | `cargo audit`, then re-check the affected feature |
| Any change to `shamir.rs` reconstruct/split/stream paths | phases 2–5 in full; the probes exist for this |

**Limits of this process.** It is a white-box audit by one engineer, not a cryptanalysis. It cannot
replace an external review for a crate that guards real secrets (see §8).

---

# Appendix B — the reproduction harness

`audit/probe/` is a `publish = false` crate that depends on `shamir_share` by relative path, so every
finding is reproduced through the **public API only**, exactly as a consumer would hit it. It is
excluded from the published package.

| Bin | Reproduces | What to expect |
|---|---|---|
| `gf` | §5 item 1 | `mul: 0 mismatches`, `inv: 0 mismatches`, `OK` |
| `forge` | [F-01](#f-01) | `FORGERY SUCCEEDED` (open) / `FORGERY BLOCKED` (fixed) |
| `stream` | [F-02](#f-02), §5 item 8, [F-18](#f-18) | `*** BUG: silent data loss` (open); `--heavy` prints the 64 MiB compressed chunk sizes |
| `refresh` | §5 item 9, [F-15](#f-15) | A rejected, B ok, C rejected, D undetectable, E no epoch |
| `api` | [F-07](#f-07), §5 items 5, 6, 10, 12 | `from_bytes(len=0 payload) = Ok(0)` (open); 0 non-canonical mutations |
| `authkey` | [F-03](#f-03) | `authentication key had no effect` (open) / `build() rejected` (fixed) |
| `perf` | [F-04](#f-04), [F-05](#f-05) | Timing table; compare with the numbers in those findings |
| `asmcheck` | §5 item 2, [F-04](#f-04) | Disassemble as in phase 3 |
| `corpus` | §5 item 7 | Corpus replay, no panic, 0 non-canonical |

```bash
cd audit/probe
cargo run --release --bin forge          # one finding per run; debug build gives the same result
cargo run --release --bin stream         # add --heavy for the 64 MiB compressed case
```

The crate deliberately does **not** depend on the library's internals: if a fix changes a public
signature, the probe stops compiling, which is itself a signal to update this document.

---

# Appendix C — run log

Recorded 2026-11-20, macOS aarch64, `rustc 1.100.0`, offline against the local registry cache.

| Step | Result |
|---|---|
| `cargo build --all-features` | PASS |
| `cargo test --all-features` | PASS — 163 unit/integration + 33 doc-tests |
| `cargo test --no-default-features` | PASS |
| 15-combination feature matrix | PASS (all) |
| `--target wasm32-unknown-unknown --no-default-features` | PASS |
| `--target wasm32-unknown-unknown --features "hsss,refresh,serde"` | PASS |
| `cargo +1.88.0 check --all-features` | PASS (MSRV honest) |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| pedantic + unwrap/index/arith/cast lints | 299 lib + 530 test warnings; no secret-dependent hit |
| `cargo doc` with `-D warnings` | FAIL in `SUMMARY.md` (`env: warnings: No such file or directory` runner bug — see [F-28](#f-28)) |
| `cargo fmt --check` | FAIL (`tests/wire_format_test.rs:195` — see [F-19](#f-19)) |
| `cargo audit --no-fetch` | PASS — 1550 advisories, 134 crates, none affecting this tree |
| `cargo deny check` | NOT RUN — sandbox read-only on `~/.cargo/advisory-dbs` |
| `cargo geiger --all-features` | PASS — 0 unsafe in `shamir_share`; `zstd-sys` is C |
| `miri test --lib finite_field` | PASS — 11 tests, no UB |
| `package --list` | 39 files (see [F-10](#f-10)) |
| `publish --dry-run` | NOT RUN — needs network |
| `fuzz_share_from_bytes` 46 s | 16,086,443 execs, no crash |
| `fuzz_reconstruct` 41 s | 932,075 execs, no crash |
| `fuzz_reconstruct_stream` 41 s | 75,089 execs, no crash |
| `fuzz_hsss` | not run this session |
| `llvm-cov` | tests pass under instrumentation; report generation failed |
| `probe::gf` | 0 mismatches / 0 mismatches / 0 violations |
| `probe::forge` | **FORGERY SUCCEEDED** ([F-01](#f-01) open) |
| `probe::stream` | **8 of 8 bytes lost, `Ok(())`** ([F-02](#f-02) open); debug build panics at `shamir.rs:708` |
| `probe::stream --heavy` | roundtrip = true — 67,110,458 < 67,371,264 |
| `probe::authkey` | **key had no effect** ([F-03](#f-03) open) |
| `probe::api` | 655/752 mutations accepted, 0 non-canonical; `from_bytes(len=0 payload) = Ok(0)` ([F-07](#f-07) open) |
| `probe::refresh` | A rejected, B ok, C rejected, D undetectable, E no epoch |
| `probe::perf` | n=255/k=128/64 KiB: split 31,266 ms, reconstruct(all) 14,901 ms |
| `probe::asmcheck` | multiply has 16 `subtle::black_box` calls, 0 conditional branches ([F-04](#f-04) open) |
| `probe::corpus` | 133 stream inputs no panic; 15 accepted, 0 non-canonical; 306 mutations no panic |

Re-run `../shamir_share_audit/run_audit.sh` (once [F-28](#f-28) path fixes land) to regenerate this
table into `../shamir_share_audit/results/SUMMARY.md`, with an automatic `OPEN`/`FIXED` verdict per
finding in `../shamir_share_audit/results/FINDINGS.md`.
