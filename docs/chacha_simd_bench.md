<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### ChaCha20 SIMD 4-Wide Benchmark Results

Measured throughput results for the 4-wide inter-block SIMD implementation (`chachaEncryptChunk_simd`) across Chromium, Firefox, WebKit, and Bun. See [chacha_audit.md](./chacha_audit.md) for algorithm correctness verifications.

> ### Table of Contents
> - [Environment](#environment)
> - [Browser throughput](#browser-throughput)
> - [Bun](#bun)
> - [Analysis](#analysis)
> - [Negative result: intra-block SIMD](#negative-result-intra-block-simd)

---

## Environment

4-wide inter-block SIMD (`chachaEncryptChunk_simd`): each v128 register lane
holds word `w` from a different block (counters ctr, ctr+1, ctr+2, ctr+3).
This is the same parallelism model used in Serpent CTR-4.

- **Date:** 2026-03-27
- **Hardware:** Apple Silicon (arm64)
- **Bun version:** measured via `bun run test`
- **Browsers:** Playwright; Chromium, Firefox, WebKit
- **Benchmark:** `test/e2e/chacha20_simd_bench.spec.ts`
  - 50 warmup iterations, then 200–5000 timed trials per chunk size
  - Key: RFC 8439 §2.4.2 all-zero-sequential, Nonce: SWEEP_NONCE

---

## Browser throughput

Single thread.

### Chromium (V8)

| Chunk size | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|------------|---------------|-------------|---------|
| 65,536 B   | 506.1         | 1285.0      | **2.54×** |
| 16,384 B   | 512.0         | 1204.7      | **2.35×** |
| 256 B      | 328.2         | 711.1       | **2.17×** |

### Firefox (SpiderMonkey)

| Chunk size | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|------------|---------------|-------------|---------|
| 65,536 B   | 24.9          | 60.1        | **2.42×** |
| 16,384 B   | 23.4          | 56.9        | **2.43×** |
| 256 B      | 22.5          | 53.3        | **2.38×** |

### WebKit (JSC)

| Chunk size | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|------------|---------------|-------------|---------|
| 65,536 B   | 409.6         | 1191.6      | **2.91×** |
| 16,384 B   | 431.2         | 1365.3      | **3.17×** |
| 256 B      | 256.0         | 426.7       | **1.67×** |

---

## Bun

V8-based; measured via extended benchmark in `test/unit/chacha20/chacha20_simd_4x_gate.test.ts`
(50 warmup, 200 trials):

| Chunk size | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|------------|---------------|-------------|---------|
| 65,536 B   | ~310–330      | ~970–1030   | **~3.11×** |
| 16,384 B   | ~310–330      | ~980–1050   | **~3.17×** |

---

## Analysis

**Inter-block SIMD delivers 2–3× gains across all tested runtimes.**

Firefox (SpiderMonkey) has significantly lower absolute throughput (~22–60 MB/s
vs ~250–1365 MB/s on V8/JSC) for both scalar and SIMD paths. This is a known
SpiderMonkey characteristic for tight WASM inner loops with many fixed-address
loads; SpiderMonkey does not perform the same alias-analysis-based register
promotion that V8 applies. Despite the lower absolute numbers, the **speedup
ratio is consistent (2.38–2.43×)**; SpiderMonkey benefits from SIMD proportionally.

**SIMD recovers Firefox throughput relative to scalar.**
The scalar path relies on fixed-address loads to the state matrix
(`CHACHA_STATE_OFFSET`). V8/JSC recognise these as loop-invariant and
register-promote them. SpiderMonkey does not, paying memory traffic on every
iteration. The SIMD path loads all 16 state words once into v128 locals before
the round loop, making the loop-invariant promotion explicit in the code, so
SpiderMonkey sees the same working set as V8/JSC.

**256-byte inputs** (minimum SIMD threshold, exactly one 4-block group) show a
smaller gain on WebKit (1.67×) and a larger gain on Firefox (2.38×). At this
size the loop-body overhead is proportionally larger; the larger Firefox gain
follows from the v128 local benefit described above.

---

## Negative result: intra-block SIMD

A prior attempt at intra-block SIMD (one block using v128 with shuffles) was
benchmarked across 4 attempts and measured **0.60×, 0.72×, 0.71×, 0.70×
scalar**, uniformly slower across all runtimes. Root causes:

**1. No `i32x4.rotl` in WASM SIMD; 3× rotation cost.**

WASM SIMD has no rotate-left instruction for v128. Each rotation requires three
instructions: `i32x4.shl` + `i32x4.shr_u` + `v128.or`. ChaCha20 performs 8
rotations per quarter-round × 8 quarter-rounds per double-round × 10
double-rounds = 640 rotations total. The 3× cost triples the instruction count
for the most frequent operation in the entire cipher.

**2. 6 cross-lane shuffles per double-round.**

The diagonal quarter-rounds require word indices to be realigned across v128
lanes after the column rounds. Each realignment costs a `i8x16.shuffle`
instruction. Six shuffles per double-round with no scalar equivalent; pure
overhead.

**3. V8/JSC register-promotion neutralises the memory traffic advantage.**

The expected win from SIMD was eliminating repeated loads of the 16-word state
matrix (`CHACHA_STATE_OFFSET` words 0–15, fixed constant addresses). V8 and JSC
already apply register promotion to these fixed-address loads, keeping all 16
words in scalar registers across the round loop. SIMD was supposed to load them
once into v128 locals, but V8/JSC already do the equivalent. The advantage does
not materialise.

The inter-block 4-wide approach (`chacha20_simd_4x.ts`) avoids all three issues:
it processes 4 independent blocks simultaneously, so each SIMD instruction does
4× the useful work. Rotation cost per block is identical to scalar but 4 blocks
complete in the same time. No diagonal alignment is needed (independent blocks
require no shuffles). And the v128 local loads are genuinely beneficial since the
4-block working set does not fit in scalar registers.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [asm_chacha](./asm_chacha.md) | WASM API reference including SIMD exports |
| [chacha20](./chacha20.md) | TypeScript wrapper classes |
| [serpent_simd_bench](./serpent_simd_bench.md) | Serpent-256 SIMD benchmark (same inter-block model) |
| [chacha_audit.md](./chacha_audit.md) | XChaCha20-Poly1305 implementation audit |
