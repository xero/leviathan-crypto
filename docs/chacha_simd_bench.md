<!--
                 ▄▄▄▄▄▄▄▄▄▄
          ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
       ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
     ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ ▒ ▒ █
    ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
    ████████      ███▀▀     ████▀  █▀ █▀       Leviathan Crypto Library
    ███████▌    ▀██▀         ███
     ███████   ▀███           ▀██ ▀█▄      Repository & Mirror:
      ▀██████   ▄▄██            ▀▀  ██▄    github.com/xero/leviathan-crypto
        ▀█████▄   ▄██▄             ▄▀▄▀    unpkg.com/leviathan-crypto
           ▀████▄   ▄██▄
             ▐████   ▐███                  Author: xero (https://x-e.ro)
      ▄▄██████████    ▐███         ▄▄      License: MIT
   ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
 ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
  ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
 ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
 █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
  ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
                          ▀█████▀▀
-->

# ChaCha20 SIMD 4-Wide Benchmark Results

4-wide inter-block SIMD (`chachaEncryptChunk_simd`): each v128 register lane
holds word `w` from a different block (counters ctr, ctr+1, ctr+2, ctr+3).
This is the same parallelism model used in Serpent CTR-4.

## Environment

- **Date:** 2026-03-27
- **Hardware:** Apple Silicon (arm64)
- **Bun version:** measured via `bun run test`
- **Browsers:** Playwright — Chromium, Firefox, WebKit
- **Benchmark:** `test/e2e/chacha20_simd_bench.spec.ts`
  — 50 warmup iterations, then 200–5000 timed trials per chunk size
  — Key: RFC 8439 §2.4.2 all-zero-sequential, Nonce: SWEEP_NONCE

## Browser throughput — single thread

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

## Bun (V8-based) — unit test benchmark

Measured via extended benchmark in `test/unit/chacha20/chacha20_simd_4x_gate.test.ts`
(50 warmup, 200 trials):

| Chunk size | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|------------|---------------|-------------|---------|
| 65,536 B   | ~310–330      | ~970–1030   | **~3.11×** |
| 16,384 B   | ~310–330      | ~980–1050   | **~3.17×** |

## Analysis

**Inter-block SIMD delivers 2–3× gains across all tested runtimes.**

Firefox (SpiderMonkey) has significantly lower absolute throughput (~22–60 MB/s
vs ~250–1365 MB/s on V8/JSC) for both scalar and SIMD paths. This is a known
SpiderMonkey characteristic for tight WASM inner loops with many fixed-address
loads — SpiderMonkey does not perform the same alias-analysis-based register
promotion that V8 applies. Despite the lower absolute numbers, the **speedup
ratio is consistent (2.38–2.43×)** — SpiderMonkey benefits from SIMD proportionally.

**Why SIMD recovers Firefox throughput relative to scalar:**
The scalar path relies on fixed-address loads to the state matrix
(`CHACHA_STATE_OFFSET`). V8/JSC recognise these as loop-invariant and
register-promote them. SpiderMonkey does not, paying memory traffic on every
iteration. The SIMD path loads all 16 state words once into v128 locals before
the round loop, making the loop-invariant promotion explicit in the code — so
SpiderMonkey sees the same working set as V8/JSC.

**256-byte inputs** (minimum SIMD threshold — exactly one 4-block group) show a
smaller gain on WebKit (1.67×) and a larger gain on Firefox (2.38×). At this
size the loop-body overhead is proportionally larger; the Firefox advantage is
explained by the v128 local benefit described above.

## Negative result: intra-block SIMD (documented)

A prior attempt at intra-block SIMD (one block using v128 with shuffles) measured
**0.65–0.74× scalar** across all runtimes. Root causes:
- No `i32x4.rotl` in WASM SIMD — each rotation requires 3 v128 ops vs 1 scalar
- 6 cross-lane shuffles per double round for the diagonal arrangement
- V8/JSC already register-promote fixed-address scalar loads, removing the
  memory traffic advantage SIMD was supposed to provide

The intra-block implementation is preserved in `src/asm/chacha/chacha20_simd.ts`
(no longer exported) as a documented negative result.

---

> **Cross-references:**
> - [asm_chacha.md](./asm_chacha.md) — WASM API reference including SIMD exports
> - [chacha20.md](./chacha20.md) — TypeScript wrapper classes
> - [serpent_simd_bench.md](./serpent_simd_bench.md) — Serpent-256 SIMD benchmark (same inter-block model)
