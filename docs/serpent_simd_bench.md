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

# Serpent-256 SIMD Benchmark Results

4-wide inter-block SIMD (`encryptChunk_simd`): each v128 register lane holds
word `w` from a different block (counters ctr, ctr+1, ctr+2, ctr+3). Same
parallelism model as ChaCha20 CTR-4.

## Environment

- **Date:** 2026-03-27
- **Hardware:** Apple Silicon (arm64)
- **Browsers:** Playwright — Chromium, Firefox, WebKit
- **Benchmark:** `test/e2e/serpent_simd_bench.spec.ts`
  — 50–100 warmup iterations, then 200–2000 timed trials per chunk size
  — Key: 32-byte sequential (0x00..0x1f), Nonce: 16-byte sequential (0x00..0x0f)

## Browser throughput — single thread

### Chromium (V8)

| Chunk size | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|------------|---------------|-------------|---------|
| 65,536 B   | 15.0          | 38.9        | **2.59×** |
| 16,384 B   | 15.2          | 39.1        | **2.58×** |
|  1,024 B   | 14.7          | 37.6        | **2.55×** |

### Firefox (SpiderMonkey)

| Chunk size | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|------------|---------------|-------------|---------|
| 65,536 B   | 7.1           | 15.8        | **2.22×** |
| 16,384 B   | 7.4           | 15.7        | **2.11×** |
|  1,024 B   | 7.0           | 14.8        | **2.12×** |

### WebKit (JSC)

| Chunk size | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|------------|---------------|-------------|---------|
| 65,536 B   | 33.7          | 43.5        | **1.29×** |
| 16,384 B   | 34.7          | 43.6        | **1.26×** |
|  1,024 B   | 32.5          | 40.2        | **1.24×** |

## Analysis

**Inter-block SIMD delivers 1.2–2.6× gains across all tested runtimes.**

Chromium (V8) and Firefox (SpiderMonkey) see the largest gains (2.1–2.6×).
WebKit (JSC) shows a smaller but consistent gain (1.24–1.29×) — JSC's scalar
JIT is already more aggressive for this workload, leaving less headroom for SIMD.

Firefox absolute throughput is lower (~7 MB/s scalar vs ~15–35 MB/s on V8/JSC)
for the same reason as ChaCha20: SpiderMonkey does not apply the same
alias-analysis-based register promotion that V8/JSC use for fixed-address loads.
The **speedup ratio is consistent (2.11–2.22×)** despite lower absolute numbers.

The 1,024-byte chunk size (Serpent CTR-4 SIMD threshold is 64 bytes — a single
4-block group is 64 bytes) shows speedup essentially equal to large chunks.
Unlike ChaCha20 where the minimum SIMD threshold (256 bytes) affects small-chunk
ratios, Serpent's smaller block size means SIMD benefits appear at much smaller
inputs.

## CBC decrypt — single thread

CBC encryption is not parallelizable (sequential dependency:
`CT[n] = encrypt(PT[n] XOR CT[n-1])`). Only the decrypt path benefits from SIMD.

CBC decrypt SIMD benchmarks are not yet measured. Use the above CTR numbers as a
proxy — the SIMD model is identical (4-wide inter-block parallelism on independent
blocks), and CBC decrypt is structurally identical to CTR encryption for the
purpose of SIMD throughput.

---

> **Cross-references:**
> - [asm_serpent.md](./asm_serpent.md) — WASM API reference including SIMD exports
> - [serpent.md](./serpent.md) — TypeScript wrapper classes
> - [chacha_simd_bench.md](./chacha_simd_bench.md) — ChaCha20 SIMD benchmark (same inter-block model)
