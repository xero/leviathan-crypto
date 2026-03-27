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

## Environment
- Hardware: [to be measured]
- Node/Bun version: [to be measured]
- Browsers: Chromium, Firefox, WebKit

## Single-thread throughput

| Runtime            | Scalar (MB/s) | SIMD (MB/s) | Speedup |
|--------------------|---------------|-------------|---------|
| Bun (V8)           | pending       | pending     | pending |
| Node.js (V8)       | pending       | pending     | pending |
| Chromium (V8)      | pending       | pending     | pending |
| Firefox (SpiderMonkey) | pending   | pending     | pending |
| WebKit (JSC)       | pending       | pending     | pending |

## 4-worker pool with SIMD

| Runtime            | Scalar pool (MB/s) | SIMD pool (MB/s) | Speedup |
|--------------------|---------------------|-------------------|---------|
| Bun (V8)           | pending             | pending           | pending |
| Chromium (V8)      | pending             | pending           | pending |
| Firefox (SpiderMonkey) | pending         | pending           | pending |
| WebKit (JSC)       | pending             | pending           | pending |

## CBC decrypt — single-thread throughput

CBC encryption is not parallelizable (sequential dependency: `CT[n] = encrypt(PT[n] XOR CT[n-1])`).
Only the decrypt path benefits from SIMD. CBC encrypt throughput is unchanged.

| Runtime            | Scalar decrypt (MB/s) | SIMD decrypt (MB/s) | Speedup |
|--------------------|-----------------------|---------------------|---------|
| Bun (V8)           | pending               | pending             | pending |
| Node.js (V8)       | pending               | pending             | pending |
| Chromium (V8)      | pending               | pending             | pending |
| Firefox (SpiderMonkey) | pending           | pending             | pending |
| WebKit (JSC)       | pending               | pending             | pending |

**CBC encrypt throughput**: unchanged (scalar only, no SIMD path exists).

## Notes

Benchmark results require `bench/serpent_simd_bench.ts` to be implemented and
run on each target platform. The SIMD path is selected automatically via
`hasSIMD()` runtime detection in the TypeScript layer.

Firefox (SpiderMonkey) scalar throughput is historically lower (~7.3 MB/s vs
~34 MB/s on V8/JSC) due to different alias analysis. SIMD should recover
Firefox throughput since it does not rely on fixed-address promotion -- but this
requires explicit measurement before shipping.
