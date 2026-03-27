//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ ▒ ▒ █
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
//     ████████      ███▀▀     ████▀  █▀ █▀       Leviathan Crypto Library
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Repository & Mirror:
//       ▀██████   ▄▄██            ▀▀  ██▄    github.com/xero/leviathan-crypto
//         ▀█████▄   ▄██▄             ▄▀▄▀    unpkg.com/leviathan-crypto
//            ▀████▄   ▄██▄
//              ▐████   ▐███                  Author: xero (https://x-e.ro)
//       ▄▄██████████    ▐███         ▄▄      License: MIT
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
//
// src/asm/chacha/chacha20_simd.ts
//
// INTRA-BLOCK SIMD — DOCUMENTED NEGATIVE RESULT. NOT EXPORTED.
//
// This file is preserved as evidence of the intra-block SIMD approach,
// which was benchmarked and found to be 0.65–0.74× scalar across all
// chunk sizes and all tested runtimes. Root causes:
//
//   1. No i32x4.rotl in WASM SIMD — each rotation costs 3 instructions
//      (shl + shr_u + or) versus 1 scalar rotl instruction. ChaCha20
//      performs 8 rotations per quarter round × 8 QRs per double round
//      × 10 double rounds = 640 rotations. The 3× cost triples the
//      instruction count for the most frequent operation.
//
//   2. 6 shuffles per double round required for the diagonal rounds
//      to realign word indices across lanes. No scalar equivalent.
//
//   3. V8 already register-promotes the scalar fixed-address loads
//      (CHACHA_STATE_OFFSET words 0–15 are fixed, constant addresses),
//      eliminating the memory traffic advantage SIMD was supposed to
//      provide.
//
// The inter-block 4-wide approach (chacha20_simd_4x.ts) achieves 2–3×
// by processing 4 independent blocks simultaneously — same rotation
// cost per block but 4× the useful work per SIMD instruction, and zero
// shuffle overhead since diagonal alignment is not needed.
//
// Do not attempt to fix or re-enable this file. The root causes are
// fundamental to WASM SIMD and will not be resolved by tuning.
