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
// src/asm/slhdsa/params.ts
//
// SLH-DSA, approved parameter set table.
// FIPS 205, Stateless Hash-Based Digital Signature Standard, §11.1 Table 2.
//
// This file exports the numeric per-parameter-set constants only; derived
// constants (len_1, len_2, len, k, a, h, d, h') are computed inside the
// individual WOTS+ / FORS / XMSS / hypertree modules via per-set lookup.
// Current scope is the SHAKE-family fast variants (128f / 192f / 256f);
// the slow variants (128s/192s/256s) and the SHA-2 family are out of scope.
//
//   ┌───────┬────┬────┬────┬────┬────┬────┬────┐
//   │ set   │ n  │ h  │ d  │ h' │ k  │ a  │ m  │
//   ├───────┼────┼────┼────┼────┼────┼────┼────┤
//   │ 128f  │ 16 │ 66 │ 22 │ 3  │ 33 │ 6  │ 34 │
//   │ 192f  │ 24 │ 66 │ 22 │ 3  │ 33 │ 8  │ 42 │
//   │ 256f  │ 32 │ 68 │ 17 │ 4  │ 35 │ 9  │ 49 │
//   └───────┴────┴────┴────┴────┴────┴────┴────┘
//
// m derivation per FIPS 205 §9 / §10.1: m = ⌈(h-h/d)/8⌉ + ⌈h/(8·d)⌉ + ⌈(k·a)/8⌉.
//   128f: ⌈63/8⌉ + ⌈3/8⌉ + ⌈198/8⌉ = 8 + 1 + 25 = 34
//   192f: ⌈63/8⌉ + ⌈3/8⌉ + ⌈264/8⌉ = 8 + 1 + 33 = 42
//   256f: ⌈64/8⌉ + ⌈4/8⌉ + ⌈315/8⌉ = 8 + 1 + 40 = 49
//
// Derived encoding sizes (FIPS 205 §11.2 + §9 sigEncode):
//
//   pkBytes  = 2·n
//   skBytes  = 4·n
//   sigBytes = (1 + k·(a+1) + h + d·len) · n
//              where, for w = 16, len_1 = ⌈8·n/4⌉, len_2 = 3, len = len_1+len_2
//
//                pkBytes  skBytes  sigBytes
//        128f       32      64     17088
//        192f       48      96     35664
//        256f       64     128     49856

// ── SLH-DSA-SHAKE-128f, FIPS 205 §11.1 Table 2 (security category 1, fast). ──

export const SLHDSA_128F_N:        i32 = 16;
export const SLHDSA_128F_H:        i32 = 66;
export const SLHDSA_128F_D:        i32 = 22;
export const SLHDSA_128F_HPRIME:   i32 = 3;
export const SLHDSA_128F_K:        i32 = 33;
export const SLHDSA_128F_A:        i32 = 6;
export const SLHDSA_128F_M:        i32 = 34;
export const SLHDSA_128F_PK_BYTES:  i32 = 32;
export const SLHDSA_128F_SK_BYTES:  i32 = 64;
export const SLHDSA_128F_SIG_BYTES: i32 = 17088;

// ── SLH-DSA-SHAKE-192f, FIPS 205 §11.1 Table 2 (security category 3, fast). ──

export const SLHDSA_192F_N:        i32 = 24;
export const SLHDSA_192F_H:        i32 = 66;
export const SLHDSA_192F_D:        i32 = 22;
export const SLHDSA_192F_HPRIME:   i32 = 3;
export const SLHDSA_192F_K:        i32 = 33;
export const SLHDSA_192F_A:        i32 = 8;
export const SLHDSA_192F_M:        i32 = 42;
export const SLHDSA_192F_PK_BYTES:  i32 = 48;
export const SLHDSA_192F_SK_BYTES:  i32 = 96;
export const SLHDSA_192F_SIG_BYTES: i32 = 35664;

// ── SLH-DSA-SHAKE-256f, FIPS 205 §11.1 Table 2 (security category 5, fast). ──

export const SLHDSA_256F_N:        i32 = 32;
export const SLHDSA_256F_H:        i32 = 68;
export const SLHDSA_256F_D:        i32 = 17;
export const SLHDSA_256F_HPRIME:   i32 = 4;
export const SLHDSA_256F_K:        i32 = 35;
export const SLHDSA_256F_A:        i32 = 9;
export const SLHDSA_256F_M:        i32 = 49;
export const SLHDSA_256F_PK_BYTES:  i32 = 64;
export const SLHDSA_256F_SK_BYTES:  i32 = 128;
export const SLHDSA_256F_SIG_BYTES: i32 = 49856;
