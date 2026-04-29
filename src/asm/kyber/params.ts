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
// src/asm/kyber/params.ts
//
// ML-KEM (Kyber) module — mathematical constants.
// FIPS 203 §4 — Module-Lattice-Based Key-Encapsulation Mechanism Standard.

// ── Ring parameters ──────────────────────────────────────────────────────────

/** Prime modulus q = 3329 (FIPS 203 §4) */
export const Q: i32 = 3329;

/** Polynomial degree n = 256 (FIPS 203 §4) */
export const N: i32 = 256;

/** Polynomial byte length: 256 × 12-bit coefficients packed = 384 bytes */
export const POLY_BYTES: i32 = 384;

// ── Montgomery reduction constants ───────────────────────────────────────────

/**
 * QINV = q^{-1} mod 2^16.
 * Verify: q * QINV ≡ 1 mod 2^16, i.e. (3329 * (-3327)) & 0xFFFF == 0x0001.
 */
export const QINV: i32 = -3327;

/**
 * MONT = 2^16 mod q = 2285, centered: 2285 - 3329 = -1044.
 * Used as the Montgomery factor R = 2^16. MONT = R mod q centered.
 */
export const MONT: i32 = -1044;

// ── Barrett reduction constants ───────────────────────────────────────────────

/**
 * Barrett multiplier v = ⌊(2^26 + q/2) / q⌋ = 20159.
 * Centered Barrett reduction returns values in [-(q-1)/2, (q-1)/2].
 */
export const BARRETT_V: i32 = 20159;

/** Barrett shift amount = 26. */
export const BARRETT_SHIFT: i32 = 26;

// ── Compression/decompression magic constants ─────────────────────────────────
// Division-free multiply-shift sequences replacing (x * 2^d + q/2) / q.
// Source: pq-crystals/kyber main branch ref/poly.c, ref/polyvec.c.

/** Compress to 4 bits (poly dv=4 / msg d=1): multiplier */
export const COMPRESS4_MUL: i32 = 80635;
/** Compress to 4 bits: addend */
export const COMPRESS4_ADD: i32 = 1665;
/** Compress to 4 bits: right-shift amount */
export const COMPRESS4_SHIFT: i32 = 28;

/** Compress to 5 bits (poly dv=5): multiplier */
export const COMPRESS5_MUL: i32 = 40318;
/** Compress to 5 bits: addend */
export const COMPRESS5_ADD: i32 = 1664;
/** Compress to 5 bits: right-shift amount */
export const COMPRESS5_SHIFT: i32 = 27;

/** Compress to 10 bits (polyvec du=10): multiplier (u64) */
export const COMPRESS10_MUL: i64 = 1290167;
/** Compress to 10 bits: addend */
export const COMPRESS10_ADD: i64 = 1665;
/** Compress to 10 bits: right-shift amount */
export const COMPRESS10_SHIFT: i32 = 32;

/** Compress to 11 bits (polyvec du=11): multiplier (u64) */
export const COMPRESS11_MUL: i64 = 645084;
/** Compress to 11 bits: addend */
export const COMPRESS11_ADD: i64 = 1664;
/** Compress to 11 bits: right-shift amount */
export const COMPRESS11_SHIFT: i32 = 31;

// ── Decompress rounding constants ─────────────────────────────────────────────

/** ⌈q/2⌉ = 1665, used in frommsg and as rounding in decompress_1 */
export const HALF_Q: i32 = 1665;
