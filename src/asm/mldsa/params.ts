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
// src/asm/mldsa/params.ts
//
// ML-DSA, ring-level mathematical constants.
// FIPS 204, Module-Lattice-Based Digital Signature Standard.
//
// Parameter-set values (k, ℓ, η, γ₁, γ₂, τ, β, ω) are NOT defined here,
// they live in the TypeScript layer (phase 4). This file holds only the
// constants common to all ML-DSA parameter sets.

// ── Ring parameters ─────────────────────────────────────────────────────────

/** Prime modulus q = 2²³ − 2¹³ + 1 = 8380417 (FIPS 204 §2.3). */
export const Q: i32 = 8380417;

/** Polynomial degree n = 256 (FIPS 204 §2.3, ring R_q = Z_q[X]/(X²⁵⁶ + 1)). */
export const N: i32 = 256;

/** 512-th root of unity ζ = 1753 ∈ Z_q (FIPS 204 §2.5). */
export const ZETA: i32 = 1753;

/** Low-bit drop count d = 13, common to all parameter sets (FIPS 204 §4 Table 1). */
export const D: i32 = 13;

// ── Montgomery reduction constants (FIPS 204 Appendix A) ────────────────────

/**
 * QINV = q⁻¹ mod 2³² = 58728449 (FIPS 204 Algorithm 49 line 1).
 * Used in MontgomeryReduce: t ← ((a mod 2³²) · QINV) mod 2³².
 *
 * Note the Montgomery factor for ML-DSA is R = 2³² (FIPS 204 Appendix A),
 * unlike Kyber where R = 2¹⁶. The wider R is required because q ≈ 2²³
 * does not fit in i16.
 */
export const QINV: i32 = 58728449;

/**
 * 256⁻¹ · 2³² mod q (centered), Montgomery form of the NTT⁻¹ scaling factor f.
 *
 * FIPS 204 Algorithm 42 line 21 sets f ← 8347681 = 256⁻¹ mod q (regular form).
 * Stored in Montgomery form so that MontgomeryReduce(F_MONT · w[j])
 * yields f · w[j] in regular form, matching the algorithm's intent.
 *
 * Derivation: 256 · 8347681 ≡ 1 (mod q), so 8347681 · 2³² ≡ 2²⁴ (mod q).
 * 2²⁴ mod q = 16777216 − 2·8380417 = 16382. Centered (positive, < q/2): 16382.
 */
export const F_MONT: i32 = 16382;

// ── Barrett reduction constants ─────────────────────────────────────────────

/**
 * Barrett multiplier v = 1049603.
 * Verified: |v·a / 2⁴³ − a/q| < 0.5 for all |a| ≤ 2³¹, so the post-
 * correction (one conditional ±q) always yields the correct centered residue
 * (FIPS 204 §2.3, mod± q).
 *
 * Derivation. 2⁴³ / q = 8,796,093,022,208 / 8,380,417 = 1049600.876…, so
 * round(2⁴³/q) = 1049601. The stored value 1049603 is a deliberate safe
 * overestimate. Error bound:
 *     |v·a/2⁴³ − a/q| = (|a|/2⁴³) · |v − 2⁴³/q|
 * For |a| ≤ 2³¹, the < 0.5 correctness target needs |v − 2⁴³/q| < 2¹¹ = 2048.
 * Actual: |v − 2⁴³/q| ≈ 2.124, roughly 10 bits of slack.
 *
 * The shift k=43 was picked so that v·a stays within i64 for a ∈ [−2³¹, 2³¹)
 * (worst case |v·a| < 2³¹·2²¹ = 2⁵²).
 */
export const BARRETT_V: i32     = 1049603;
export const BARRETT_SHIFT: i32 = 43;

// ── Helpers ─────────────────────────────────────────────────────────────────

/** (q − 1) / 2 = 4190208, the centered residue boundary (FIPS 204 §2.3). */
export const HALF_Q: i32 = 4190208;
