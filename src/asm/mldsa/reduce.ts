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
// src/asm/mldsa/reduce.ts
//
// ML-DSA, modular arithmetic: Montgomery and Barrett reduction over Z_q.
// FIPS 204 Appendix A (Algorithm 49, MontgomeryReduce) and §2.3 (mod± q).

import { Q, QINV, BARRETT_V, BARRETT_SHIFT, HALF_Q } from './params';

/**
 * Montgomery reduction. FIPS 204 Algorithm 49, MontgomeryReduce(a).
 *
 * Input:  a ∈ [-2³¹·q, 2³¹·q]   (i64)
 * Output: r ≡ a·2⁻³² (mod q),   |r| < 2q   (per FIPS 204 Appendix A)
 *
 * Steps (FIPS 204 Algorithm 49):
 *   1. QINV ← 58728449                                     (= q⁻¹ mod 2³²)
 *   2. t ← ((a mod 2³²) · QINV) mod 2³²
 *   3. r ← (a − t·q) / 2³²
 *   4. return r
 *
 * The "(a mod 2³²) · QINV mod 2³²" sequence is realised in two's-complement
 * i32 arithmetic by ((i32)a) * QINV with implicit wrap, the low 32 bits of
 * the full product are the low 32 bits of (a · QINV) regardless of sign.
 * The subtraction a − t·q is then exact in i64 and the result is divisible
 * by 2³², so the arithmetic right shift by 32 yields the mathematical
 * quotient (signed, since t·q can exceed a in magnitude).
 */
@inline
export function montgomery_reduce(a: i64): i32 {
	// t = (i32)((a mod 2³²) · QINV), the low 32 bits of the full product
	const t: i32 = (<i32>a) * QINV;
	// r = (a − t·q) >> 32
	return <i32>((a - <i64>t * <i64>Q) >> 32);
}

/**
 * Barrett reduction (centered) over i32 inputs. Returns the unique r ≡ a (mod q)
 * with r ∈ [-(q-1)/2, (q-1)/2], i.e. a mod± q per FIPS 204 §2.3.
 *
 * Multiply-shift estimate of round(a / q):
 *   v = 1049603 ≈ 2⁴³ / q   (params.ts BARRETT_V, derivation cited there)
 *   t = (v · a + 2⁴²) >> 43 ≈ round(a / q)
 *
 * Branch-free post-correction handles boundary cases where the rounded t
 * leaves r just outside [-HALF_Q, HALF_Q]: a single conditional ±q absorbs
 * the at-most-one-off error. No data-dependent branching on coefficient
 * values, the corrections compile to mask-and-add, suitable for
 * constant-time use.
 */
@inline
export function barrett_reduce(a: i32): i32 {
	// t ≈ round(a / q)
	const t: i32 = <i32>((<i64>a * <i64>BARRETT_V + (<i64>1 << (BARRETT_SHIFT - 1))) >> BARRETT_SHIFT);
	let r: i32 = a - t * Q;
	// If r > HALF_Q, subtract q. (HALF_Q − r) < 0 ⇒ sign-bit-extend to 0xFFFFFFFF ⇒ AND with q.
	r -= ((HALF_Q - r) >> 31) & Q;
	// If r < -HALF_Q, add q. (r + HALF_Q) < 0 ⇒ sign-bit-extend to 0xFFFFFFFF ⇒ AND with q.
	r += ((r + HALF_Q) >> 31) & Q;
	return r;
}

/**
 * Multiplication in Z_q via Montgomery domain.
 * Returns (a · b · 2⁻³²) mod q with magnitude < 2q.
 *
 * Used inside NTT/NTT⁻¹ butterflies where one operand (the zeta) is stored
 * pre-multiplied by 2³² (Montgomery form). The 2⁻³² applied here cancels
 * that factor, yielding the regular-form product.
 */
@inline
export function fqmul(a: i32, b: i32): i32 {
	return montgomery_reduce(<i64>a * <i64>b);
}
