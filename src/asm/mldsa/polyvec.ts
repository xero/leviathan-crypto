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
// src/asm/mldsa/polyvec.ts
//
// ML-DSA, k-/ℓ-iterated polyvec operations.
// FIPS 204 §7.6 (AddVectorNTT, ScalarVectorNTT, MatrixVectorNTT) plus the
// rounding/hint wrappers needed for Sign_internal and Verify_internal.
//
// Each polynomial in a polyvec occupies POLY_BYTES = 1024 bytes (256 × i32).
// `len` is the runtime k or ℓ supplied by the orchestration layer.

import { N } from './params';
import { POLY_SLOT_7 } from './buffers';
import {
	poly_pointwise_montgomery_simd as poly_pointwise_montgomery,
	poly_add_simd  as poly_add,
	poly_sub_simd  as poly_sub,
	poly_reduce_simd as poly_reduce,
	poly_caddq_simd  as poly_caddq,
} from './poly_simd';
import { poly_freeze, poly_chknorm, poly_tomont } from './poly';
import { ntt_simd, invntt_simd } from './ntt_simd';
import { power2round, decompose, highbits, lowbits, make_hint, use_hint } from './rounding';

const POLY_BYTES: i32 = N * 4;  // 1024

// ── Element-wise vector arithmetic ──────────────────────────────────────────

export function polyvec_add(rOff: i32, aOff: i32, bOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		poly_add(rOff + i * POLY_BYTES, aOff + i * POLY_BYTES, bOff + i * POLY_BYTES);
	}
}

export function polyvec_sub(rOff: i32, aOff: i32, bOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		poly_sub(rOff + i * POLY_BYTES, aOff + i * POLY_BYTES, bOff + i * POLY_BYTES);
	}
}

export function polyvec_reduce(pvOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		poly_reduce(pvOff + i * POLY_BYTES);
	}
}

export function polyvec_caddq(pvOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		poly_caddq(pvOff + i * POLY_BYTES);
	}
}

export function polyvec_freeze(pvOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		poly_freeze(pvOff + i * POLY_BYTES);
	}
}

/** Convert each coefficient of every polynomial to Montgomery form
 *  (p[i] ← p[i]·R mod q, R = 2³²). Used by keygen between NTT(s₁) and the
 *  matrix-vector product: tomont turns the regular-form ŝ₁ into the
 *  Montgomery factor that the pointwise kernel expects, so that the
 *  internal R⁻¹ leaves the result Â·ŝ₁ in regular form. */
export function polyvec_tomont(pvOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		poly_tomont(pvOff + i * POLY_BYTES);
	}
}

// ── NTT, apply forward / inverse NTT to each entry ─────────────────────────

export function polyvec_ntt(pvOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		ntt_simd(pvOff + i * POLY_BYTES);
	}
}

export function polyvec_invntt(pvOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		invntt_simd(pvOff + i * POLY_BYTES);
	}
}

// ── Pointwise / inner-product / matrix-vector multiplication in T_q ─────────
//
// FIPS 204 Algorithm 45 lifted to vector and matrix forms (Algs 46-48).

/** Coefficient-wise c[i] = a[i] ◦ b[i] across `len` polynomials. */
export function polyvec_pointwise_montgomery(rOff: i32, aOff: i32, bOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		poly_pointwise_montgomery(
			rOff + i * POLY_BYTES,
			aOff + i * POLY_BYTES,
			bOff + i * POLY_BYTES,
		);
	}
}

/**
 * Inner product Σ a[i] ◦ b[i] in T_q. Output is a single polynomial.
 * FIPS 204 Algorithm 46 (AddVectorNTT) composed with Algorithm 45.
 *
 * Uses POLY_SLOT_7 as scratch for each multiply step, so callers must NOT
 * pass POLY_SLOT_7 as r, a, or b. (The inner product is only ever called
 * with polyvec slots and named output polys, so this is safe in practice.)
 */
export function polyvec_pointwise_acc_montgomery(rPolyOff: i32, aPvOff: i32, bPvOff: i32, len: i32): void {
	// First product seeds the accumulator.
	poly_pointwise_montgomery(rPolyOff, aPvOff, bPvOff);
	// Add subsequent products into the accumulator via a scratch poly.
	for (let i: i32 = 1; i < len; i++) {
		poly_pointwise_montgomery(
			POLY_SLOT_7,
			aPvOff + i * POLY_BYTES,
			bPvOff + i * POLY_BYTES,
		);
		poly_add(rPolyOff, rPolyOff, POLY_SLOT_7);
	}
}

/**
 * Â · v where Â is k × ℓ polynomials and v is length-ℓ. Output is length-k.
 * FIPS 204 Algorithm 48 (MatrixVectorNTT). Matrix is row-major: row i,
 * column j sits at matOff + (i*l + j) * POLY_BYTES.
 */
export function polyvec_matrix_pointwise_montgomery(rPvOff: i32, matOff: i32, vPvOff: i32, k: i32, l: i32): void {
	for (let i: i32 = 0; i < k; i++) {
		polyvec_pointwise_acc_montgomery(
			rPvOff + i * POLY_BYTES,
			matOff + i * l * POLY_BYTES,
			vPvOff,
			l,
		);
	}
}

// ── Norm check ──────────────────────────────────────────────────────────────

/**
 * Returns 1 iff some coefficient across the polyvec exceeds `bound` in
 * absolute value, else 0. Caller must call polyvec_reduce first so that
 * coefficients are in centered residues. Same CT posture as poly_chknorm.
 */
export function polyvec_chknorm(pvOff: i32, bound: i32, len: i32): i32 {
	for (let i: i32 = 0; i < len; i++) {
		if (poly_chknorm(pvOff + i * POLY_BYTES, bound) != 0) return 1;
	}
	return 0;
}

// ── Rounding wrappers, apply per-polynomial rounding kernels ───────────────

export function polyvec_power2round(r1pvOff: i32, r0pvOff: i32, aPvOff: i32, len: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		power2round(
			r1pvOff + i * POLY_BYTES,
			r0pvOff + i * POLY_BYTES,
			aPvOff  + i * POLY_BYTES,
		);
	}
}

export function polyvec_decompose(r1pvOff: i32, r0pvOff: i32, aPvOff: i32, len: i32, gamma2: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		decompose(
			r1pvOff + i * POLY_BYTES,
			r0pvOff + i * POLY_BYTES,
			aPvOff  + i * POLY_BYTES,
			gamma2,
		);
	}
}

export function polyvec_highbits(rPvOff: i32, aPvOff: i32, len: i32, gamma2: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		highbits(rPvOff + i * POLY_BYTES, aPvOff + i * POLY_BYTES, gamma2);
	}
}

export function polyvec_lowbits(rPvOff: i32, aPvOff: i32, len: i32, gamma2: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		lowbits(rPvOff + i * POLY_BYTES, aPvOff + i * POLY_BYTES, gamma2);
	}
}

/**
 * MakeHint per polynomial, plus aggregate popcount over the resulting hint
 * polyvec. The popcount feeds the `popcount(h) > ω` reject check at Alg 7
 * line 28.
 */
export function polyvec_make_hint(hPvOff: i32, zPvOff: i32, rPvOff: i32, len: i32, gamma2: i32): i32 {
	let pop: i32 = 0;
	for (let i: i32 = 0; i < len; i++) {
		const polyOff: i32 = hPvOff + i * POLY_BYTES;
		make_hint(polyOff, zPvOff + i * POLY_BYTES, rPvOff + i * POLY_BYTES, gamma2);
		// Accumulate popcount over this hint polynomial.
		for (let j: i32 = 0; j < N; j++) {
			pop += load<i32>(polyOff + j * 4);
		}
	}
	return pop;
}

export function polyvec_use_hint(rPvOff: i32, hPvOff: i32, aPvOff: i32, len: i32, gamma2: i32): void {
	for (let i: i32 = 0; i < len; i++) {
		use_hint(
			rPvOff + i * POLY_BYTES,
			hPvOff + i * POLY_BYTES,
			aPvOff + i * POLY_BYTES,
			gamma2,
		);
	}
}
