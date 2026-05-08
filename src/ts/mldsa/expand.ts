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
// src/ts/mldsa/expand.ts
//
// FIPS 204 Algorithms 32 (ExpandA), 33 (ExpandS), 34 (ExpandMask) —
// pseudorandom expansion of seeds into the matrix Â (public), the noise
// polyvecs s₁/s₂ (secret, time domain), and the masking polyvec y (per
// signing iteration, time domain).
//
// ExpandA samples Â directly in NTT domain (RejNTTPoly produces NTT
// coefficients). ExpandS / ExpandMask sample in time domain; the
// orchestration layer applies polyvec_ntt where needed for the matrix-
// vector products in Sign_internal and Verify_internal.

import type { MlDsaExports, Sha3Exports } from './types.js';
import type { MlDsaParams } from './params.js';
import { wipe } from '../utils.js';
import { shake128Squeezer, shake256Squeezer, shake256HashConcat } from './sha3-helpers.js';

const POLY_BYTES = 1024;  // 256 × i32

/**
 * ExpandA — FIPS 204 Algorithm 32.
 *
 * For (i, j) ∈ [0, k) × [0, ℓ):
 *   s ← ρ ‖ IntegerToBytes(j, 1) ‖ IntegerToBytes(i, 1)
 *   Â[i, j] ← RejNTTPoly(SHAKE128(s))
 *
 * Output is row-major: Â[i, j] sits at matrixOff + (i·ℓ + j) · 1024.
 * This matches `polyvec_matrix_pointwise_montgomery`'s row-stride contract.
 *
 * ρ is the public seed; the rej_ntt_poly inner loop has data-dependent
 * branching but only on ρ-derived bytes (public), so no CT concern.
 */
export function expandA(
	mx: MlDsaExports,
	sx: Sha3Exports,
	params: MlDsaParams,
	rho: Uint8Array,
	matrixOff: number,
): void {
	const { k, l } = params;
	const xofPrfOff = mx.getXofPrfOffset();
	const mlMem = new Uint8Array(mx.memory.buffer);

	// XOF input: ρ(32) ‖ jByte ‖ iByte (FIPS 204 §7.3 Alg 32 line 4)
	const xofSeed = new Uint8Array(34);
	xofSeed.set(rho, 0);

	for (let i = 0; i < k; i++) {
		for (let j = 0; j < l; j++) {
			xofSeed[32] = j;
			xofSeed[33] = i;
			const sq = shake128Squeezer(sx, xofSeed);
			const polyOff = matrixOff + (i * l + j) * POLY_BYTES;
			let ctr = 0;
			while (ctr < 256) {
				const block = sq.squeeze();
				mlMem.set(block, xofPrfOff);
				ctr += mx.rej_ntt_poly(polyOff, ctr, xofPrfOff, sq.rate);
			}
		}
	}
}

/**
 * ExpandS — FIPS 204 Algorithm 33.
 *
 * For r ∈ [0, ℓ): s₁[r] ← RejBoundedPoly(SHAKE256(ρ' ‖ IntegerToBytes(r, 2)))
 * For r ∈ [0, k): s₂[r] ← RejBoundedPoly(SHAKE256(ρ' ‖ IntegerToBytes(r+ℓ, 2)))
 *
 * Note the index is 2 bytes (little-endian per FIPS 204 §7.1 Alg 11) — kyber
 * uses 1 byte because k ≤ 4, but ML-DSA's max index is k+ℓ-1 = 14 (still
 * ≤ 255 in practice but the spec mandates 2 bytes).
 *
 * ρ' is secret. The local seed scratch is wiped on exit; the caller is
 * responsible for the WASM-resident ρ' source buffer.
 */
export function expandS(
	mx: MlDsaExports,
	sx: Sha3Exports,
	params: MlDsaParams,
	rhoPrime: Uint8Array,
	s1Off: number,
	s2Off: number,
): void {
	const { k, l, eta } = params;
	const xofPrfOff = mx.getXofPrfOffset();
	const mlMem = new Uint8Array(mx.memory.buffer);

	// PRF input: ρ'(64) ‖ idx_lo ‖ idx_hi
	const seed = new Uint8Array(66);
	seed.set(rhoPrime, 0);

	try {
		// s₁: ℓ polynomials at indices 0..ℓ-1
		for (let r = 0; r < l; r++) {
			seed[64] =  r        & 0xFF;
			seed[65] = (r >>> 8) & 0xFF;
			const sq = shake256Squeezer(sx, seed);
			const off = s1Off + r * POLY_BYTES;
			let ctr = 0;
			while (ctr < 256) {
				const block = sq.squeeze();
				mlMem.set(block, xofPrfOff);
				ctr += mx.rej_bounded_poly(off, ctr, xofPrfOff, sq.rate, eta);
			}
		}
		// s₂: k polynomials at indices ℓ..ℓ+k-1
		for (let r = 0; r < k; r++) {
			const idx = r + l;
			seed[64] =  idx        & 0xFF;
			seed[65] = (idx >>> 8) & 0xFF;
			const sq = shake256Squeezer(sx, seed);
			const off = s2Off + r * POLY_BYTES;
			let ctr = 0;
			while (ctr < 256) {
				const block = sq.squeeze();
				mlMem.set(block, xofPrfOff);
				ctr += mx.rej_bounded_poly(off, ctr, xofPrfOff, sq.rate, eta);
			}
		}
	} finally {
		// Local seed buffer carries ρ' for the duration of this call; wipe
		// even on early throw so it never persists in TS heap.
		wipe(seed);
	}
}

// Bitlen helper — bitlen(n) for n > 0 is floor(log2(n)) + 1, used to size
// the BitUnpack output width inside ExpandMask. Identical to the helper in
// keygen.ts; keeping a private copy here avoids cross-importing the keygen
// module just for one tiny utility.
function bitlen(n: number): number {
	let b = 0; let x = n;
	while (x > 0) {
		b++; x >>>= 1;
	}
	return b;
}

/**
 * ExpandMask — FIPS 204 Algorithm 34.
 *
 * For r ∈ [0, ℓ):
 *   v ← SHAKE256(ρ'' ‖ IntegerToBytes(κ + r, 2),  32·c)
 *   y[r] ← BitUnpack(v, γ₁ − 1, γ₁)
 *
 * where c = 1 + bitlen(γ₁ − 1) is the per-coefficient byte width
 * (18 when γ₁ = 2¹⁷, 20 when γ₁ = 2¹⁹). Output coefficients land in
 * [-(γ₁ − 1), γ₁]; bit_unpack(a=γ₁−1, b=γ₁) covers exactly that range.
 *
 * y is produced in time domain at `yPvOff`. Sign_internal applies
 * polyvec_ntt to y before the matrix-vector product Â · NTT(y).
 *
 * ρ'' is secret (derived from K ‖ rnd ‖ μ). This function uses one
 * one-shot SHAKE256 per polynomial (caller's full input is ≤ 168 B,
 * fits in a single shake256HashConcat call); the SHAKE state is reset
 * each iteration via shake256Init inside the helper, so no state
 * carries between r values. The squeeze output lands in a TS-side
 * buffer and is set into the WASM XOF/PRF region only long enough for
 * bit_unpack to consume it.
 */
export function expandMask(
	mx: MlDsaExports,
	sx: Sha3Exports,
	params: MlDsaParams,
	rhoPrimePrime: Uint8Array,
	kappa: number,
	yPvOff: number,
): void {
	const { l, gamma1 } = params;
	const c        = 1 + bitlen(gamma1 - 1);    // 18 or 20
	const polyBytesV = 32 * c;                  // 576 or 640
	const xofPrfOff = mx.getXofPrfOffset();
	const mlMem    = new Uint8Array(mx.memory.buffer);

	const idxBytes = new Uint8Array(2);

	for (let r = 0; r < l; r++) {
		const n = kappa + r;
		idxBytes[0] =  n        & 0xFF;
		idxBytes[1] = (n >>> 8) & 0xFF;

		// SHAKE256(ρ'' ‖ idx, 32·c). For γ₁ ≤ 2¹⁹ the output never exceeds
		// 640 bytes — well within the 8192-byte XOF region.
		const v = shake256HashConcat(sx, [rhoPrimePrime, idxBytes], polyBytesV);
		try {
			mlMem.set(v, xofPrfOff);
			// bit_unpack(a=γ₁-1, b=γ₁): bitlen(a+b) = bitlen(2γ₁-1) = c.
			// Decodes to coefficients in [-(γ₁-1), γ₁] — Alg 34 / Alg 19.
			mx.bit_unpack(yPvOff + r * 1024, xofPrfOff, gamma1 - 1, gamma1);
		} finally {
			wipe(v);
		}
	}
}
