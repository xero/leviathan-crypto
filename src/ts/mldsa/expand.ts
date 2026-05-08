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
// FIPS 204 Algorithms 32 (ExpandA) and 33 (ExpandS) — pseudorandom
// expansion of ρ to the matrix Â and ρ' to the noise polyvecs s₁, s₂.
//
// ExpandA samples Â directly in NTT domain (RejNTTPoly produces NTT
// coefficients). ExpandS samples in time domain; the orchestration layer
// applies polyvec_ntt to s₁ when needed for the matrix-vector product.

import type { MlDsaExports, Sha3Exports } from './types.js';
import type { MlDsaParams } from './params.js';
import { wipe } from '../utils.js';
import { shake128Squeezer, shake256Squeezer } from './sha3-helpers.js';

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
