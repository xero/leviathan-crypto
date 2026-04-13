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
// src/asm/kyber/ntt_simd.ts
//
// ML-KEM (Kyber) — SIMD NTT and inverse NTT using WASM v128.
// FIPS 203 Algorithms 9 and 10, vectorized.
//
// SIMD path: layers with len >= 8 process 8 butterflies per v128 op.
// Scalar tail: layers with len < 8 (len = 4, 2) use fqmul/barrett_reduce
//   from reduce.ts — the same code as the scalar ntt.ts implementation.
//
// CT posture: all coefficient processing is unconditional. No data-dependent
// branching. The SIMD path has the same constant-time properties as scalar.

import { fqmul, barrett_reduce } from './reduce';
import { getZetasOffset } from './ntt';

// Local copies of reduction constants to avoid repeated imports.
// Q = 3329, QINV = -3327, BARRETT_V = 20159, BARRETT_SHIFT = 26.
const _Q:   i32 = 3329;
const _QINV: i16 = -3327;
const _BV:   i32 = 20159;   // Barrett multiplier
const _BRD:  i32 = 1 << 25; // rounding: 1 << (BARRETT_SHIFT - 1)
const _F:    i16 = 1441;    // invNTT scaling factor: mont²/128 mod q

// ── fqmul_8x ────────────────────────────────────────────────────────────────
// 8× fqmul: a·b·R⁻¹ mod q for each of the 8 i16 lane pairs (R = 2¹⁶).
//
// Montgomery reduction: given prod = a*b (i32), compute (prod - t*Q) >> 16
// where t = (i16)(prod * QINV).
//
// t is computed entirely in i16 arithmetic using i16x8.mul, which gives
// (x*y) mod 2^16 by definition — no sign-extend tricks needed.
// By the ring Z/2^16Z: low16(a*b*QINV) = low16(a * low16(b*QINV)).
// prod is computed via extmul (i32 exact product) for the final subtraction.
@inline
function fqmul_8x(a: v128, b: v128): v128 {
	const qinv_v: v128 = i16x8.splat(_QINV);
	const q_v:    v128 = i32x4.splat(_Q);

	// Full 32-bit products for the final (prod - t*Q) >> 16 step.
	const prod_lo: v128 = i32x4.extmul_low_i16x8_s(a, b);
	const prod_hi: v128 = i32x4.extmul_high_i16x8_s(a, b);

	// t = (i16)(a * b * QINV) computed in i16:
	//   t = a * (b * QINV)  in Z/2^16Z  (ring property: low16 is closed under *)
	const t_i16: v128 = i16x8.mul(a, i16x8.mul(b, qinv_v));

	// Sign-extend t to i32 for the subtraction.
	const t_lo: v128 = i32x4.extend_low_i16x8_s(t_i16);
	const t_hi: v128 = i32x4.extend_high_i16x8_s(t_i16);

	// r = (prod - t*Q) >> 16
	const r_lo: v128 = i32x4.shr_s(i32x4.sub(prod_lo, i32x4.mul(t_lo, q_v)), 16);
	const r_hi: v128 = i32x4.shr_s(i32x4.sub(prod_hi, i32x4.mul(t_hi, q_v)), 16);

	return i16x8.narrow_i32x4_s(r_lo, r_hi);
}

// ── barrett_reduce_8x ───────────────────────────────────────────────────────
// 8× Barrett reduction. Output in [-(q-1)/2, (q-1)/2].
// Widen to i32x4 for the multiply-shift, narrow back to i16x8.
@inline
export function barrett_reduce_8x(a: v128): v128 {
	const v_v:   v128 = i32x4.splat(_BV);
	const rnd_v: v128 = i32x4.splat(_BRD);
	const q_v:   v128 = i32x4.splat(_Q);

	const a_lo: v128 = i32x4.extend_low_i16x8_s(a);
	const a_hi: v128 = i32x4.extend_high_i16x8_s(a);

	// t = (v * a + 2²⁵) >> 26
	const t_lo: v128 = i32x4.shr_s(i32x4.add(i32x4.mul(a_lo, v_v), rnd_v), 26);
	const r_lo: v128 = i32x4.sub(a_lo, i32x4.mul(t_lo, q_v));

	const t_hi: v128 = i32x4.shr_s(i32x4.add(i32x4.mul(a_hi, v_v), rnd_v), 26);
	const r_hi: v128 = i32x4.sub(a_hi, i32x4.mul(t_hi, q_v));

	return i16x8.narrow_i32x4_s(r_lo, r_hi);
}

// ── ntt_simd ────────────────────────────────────────────────────────────────
// In-place forward NTT. FIPS 203 Algorithm 9 — NTT.
// Input in standard order, output in bit-reversed order.
//
// SIMD layers: len = 128, 64, 32, 16, 8 — 8 butterflies per v128 iteration.
// Scalar tail: len = 4, 2 — uses fqmul from reduce.ts.
//
// @param polyOffset byte offset of 256×i16 polynomial in WASM memory.
export function ntt_simd(polyOffset: i32): void {
	const zetasPtr: i32 = getZetasOffset();
	let k: i32 = 1;
	let len: i32 = 128;

	// SIMD layers: len >= 8, each group has len >= 8 elements.
	// 8 butterflies per SIMD iteration (one v128.load per half-group).
	while (len >= 8) {
		let start: i32 = 0;
		while (start < 256) {
			const zeta: i16 = load<i16>(zetasPtr + k * 2); k++;
			const z_v:  v128 = i16x8.splat(zeta);
			const end:  i32  = start + len;
			let j: i32 = start;
			while (j < end) {
				const pj:   i32 = polyOffset + j * 2;
				const pjl:  i32 = polyOffset + (j + len) * 2;
				const a:    v128 = v128.load(pj);
				const b:    v128 = v128.load(pjl);
				const t:    v128 = fqmul_8x(z_v, b);
				v128.store(pjl, i16x8.sub(a, t));
				v128.store(pj,  i16x8.add(a, t));
				j += 8;
			}
			start = end + len;
		}
		len >>= 1;
	}

	// Scalar tail: len = 4, 2.
	while (len >= 2) {
		let start: i32 = 0;
		while (start < 256) {
			const zeta: i16 = load<i16>(zetasPtr + k * 2); k++;
			const end: i32 = start + len;
			for (let j: i32 = start; j < end; j++) {
				const t:    i16 = fqmul(zeta, load<i16>(polyOffset + (j + len) * 2));
				const valj: i16 = load<i16>(polyOffset + j * 2);
				store<i16>(polyOffset + (j + len) * 2, valj - t);
				store<i16>(polyOffset + j * 2,         valj + t);
			}
			start = end + len;
		}
		len >>= 1;
	}
}

// ── invntt_simd ─────────────────────────────────────────────────────────────
// In-place inverse NTT. FIPS 203 Algorithm 10 — NTT⁻¹.
// Input in bit-reversed order, output in standard order.
// Includes final multiplication by f = 1441 = mont²/128 (Montgomery factor).
//
// Scalar tail first: len = 2, 4.
// SIMD layers: len = 8, 16, 32, 64, 128 — 8 butterflies per v128 iteration.
//
// @param polyOffset byte offset of 256×i16 polynomial in WASM memory.
export function invntt_simd(polyOffset: i32): void {
	const zetasPtr: i32 = getZetasOffset();
	let k: i32 = 127;
	let len: i32 = 2;

	// Scalar tail: len = 2, 4.
	while (len <= 4) {
		let start: i32 = 0;
		while (start < 256) {
			const zeta: i16 = load<i16>(zetasPtr + k * 2); k--;
			const end: i32 = start + len;
			for (let j: i32 = start; j < end; j++) {
				const t: i16 = load<i16>(polyOffset + j * 2);
				const u: i16 = load<i16>(polyOffset + (j + len) * 2);
				store<i16>(polyOffset + j * 2,         barrett_reduce(t + u));
				store<i16>(polyOffset + (j + len) * 2, fqmul(zeta, u - t));
			}
			start = end + len;
		}
		len <<= 1;
	}

	// SIMD layers: len = 8, 16, 32, 64, 128.
	// Inverse butterfly: t=coeff[j], u=coeff[j+len]
	//   coeff[j]     = barrett_reduce(t + u)
	//   coeff[j+len] = fqmul(zeta, u - t)
	while (len <= 128) {
		let start: i32 = 0;
		while (start < 256) {
			const zeta: i16 = load<i16>(zetasPtr + k * 2); k--;
			const z_v:  v128 = i16x8.splat(zeta);
			const end:  i32  = start + len;
			let j: i32 = start;
			while (j < end) {
				const pj:   i32 = polyOffset + j * 2;
				const pjl:  i32 = polyOffset + (j + len) * 2;
				const t:    v128 = v128.load(pj);
				const u:    v128 = v128.load(pjl);
				v128.store(pj,  barrett_reduce_8x(i16x8.add(t, u)));
				v128.store(pjl, fqmul_8x(z_v, i16x8.sub(u, t)));
				j += 8;
			}
			start = end + len;
		}
		len <<= 1;
	}

	// Final fqmul pass: coeff[i] *= f = 1441 = mont²/128 mod q.
	// 32 v128 iterations over 256 × i16.
	const f_v: v128 = i16x8.splat(_F);
	for (let i: i32 = 0; i < 32; i++) {
		const ptr: i32 = polyOffset + i * 16;
		v128.store(ptr, fqmul_8x(f_v, v128.load(ptr)));
	}
}
