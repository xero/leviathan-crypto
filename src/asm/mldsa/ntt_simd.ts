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
// src/asm/mldsa/ntt_simd.ts
//
// ML-DSA, SIMD NTT and inverse NTT using WASM v128 with i32x4 lanes.
// FIPS 204 Algorithms 41 (NTT) and 42 (NTT⁻¹), vectorised.
//
// SIMD lane discipline: ML-DSA coefficients are i32 (q ≈ 2²³ does not fit i16),
// so each v128 carries 4 coefficients, half the lane count of ML-KEM's i16x8.
// 4 contiguous butterflies fit a v128 only when len ≥ 4 (group size ≥ 8).
// Smaller layers (len = 2, 1) reuse the scalar fqmul/barrett_reduce because
// the per-butterfly twiddle factors don't share lanes inside a vector.
//
// CT posture: every coefficient is processed unconditionally. The Barrett
// post-corrections are mask-and-add (no data-dependent branching). Same
// constant-time properties as the scalar path.

import { fqmul, barrett_reduce } from './reduce';
import { Q, QINV, F_MONT, BARRETT_V, BARRETT_SHIFT, HALF_Q } from './params';
import { getZetasOffset } from './ntt';

// ── fqmul_4x ────────────────────────────────────────────────────────────────
// 4× Montgomery multiplication: returns (a · b · 2⁻³²) mod q lane-wise.
//
// FIPS 204 Algorithm 49, vectorised:
//   c    = a × b             , full i64 product, 4 lanes split across 2 v128
//   t    = (c mod 2³²) · QINV, low 32 bits per lane via i32x4.mul
//   r    = (c − t·q) >> 32   , high 32 bits of the divisible-by-2³² value
//
// Lane packing: i64x2.shr_s(_, 32) places the desired i32 result in the LOW
// 32 bits of each i64 lane (with sign-extended zeros / ones in the high half
// that we discard). The closing v128.shuffle<i8> picks those low halves out
// of two i64x2 vectors and packs them into one i32x4.
@inline
export function fqmul_4x(a: v128, b: v128): v128 {
	// p = a * b, full signed i64 products, low pair and high pair of lanes.
	const p_lo: v128 = i64x2.extmul_low_i32x4_s(a, b);
	const p_hi: v128 = i64x2.extmul_high_i32x4_s(a, b);

	// (c mod 2³²) per lane, i32x4.mul gives the low 32 bits of each product.
	const p_mod32: v128 = i32x4.mul(a, b);

	// t = ((c mod 2³²) · QINV) mod 2³², closed in i32 by the ring property
	// of multiplication mod 2³². i32x4.mul is exactly that.
	const qinv_v: v128 = i32x4.splat(QINV);
	const t:      v128 = i32x4.mul(p_mod32, qinv_v);

	// t · q as full i64 products, split lo/hi.
	const q_v:   v128 = i32x4.splat(Q);
	const tq_lo: v128 = i64x2.extmul_low_i32x4_s(t, q_v);
	const tq_hi: v128 = i64x2.extmul_high_i32x4_s(t, q_v);

	// r = (p − t·q) >> 32, exact division because p ≡ t·q (mod 2³²).
	const r_lo: v128 = i64x2.shr_s(i64x2.sub(p_lo, tq_lo), 32);
	const r_hi: v128 = i64x2.shr_s(i64x2.sub(p_hi, tq_hi), 32);

	// Pack low i32 of each i64 lane into a single i32x4.
	// Byte indices into concat(r_lo, r_hi):
	//   r_lo[0..3]   bytes 0..3   → output i32 lane 0
	//   r_lo[8..11]  bytes 8..11  → output i32 lane 1
	//   r_hi[0..3]   bytes 16..19 → output i32 lane 2
	//   r_hi[8..11]  bytes 24..27 → output i32 lane 3
	return v128.shuffle<i8>(r_lo, r_hi,
		0, 1, 2, 3,
		8, 9, 10, 11,
		16, 17, 18, 19,
		24, 25, 26, 27,
	);
}

// ── ntt_simd, FIPS 204 Algorithm 41, vectorised ───────────────────────────
//
// SIMD layers: len = 128, 64, 32, 16, 8, 4, 4 butterflies per v128 step.
// Scalar tail: len = 2, 1, two layers where the twiddle differs per pair.
export function ntt_simd(polyOffset: i32): void {
	const zetasPtr: i32 = getZetasOffset();
	let m: i32 = 0;
	let len: i32 = 128;

	// SIMD layers, group size ≥ 8.
	while (len >= 4) {
		let start: i32 = 0;
		while (start < 256) {
			m++;
			const z: i32 = load<i32>(zetasPtr + m * 4);
			const z_v: v128 = i32x4.splat(z);
			const end: i32 = start + len;
			let j: i32 = start;
			while (j < end) {
				const pj:  i32 = polyOffset + j * 4;
				const pjl: i32 = polyOffset + (j + len) * 4;
				const a: v128 = v128.load(pj);
				const b: v128 = v128.load(pjl);
				const t: v128 = fqmul_4x(z_v, b);
				v128.store(pjl, i32x4.sub(a, t));
				v128.store(pj,  i32x4.add(a, t));
				j += 4;
			}
			start = end + len;
		}
		len >>= 1;
	}

	// Scalar tail, len = 2, 1.
	while (len >= 1) {
		let start: i32 = 0;
		while (start < 256) {
			m++;
			const z: i32 = load<i32>(zetasPtr + m * 4);
			const end: i32 = start + len;
			for (let j: i32 = start; j < end; j++) {
				const t: i32 = fqmul(z, load<i32>(polyOffset + (j + len) * 4));
				const wj: i32 = load<i32>(polyOffset + j * 4);
				store<i32>(polyOffset + (j + len) * 4, wj - t);
				store<i32>(polyOffset + j * 4,         wj + t);
			}
			start = end + len;
		}
		len >>= 1;
	}
}

// ── invntt_simd, FIPS 204 Algorithm 42, vectorised ────────────────────────
//
// Scalar head: len = 1, 2, two layers below the v128 grouping threshold.
// SIMD layers: len = 4, 8, 16, 32, 64, 128, 4 butterflies per v128 step.
// Final scalar 256⁻¹ multiplication is fused into a SIMD pass at the end.
export function invntt_simd(polyOffset: i32): void {
	const zetasPtr: i32 = getZetasOffset();
	let m: i32 = 256;
	let len: i32 = 1;

	// Scalar head, len = 1, 2.
	while (len < 4) {
		let start: i32 = 0;
		while (start < 256) {
			m--;
			const z: i32 = -load<i32>(zetasPtr + m * 4);
			const end: i32 = start + len;
			for (let j: i32 = start; j < end; j++) {
				const wj:  i32 = load<i32>(polyOffset + j * 4);
				const wjl: i32 = load<i32>(polyOffset + (j + len) * 4);
				store<i32>(polyOffset + j * 4,         barrett_reduce(wj + wjl));
				store<i32>(polyOffset + (j + len) * 4, fqmul(z, wj - wjl));
			}
			start = end + len;
		}
		len <<= 1;
	}

	// SIMD layers, len = 4, 8, 16, 32, 64, 128.
	while (len < 256) {
		let start: i32 = 0;
		while (start < 256) {
			m--;
			const z: i32 = -load<i32>(zetasPtr + m * 4);
			const z_v: v128 = i32x4.splat(z);
			const end: i32 = start + len;
			let j: i32 = start;
			while (j < end) {
				const pj:  i32 = polyOffset + j * 4;
				const pjl: i32 = polyOffset + (j + len) * 4;
				const a: v128 = v128.load(pj);
				const b: v128 = v128.load(pjl);
				v128.store(pj,  barrett_reduce_4x(i32x4.add(a, b)));
				v128.store(pjl, fqmul_4x(z_v, i32x4.sub(a, b)));
				j += 4;
			}
			start = end + len;
		}
		len <<= 1;
	}

	// Closing 256⁻¹ scale, vectorised. F_MONT lives in Montgomery form so
	// fqmul_4x(F_v, w) gives 256⁻¹ · w in regular form, matching FIPS 204
	// Algorithm 42 line 23.
	const f_v: v128 = i32x4.splat(F_MONT);
	for (let i: i32 = 0; i < 64; i++) {
		const ptr: i32 = polyOffset + i * 16;
		v128.store(ptr, fqmul_4x(f_v, v128.load(ptr)));
	}
}

// ── barrett_reduce_4x ───────────────────────────────────────────────────────
// 4× Barrett reduction. Output in [-(q-1)/2, (q-1)/2] per FIPS 204 §2.3.
// Local re-derivation of the scalar barrett_reduce for SIMD lanes.
//
// v = 1049603 ≈ 2⁴³ / q (params.ts BARRETT_V derivation). Wider intermediate
// (i64x2 × 2) carries the multiplication; shift right 43 yields t ≈ a/q;
// r = a − t·q bounded by q in magnitude after correction.
@inline
export function barrett_reduce_4x(a: v128): v128 {
	const v_v:   v128 = i32x4.splat(BARRETT_V);
	const rnd_v: v128 = i64x2.splat(<i64>1 << (BARRETT_SHIFT - 1));  // round-half-up: +2^(k-1)
	const q_v:   v128 = i32x4.splat(Q);
	const half_q_v: v128 = i32x4.splat(HALF_Q);

	// Widen a to i64 lanes for the multiply-shift.
	const t_lo64: v128 = i64x2.shr_s(
		i64x2.add(i64x2.extmul_low_i32x4_s(a, v_v),  rnd_v), BARRETT_SHIFT);
	const t_hi64: v128 = i64x2.shr_s(
		i64x2.add(i64x2.extmul_high_i32x4_s(a, v_v), rnd_v), BARRETT_SHIFT);

	// Pack t back to i32x4 (low i32 of each i64 lane).
	const t: v128 = v128.shuffle<i8>(t_lo64, t_hi64,
		0, 1, 2, 3,
		8, 9, 10, 11,
		16, 17, 18, 19,
		24, 25, 26, 27,
	);

	// r = a − t·q (i32x4-safe: |t| ≪ 2¹⁰ and q ≈ 2²³, product < 2³³, but
	// since t ≈ a/q with |a| ≤ 2³¹ we have |t·q| ≤ |a| + q so r stays i32).
	let r: v128 = i32x4.sub(a, i32x4.mul(t, q_v));

	// Branch-free centered correction: r ∈ (-q/2, q/2].
	// If r > HALF_Q ⇒ subtract q. If r < −HALF_Q ⇒ add q.
	const gt_mask: v128 = i32x4.shr_s(i32x4.sub(half_q_v, r), 31);
	r = i32x4.sub(r, v128.and(gt_mask, q_v));
	const lt_mask: v128 = i32x4.shr_s(i32x4.add(r, half_q_v), 31);
	r = i32x4.add(r, v128.and(lt_mask, q_v));

	return r;
}
