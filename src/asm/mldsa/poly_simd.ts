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
// src/asm/mldsa/poly_simd.ts
//
// ML-DSA, SIMD polynomial arithmetic using WASM v128 with i32x4 lanes.
// FIPS 204 §7.6 (AddNTT, MultiplyNTT) plus the supporting reduce / caddq.
//
// 256 × i32 polynomials decompose into 64 v128 iterations of 4 coefficients.
// Caddq uses a sign-bit mask (no data-dependent branching). Pointwise
// Montgomery multiply reuses fqmul_4x from ntt_simd.ts.

import { Q } from './params';
import { fqmul_4x, barrett_reduce_4x } from './ntt_simd';

// ── poly_add_simd, coefficient-wise add, 4 lanes per step ──────────────────
export function poly_add_simd(rOff: i32, aOff: i32, bOff: i32): void {
	for (let i: i32 = 0; i < 64; i++) {
		const off: i32 = i * 16;
		v128.store(rOff + off,
			i32x4.add(v128.load(aOff + off), v128.load(bOff + off)));
	}
}

// ── poly_sub_simd, coefficient-wise sub ────────────────────────────────────
export function poly_sub_simd(rOff: i32, aOff: i32, bOff: i32): void {
	for (let i: i32 = 0; i < 64; i++) {
		const off: i32 = i * 16;
		v128.store(rOff + off,
			i32x4.sub(v128.load(aOff + off), v128.load(bOff + off)));
	}
}

// ── poly_reduce_simd, Barrett (centered) reduction lane-wise ───────────────
export function poly_reduce_simd(polyOff: i32): void {
	for (let i: i32 = 0; i < 64; i++) {
		const ptr: i32 = polyOff + i * 16;
		v128.store(ptr, barrett_reduce_4x(v128.load(ptr)));
	}
}

// ── poly_caddq_simd, branch-free conditional add q ─────────────────────────
// (a >> 31) sprays the sign bit; AND with q yields q for a<0, 0 otherwise.
export function poly_caddq_simd(polyOff: i32): void {
	const q_v: v128 = i32x4.splat(Q);
	for (let i: i32 = 0; i < 64; i++) {
		const ptr: i32 = polyOff + i * 16;
		const a: v128 = v128.load(ptr);
		const m: v128 = i32x4.shr_s(a, 31);
		v128.store(ptr, i32x4.add(a, v128.and(m, q_v)));
	}
}

// ── poly_pointwise_montgomery_simd, FIPS 204 Algorithm 45, vectorised ──────
// c[i] = MontgomeryReduce(a[i]·b[i]); 4 lanes per v128 step.
export function poly_pointwise_montgomery_simd(rOff: i32, aOff: i32, bOff: i32): void {
	for (let i: i32 = 0; i < 64; i++) {
		const off: i32 = i * 16;
		v128.store(rOff + off,
			fqmul_4x(v128.load(aOff + off), v128.load(bOff + off)));
	}
}
