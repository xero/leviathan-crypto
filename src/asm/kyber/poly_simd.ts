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
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▄          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
//
// src/asm/kyber/poly_simd.ts
//
// ML-KEM (Kyber) — SIMD polynomial arithmetic using WASM v128.
// FIPS 203 §4 polynomial operations: add, sub, reduce, NTT wrappers.
//
// All operations process 256 × i16 coefficients in 32 v128 iterations
// (8 coefficients per v128).

import { barrett_reduce_8x, ntt_simd, invntt_simd } from './ntt_simd';

// ── poly_add_simd ─────────────────────────────────────────────────────────────
// Pointwise addition of two polynomials. 32 v128 iterations.
// No modular reduction — same semantics as scalar poly_add.
export function poly_add_simd(rOffset: i32, aOffset: i32, bOffset: i32): void {
	for (let i: i32 = 0; i < 32; i++) {
		const off: i32 = i * 16;
		v128.store(rOffset + off,
			i16x8.add(v128.load(aOffset + off), v128.load(bOffset + off)));
	}
}

// ── poly_sub_simd ─────────────────────────────────────────────────────────────
// Pointwise subtraction of two polynomials. 32 v128 iterations.
// No modular reduction — same semantics as scalar poly_sub.
export function poly_sub_simd(rOffset: i32, aOffset: i32, bOffset: i32): void {
	for (let i: i32 = 0; i < 32; i++) {
		const off: i32 = i * 16;
		v128.store(rOffset + off,
			i16x8.sub(v128.load(aOffset + off), v128.load(bOffset + off)));
	}
}

// ── poly_reduce_simd ──────────────────────────────────────────────────────────
// Barrett reduction on all 256 coefficients. Result in [-(q-1)/2, (q-1)/2].
// 32 v128 iterations using barrett_reduce_8x from ntt_simd.ts.
export function poly_reduce_simd(polyOffset: i32): void {
	for (let i: i32 = 0; i < 32; i++) {
		const ptr: i32 = polyOffset + i * 16;
		v128.store(ptr, barrett_reduce_8x(v128.load(ptr)));
	}
}

// ── poly_ntt_simd ─────────────────────────────────────────────────────────────
// Forward NTT followed by Barrett reduction. FIPS 203 Algorithm 9.
export function poly_ntt_simd(polyOffset: i32): void {
	ntt_simd(polyOffset);
	poly_reduce_simd(polyOffset);
}

// ── poly_invntt_simd ──────────────────────────────────────────────────────────
// Inverse NTT (includes Montgomery factor f=1441). FIPS 203 Algorithm 10.
export function poly_invntt_simd(polyOffset: i32): void {
	invntt_simd(polyOffset);
}
