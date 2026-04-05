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
// src/asm/kyber/ntt.ts
//
// ML-KEM (Kyber) — Number-Theoretic Transform (NTT) and inverse NTT.
// FIPS 203 Algorithms 9 and 10.
// Zeta table: ω=17 primitive 256th root of unity in Z_3329, bit-reversed,
// Montgomery domain. Source: pq-crystals/kyber main branch ref/ntt.c.

import { fqmul, barrett_reduce } from './reduce';

// ── Zetas table ────────────────────────────────────────────────────────────────
// 128 twiddle factors. Each entry zetas[i] = MONT * 17^{BitRev7(i)} mod q,
// centered to [-(q-1)/2, (q-1)/2].
// Source: pq-crystals/kyber main ref/ntt.c — must be verified by Gate 3 test.
const zetas: StaticArray<i16> = [
	-1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
	 -171,   622,  1577,   182,   962, -1202, -1474,  1468,
	  573, -1325,   264,   383,  -829,  1458, -1602,  -130,
	 -681,  1017,   732,   608, -1542,   411,  -205, -1571,
	 1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
	  516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
	 -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
	 -398,   961, -1508,  -725,   448, -1065,   677, -1275,
	-1103,   430,   555,   843, -1251,   871,  1550,   105,
	  422,   587,   177,  -235,  -291,  -460,  1574,  1653,
	 -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
	-1590,   644,  -872,   349,   418,   329,  -156,   -75,
	  817,  1097,   603,   610,  1322, -1285, -1465,   384,
	-1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
	-1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
	 -108,  -308,   996,   991,   958, -1460,  1522,  1628,
];

// In AssemblyScript, changetype<i32>(arr) returns the data pointer directly.
// The runtime header (mmInfo+gcInfo+gcInfo2+rtId+rtSize) sits at ptr-20 (before the data).
// So the data offset is 0 — changetype<i32>(zetas) IS the start of the i16 elements.
const AS_HEADER_SIZE: i32 = 0;

/**
 * Returns the byte offset of zetas[0] in WASM linear memory.
 * Useful for TS layer inspection.
 */
export function getZetasOffset(): i32 {
	return changetype<i32>(zetas) + AS_HEADER_SIZE;
}

/**
 * Returns zetas[i] (the i-th NTT twiddle factor).
 * Used by Gate 3 test to independently verify the table.
 */
export function getZeta(i: i32): i16 {
	return unchecked(zetas[i]);
}

// ── NTT ────────────────────────────────────────────────────────────────────────

/**
 * In-place forward NTT. FIPS 203 Algorithm 9 — NTT.
 * Input in standard order, output in bit-reversed order.
 * @param polyOffset byte offset of 256×i16 polynomial in WASM memory.
 */
export function ntt(polyOffset: i32): void {
	// FIPS 203 Algorithm 9, pq-crystals/kyber ref/ntt.c ntt()
	let k: i32 = 1;
	let len: i32 = 128;
	while (len >= 2) {
		let start: i32 = 0;
		while (start < 256) {
			const zeta: i16 = unchecked(zetas[k++]);
			const end: i32 = start + len;
			for (let j: i32 = start; j < end; j++) {
				const t: i16 = fqmul(zeta, load<i16>(polyOffset + (j + len) * 2));
				store<i16>(polyOffset + (j + len) * 2, load<i16>(polyOffset + j * 2) - t);
				store<i16>(polyOffset + j * 2, load<i16>(polyOffset + j * 2) + t);
			}
			start = end + len;
		}
		len >>= 1;
	}
}

/**
 * In-place inverse NTT. FIPS 203 Algorithm 10 — NTT^{-1}.
 * Input in bit-reversed order, output in standard order.
 * Includes multiplication by Montgomery factor f = 1441 = mont²/128.
 * @param polyOffset byte offset of 256×i16 polynomial in WASM memory.
 */
export function invntt(polyOffset: i32): void {
	// FIPS 203 Algorithm 10, pq-crystals/kyber ref/ntt.c invntt()
	// f = mont^2/128 mod q = 1441 (verified: 2285^2 * modinv(128, 3329) mod 3329 = 1441)
	const f: i16 = 1441;
	let k: i32 = 127;
	let len: i32 = 2;
	while (len <= 128) {
		let start: i32 = 0;
		while (start < 256) {
			const zeta: i16 = unchecked(zetas[k--]);
			const end: i32 = start + len;
			for (let j: i32 = start; j < end; j++) {
				const t: i16 = load<i16>(polyOffset + j * 2);
				const u: i16 = load<i16>(polyOffset + (j + len) * 2);
				store<i16>(polyOffset + j * 2, barrett_reduce(t + u));
				store<i16>(polyOffset + (j + len) * 2, fqmul(zeta, u - t));
			}
			start = end + len;
		}
		len <<= 1;
	}
	// Multiply all coefficients by f
	for (let j: i32 = 0; j < 256; j++) {
		store<i16>(polyOffset + j * 2, fqmul(load<i16>(polyOffset + j * 2), f));
	}
}

/**
 * Multiplication in Z_q[X]/(X² - ζ). FIPS 203 §4.3.
 * Computes r[0..1] = a[0..1] × b[0..1] mod (X² - ζ).
 * @param rOffset output pair offset
 * @param aOffset first factor pair offset
 * @param bOffset second factor pair offset
 * @param zetaIdx index into zetas table (the +ζ value; -ζ is used for the second pair)
 */
export function basemul(rOffset: i32, aOffset: i32, bOffset: i32, zetaIdx: i32): void {
	// FIPS 203 §4.3, pq-crystals/kyber ref/ntt.c basemul()
	const zeta: i16 = unchecked(zetas[zetaIdx]);
	const a0: i16 = load<i16>(aOffset);
	const a1: i16 = load<i16>(aOffset + 2);
	const b0: i16 = load<i16>(bOffset);
	const b1: i16 = load<i16>(bOffset + 2);
	// r[0] = a[1]*b[1]*ζ + a[0]*b[0]
	const r0: i16 = fqmul(fqmul(a1, b1), zeta) + fqmul(a0, b0);
	// r[1] = a[0]*b[1] + a[1]*b[0]
	const r1: i16 = fqmul(a0, b1) + fqmul(a1, b0);
	store<i16>(rOffset, r0);
	store<i16>(rOffset + 2, r1);
}
