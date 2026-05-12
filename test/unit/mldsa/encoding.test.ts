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
//                           ▀█████▀▀▀
//
// test/unit/mldsa/encoding.test.ts
//
// GATE: ML-DSA bit-pack/unpack round-trips (FIPS 204 §7.1 Algs 16-19) plus
// HintBitPack/HintBitUnpack (Algs 20-21) including the three SUF-CMA-critical
// malformed-input checks (lines 4, 9, 17 of Alg 21, see FIPS 204 §D.3).
//
// Widths exercised match the union across all parameter sets: 3, 4, 6, 10,
// 13, 18, 20.

import { describe, test, expect, beforeAll } from 'vitest';
import { loadMldsa, getWasm, readPoly, writePoly, readBytes, writeBytes, prng } from './helpers.js';

const N = 256;

beforeAll(async () => {
	await loadMldsa();
});

// ── Helpers ─────────────────────────────────────────────────────────────────

function packLen(bitlen: number): number {
	return 32 * bitlen;
}

// ── GATE: simple_bit_pack / simple_bit_unpack round-trip ───────────────────

describe('Gate, simple_bit_pack / simple_bit_unpack (FIPS 204 Algs 16, 18)', () => {
	const widths = [3, 4, 6, 10, 13, 18, 20];

	for (const bitlen of widths) {
		test(`width ${bitlen} round-trip preserves coefficients`, () => {
			const w = getWasm();
			const POLY = w.getPolySlot0();
			const POLY2 = w.getPolySlot1();
			const BUF  = w.getXofPrfOffset();   // scratch byte buffer
			const rand = prng(0x53420000 | bitlen);  // 'SB' + width
			const max = (1 << bitlen) - 1;

			// Build a polynomial with coefficients in [0, 2^bitlen − 1].
			const coeffs: number[] = new Array(N);
			for (let i = 0; i < N; i++) coeffs[i] = rand() & max;
			writePoly(coeffs, POLY);

			w.simple_bit_pack(BUF, POLY, bitlen);
			expect(readBytes(BUF, packLen(bitlen)).length).toBe(packLen(bitlen));
			w.simple_bit_unpack(POLY2, BUF, bitlen);
			const r = readPoly(POLY2);
			for (let i = 0; i < N; i++) expect(r[i]).toBe(coeffs[i]);
		});
	}
});

// ── GATE: bit_pack / bit_unpack round-trip ─────────────────────────────────

describe('Gate, bit_pack / bit_unpack (FIPS 204 Algs 17, 19)', () => {
	// (a, b) pairs cover: η=2 (3-bit), η=4 (4-bit), t0 (13-bit), z@γ₁=2¹⁷ (18-bit),
	// z@γ₁=2¹⁹ (20-bit).
	const ranges: { name: string; a: number; b: number }[] = [
		{ name: 'eta=2 → bitlen 3',  a: 2,         b: 2         },
		{ name: 'eta=4 → bitlen 4',  a: 4,         b: 4         },
		{ name: 't0    → bitlen 13', a: 4095,      b: 4096      },
		{ name: 'γ₁=2¹⁷ → bitlen 18', a: (1 << 17) - 1, b: (1 << 17)  },
		{ name: 'γ₁=2¹⁹ → bitlen 20', a: (1 << 19) - 1, b: (1 << 19)  },
	];

	for (const { name, a, b } of ranges) {
		test(`${name} round-trip preserves coefficients`, () => {
			const w = getWasm();
			const POLY = w.getPolySlot0();
			const POLY2 = w.getPolySlot1();
			const BUF  = w.getXofPrfOffset();
			const rand = prng(0x42500000 | (a + b));   // 'BP' + sum
			const span = a + b + 1;

			const coeffs: number[] = new Array(N);
			for (let i = 0; i < N; i++) coeffs[i] = (rand() % span) - a;
			writePoly(coeffs, POLY);

			w.bit_pack(BUF, POLY, a, b);
			w.bit_unpack(POLY2, BUF, a, b);
			const r = readPoly(POLY2);
			for (let i = 0; i < N; i++) expect(r[i]).toBe(coeffs[i]);
		});
	}
});

// ── GATE: hint_bit_pack / hint_bit_unpack round-trip ───────────────────────

describe('Gate, hint_bit_pack / hint_bit_unpack (FIPS 204 Algs 20, 21)', () => {
	test('round-trip with k=4, ω=80, sparse hints', () => {
		const w = getWasm();
		const k = 4, omega = 80;
		const HV  = w.getPolyvecSlot0();
		const HV2 = w.getPolyvecSlot1();
		const BUF = w.getXofPrfOffset();

		// Build a hint polyvec with at most ω total set bits, ascending positions
		// within each polynomial.
		const hint: number[][] = [];
		const counts = [10, 20, 5, 15];   // per-poly nonzero counts (sum = 50 ≤ ω)
		const rand = prng(0x48505550);    // 'HPUP'
		for (let i = 0; i < k; i++) {
			const poly = new Array<number>(N).fill(0);
			const positions = new Set<number>();
			while (positions.size < counts[i]) positions.add(rand() % N);
			[...positions].sort((x, y) => x - y).forEach(p => {
				poly[p] = 1;
			});
			hint.push(poly);
			writePoly(poly, HV + i * 1024);
		}

		w.hint_bit_pack(BUF, HV, k, omega);
		const ret = w.hint_bit_unpack(HV2, BUF, k, omega);
		expect(ret).toBe(0);
		for (let i = 0; i < k; i++) {
			const got = readPoly(HV2 + i * 1024);
			for (let j = 0; j < N; j++) expect(got[j]).toBe(hint[i][j]);
		}
	});

	// ── Three SUF-CMA-critical malformed-input checks ──────────────────────

	test('malformed input, y[ω+i] regresses below Index → -1 (Alg 21 line 4)', () => {
		const w = getWasm();
		const k = 2, omega = 4;
		const HV  = w.getPolyvecSlot0();
		const BUF = w.getXofPrfOffset();
		// y[ω + 0] = 2, y[ω + 1] = 1. Second cumulative is less than first → reject.
		const bytes = new Uint8Array(omega + k);
		bytes[0] = 0;     // poly 0, position 0
		bytes[1] = 5;     // poly 0, position 5
		bytes[omega + 0] = 2;   // cumulative count after poly 0 = 2
		bytes[omega + 1] = 1;   // cumulative count after poly 1 must be ≥ 2
		writeBytes(bytes, BUF);
		expect(w.hint_bit_unpack(HV, BUF, k, omega)).toBe(-1);
	});

	test('malformed input, y[ω+i] > ω → -1 (Alg 21 line 4 upper bound)', () => {
		const w = getWasm();
		const k = 2, omega = 4;
		const HV  = w.getPolyvecSlot0();
		const BUF = w.getXofPrfOffset();
		const bytes = new Uint8Array(omega + k);
		bytes[omega + 0] = 5;   // > ω = 4
		writeBytes(bytes, BUF);
		expect(w.hint_bit_unpack(HV, BUF, k, omega)).toBe(-1);
	});

	test('malformed input, non-strict ascending positions in same poly → -1 (Alg 21 line 9)', () => {
		const w = getWasm();
		const k = 1, omega = 4;
		const HV  = w.getPolyvecSlot0();
		const BUF = w.getXofPrfOffset();
		const bytes = new Uint8Array(omega + k);
		bytes[0] = 5;          // first position
		bytes[1] = 5;          // duplicate (must be strictly greater)
		bytes[omega + 0] = 2;  // 2 set bits in poly 0
		writeBytes(bytes, BUF);
		expect(w.hint_bit_unpack(HV, BUF, k, omega)).toBe(-1);

		// Equal-prev with descending also forbidden.
		bytes[0] = 7;
		bytes[1] = 5;
		writeBytes(bytes, BUF);
		expect(w.hint_bit_unpack(HV, BUF, k, omega)).toBe(-1);
	});

	test('malformed input, trailing nonzero byte in [Index, ω) → -1 (Alg 21 line 17)', () => {
		const w = getWasm();
		const k = 1, omega = 4;
		const HV  = w.getPolyvecSlot0();
		const BUF = w.getXofPrfOffset();
		const bytes = new Uint8Array(omega + k);
		bytes[0] = 3;          // poly 0, position 3
		bytes[1] = 0;          // legit trailing zero
		bytes[2] = 0;
		bytes[3] = 0xAB;       // illegal trailing nonzero
		bytes[omega + 0] = 1;  // only 1 set bit in poly 0
		writeBytes(bytes, BUF);
		expect(w.hint_bit_unpack(HV, BUF, k, omega)).toBe(-1);
	});

	test('boundary, empty hint (no set bits anywhere) round-trips with all zeros', () => {
		const w = getWasm();
		const k = 4, omega = 75;
		const HV  = w.getPolyvecSlot0();
		const HV2 = w.getPolyvecSlot1();
		const BUF = w.getXofPrfOffset();
		// Empty hint polyvec.
		for (let i = 0; i < k; i++) writePoly(new Array(N).fill(0), HV + i * 1024);
		w.hint_bit_pack(BUF, HV, k, omega);
		const ret = w.hint_bit_unpack(HV2, BUF, k, omega);
		expect(ret).toBe(0);
		for (let i = 0; i < k; i++) {
			const got = readPoly(HV2 + i * 1024);
			for (let j = 0; j < N; j++) expect(got[j]).toBe(0);
		}
	});
});
