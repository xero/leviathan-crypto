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
// test/unit/kyber/ntt_simd_gate.test.ts
//
// Gate tests for the SIMD NTT and polynomial arithmetic vectorizations.
// Phase 1 gate: ntt_simd / invntt_simd must be byte-identical to scalar
// ntt / invntt for arbitrary inputs.
// Phase 2 gate: poly_add, poly_sub, poly_reduce, poly_ntt, poly_invntt
// (all SIMD) must match their reference semantics.

import { describe, test, expect, beforeAll } from 'vitest';
import {
	loadKyber, getWasm,
	readPoly, writePoly,
	prng, randPoly, i16,
} from './helpers.js';

const Q  = 3329;
const N  = 256;

beforeAll(async () => {
	await loadKyber();
});

// ── Gate 1 — SIMD NTT byte-identical to scalar NTT ───────────────────────────

describe('Gate 1 — SIMD NTT matches scalar NTT', () => {

	test('ntt (SIMD) == ntt_scalar for zero polynomial', () => {
		const w = getWasm();
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		writePoly(new Array(N).fill(0), s0);
		writePoly(new Array(N).fill(0), s1);
		w.ntt(s0);
		w.ntt_scalar(s1);
		expect(readPoly(s0)).toEqual(readPoly(s1));
	});

	test('ntt (SIMD) == ntt_scalar for single-coefficient polynomial', () => {
		const w = getWasm();
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		// coeff[128] = 128 — exercises the first non-trivial butterfly
		const poly = new Array(N).fill(0);
		poly[128] = 128;
		writePoly(poly, s0);
		writePoly(poly, s1);
		w.ntt(s0);
		w.ntt_scalar(s1);
		expect(readPoly(s0)).toEqual(readPoly(s1));
	});

	test('ntt (SIMD) == ntt_scalar for all-ones polynomial', () => {
		const w = getWasm();
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const poly = new Array(N).fill(1);
		writePoly(poly, s0);
		writePoly(poly, s1);
		w.ntt(s0);
		w.ntt_scalar(s1);
		expect(readPoly(s0)).toEqual(readPoly(s1));
	});

	test('ntt (SIMD) == ntt_scalar for 100 random polynomials', () => {
		const w = getWasm();
		const rand = prng(0x4E54_5301);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		for (let trial = 0; trial < 100; trial++) {
			const poly = randPoly(Q, rand);
			writePoly(poly, s0);
			writePoly(poly, s1);
			w.ntt(s0);
			w.ntt_scalar(s1);
			const simd = readPoly(s0);
			const scalar = readPoly(s1);
			for (let i = 0; i < N; i++) {
				if (simd[i] !== scalar[i]) {
					throw new Error(
						`trial=${trial} coeff[${i}]: simd=${simd[i]} scalar=${scalar[i]}`,
					);
				}
			}
		}
	});

	test('invntt (SIMD) == invntt_scalar for 100 random NTT-domain polynomials', () => {
		const w = getWasm();
		const rand = prng(0x494E_5601);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		for (let trial = 0; trial < 100; trial++) {
			// Apply scalar NTT to get a valid NTT-domain poly, then compare invntt paths
			const poly = randPoly(Q, rand);
			writePoly(poly, s0);
			w.ntt_scalar(s0);
			const nttPoly = readPoly(s0);

			writePoly(nttPoly, s0);
			writePoly(nttPoly, s1);
			w.invntt(s0);
			w.invntt_scalar(s1);
			const simd = readPoly(s0);
			const scalar = readPoly(s1);
			for (let i = 0; i < N; i++) {
				if (simd[i] !== scalar[i]) {
					throw new Error(
						`trial=${trial} coeff[${i}]: simd=${simd[i]} scalar=${scalar[i]}`,
					);
				}
			}
		}
	});

	test('ntt_simd → invntt_simd roundtrip recovers input (100 random polynomials)', () => {
		const w = getWasm();
		const rand = prng(0x5254_5501);
		const s0 = w.getPolySlot0();
		for (let trial = 0; trial < 100; trial++) {
			const original = randPoly(Q, rand);
			writePoly(original, s0);
			w.ntt(s0);
			w.invntt(s0);
			w.poly_reduce(s0);
			const recovered = readPoly(s0);
			for (let i = 0; i < N; i++) {
				// invntt(ntt(f)) = f * R mod q — apply montgomery_reduce to normalize
				const normalized = i16(w.montgomery_reduce(recovered[i]));
				if (((original[i] - normalized) % Q + Q) % Q !== 0) {
					throw new Error(
						`trial=${trial} coeff[${i}]: original=${original[i]} normalized=${normalized}`,
					);
				}
			}
		}
	});
});

// ── Gate 2 — SIMD polynomial arithmetic matches reference semantics ───────────

describe('Gate 2 — SIMD poly arithmetic matches reference', () => {

	test('poly_add (SIMD): r[i] = a[i] + b[i] for 50 random pairs', () => {
		const w = getWasm();
		const rand = prng(0x4144_4401);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const s2 = w.getPolySlot2();
		for (let trial = 0; trial < 50; trial++) {
			const a = randPoly(Q, rand);
			const b = randPoly(Q, rand);
			writePoly(a, s0);
			writePoly(b, s1);
			w.poly_add(s2, s0, s1);
			const got = readPoly(s2);
			for (let i = 0; i < N; i++) {
				// a[i] + b[i] as i16 (wrapping)
				const expected = i16(a[i] + b[i]);
				if (got[i] !== expected) {
					throw new Error(
						`trial=${trial} coeff[${i}]: got=${got[i]} expected=${expected}`,
					);
				}
			}
		}
	});

	test('poly_sub (SIMD): r[i] = a[i] - b[i] for 50 random pairs', () => {
		const w = getWasm();
		const rand = prng(0x5355_4201);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const s2 = w.getPolySlot2();
		for (let trial = 0; trial < 50; trial++) {
			const a = randPoly(Q, rand);
			const b = randPoly(Q, rand);
			writePoly(a, s0);
			writePoly(b, s1);
			w.poly_sub(s2, s0, s1);
			const got = readPoly(s2);
			for (let i = 0; i < N; i++) {
				const expected = i16(a[i] - b[i]);
				if (got[i] !== expected) {
					throw new Error(
						`trial=${trial} coeff[${i}]: got=${got[i]} expected=${expected}`,
					);
				}
			}
		}
	});

	test('poly_reduce (SIMD): each coefficient matches scalar barrett_reduce', () => {
		const w = getWasm();
		const rand = prng(0x5245_4401);
		const s0 = w.getPolySlot0();
		for (let trial = 0; trial < 50; trial++) {
			const poly = randPoly(Q, rand);
			// Use wider range to stress the reduction — include values up to 2q
			for (let i = 0; i < N; i++) poly[i] = (rand() % (2 * Q)) - Q;
			writePoly(poly, s0);
			w.poly_reduce(s0);
			const got = readPoly(s0);
			for (let i = 0; i < N; i++) {
				const expected = i16(w.barrett_reduce(poly[i]));
				if (got[i] !== expected) {
					throw new Error(
						`trial=${trial} coeff[${i}]: got=${got[i]} expected=${expected}`,
					);
				}
			}
		}
	});

	test('poly_ntt (SIMD): matches scalar ntt + element-wise barrett_reduce', () => {
		const w = getWasm();
		const rand = prng(0x4E54_5401);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		for (let trial = 0; trial < 50; trial++) {
			const poly = randPoly(Q, rand);
			writePoly(poly, s0);
			writePoly(poly, s1);

			// SIMD poly_ntt
			w.poly_ntt(s0);

			// Reference: scalar ntt then element-wise reduce
			w.ntt_scalar(s1);
			const refCoeffs = readPoly(s1).map(c => i16(w.barrett_reduce(c)));

			const got = readPoly(s0);
			for (let i = 0; i < N; i++) {
				if (got[i] !== refCoeffs[i]) {
					throw new Error(
						`trial=${trial} coeff[${i}]: got=${got[i]} ref=${refCoeffs[i]}`,
					);
				}
			}
		}
	});

	test('poly_invntt (SIMD): matches scalar invntt', () => {
		const w = getWasm();
		const rand = prng(0x494E_5401);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		for (let trial = 0; trial < 50; trial++) {
			// Build a valid NTT-domain polynomial
			const poly = randPoly(Q, rand);
			writePoly(poly, s0);
			w.ntt_scalar(s0);
			const nttPoly = readPoly(s0);

			writePoly(nttPoly, s0);
			writePoly(nttPoly, s1);

			w.poly_invntt(s0);
			w.invntt_scalar(s1);

			const got = readPoly(s0);
			const ref = readPoly(s1);
			for (let i = 0; i < N; i++) {
				if (got[i] !== ref[i]) {
					throw new Error(
						`trial=${trial} coeff[${i}]: got=${got[i]} ref=${ref[i]}`,
					);
				}
			}
		}
	});
});
