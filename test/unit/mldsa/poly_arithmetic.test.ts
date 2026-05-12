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
// test/unit/mldsa/poly_arithmetic.test.ts
//
// GATE: ML-DSA polynomial arithmetic, add, sub, reduce, caddq, pointwise
// Montgomery multiply, chknorm. Property-based against the spec definitions
// (FIPS 204 §7.6 Algorithms 44-45 and §2.3 mod± q / norm definitions).
//
// The pointwise-multiply round-trip gate verifies NTT-domain multiplication
// matches schoolbook multiplication mod (X²⁵⁶ + 1) mod q over a randomised
// batch, the same kind of cross-check used to validate Kyber's basemul.

import { describe, test, expect, beforeAll } from 'vitest';
import { loadMldsa, getWasm, readPoly, writePoly, prng, modQ } from './helpers.js';

const Q  = 8380417;
const N  = 256;
const HALF_Q = (Q - 1) / 2;
const R  = 1n << 32n;
const Q_BIG  = BigInt(Q);

beforeAll(async () => {
	await loadMldsa();
});

// ── Helpers ─────────────────────────────────────────────────────────────────

function zeroPoly(): number[] {
	return new Array<number>(N).fill(0);
}

function randCoeffs(rand: () => number, mag: number, signed = false): number[] {
	const out: number[] = new Array(N);
	for (let i = 0; i < N; i++) {
		const v = rand() % mag;
		out[i] = signed ? v - (mag >>> 1) : v;
	}
	return out;
}

/** Schoolbook multiplication mod (X²⁵⁶ + 1) over Z_q, in regular form. */
function schoolbookMul(a: number[], b: number[]): number[] {
	const out: bigint[] = new Array(N).fill(0n);
	for (let i = 0; i < N; i++) {
		const ai = BigInt(a[i]);
		for (let j = 0; j < N; j++) {
			const bj = BigInt(b[j]);
			const k = i + j;
			if (k < N) {
				out[k] = out[k] + ai * bj;
			} else {
				// X²⁵⁶ = -1 in R_q
				out[k - N] = out[k - N] - ai * bj;
			}
		}
	}
	return out.map(v => Number(((v % Q_BIG) + Q_BIG) % Q_BIG));
}

// ── GATE: poly_add ──────────────────────────────────────────────────────────

describe('Gate, poly_add (FIPS 204 Algorithm 44, coefficient-wise)', () => {
	test('add two known polynomials, coefficient-wise sum without reduction', () => {
		const w = getWasm();
		const A = w.getPolySlot0(), B = w.getPolySlot1(), R0 = w.getPolySlot2();
		const a = zeroPoly(); a[0] = 100; a[1] = -50; a[255] = Q - 1;
		const b = zeroPoly(); b[0] = 200; b[1] = 50;  b[255] = 1;
		writePoly(a, A); writePoly(b, B);
		w.poly_add(R0, A, B);
		const r = readPoly(R0);
		expect(r[0]).toBe(300);
		expect(r[1]).toBe(0);
		expect(r[255]).toBe(Q);  // intentional: no reduction
	});

	test('30 random adds match coefficient-wise integer sum', () => {
		const w = getWasm();
		const rand = prng(0x41444D44);  // 'ADMD'
		const A = w.getPolySlot0(), B = w.getPolySlot1(), R0 = w.getPolySlot2();
		for (let trial = 0; trial < 30; trial++) {
			const a = randCoeffs(rand, Q, true);
			const b = randCoeffs(rand, Q, true);
			writePoly(a, A); writePoly(b, B);
			w.poly_add(R0, A, B);
			const r = readPoly(R0);
			for (let i = 0; i < N; i++) expect(r[i]).toBe(a[i] + b[i]);
		}
	});
});

// ── GATE: poly_sub ──────────────────────────────────────────────────────────

describe('Gate, poly_sub', () => {
	test('30 random subs match coefficient-wise integer difference', () => {
		const w = getWasm();
		const rand = prng(0x53554244);  // 'SUBD'
		const A = w.getPolySlot0(), B = w.getPolySlot1(), R0 = w.getPolySlot2();
		for (let trial = 0; trial < 30; trial++) {
			const a = randCoeffs(rand, Q, true);
			const b = randCoeffs(rand, Q, true);
			writePoly(a, A); writePoly(b, B);
			w.poly_sub(R0, A, B);
			const r = readPoly(R0);
			for (let i = 0; i < N; i++) expect(r[i]).toBe(a[i] - b[i]);
		}
	});
});

// ── GATE: poly_reduce ──────────────────────────────────────────────────────

describe('Gate, poly_reduce (centered Barrett, FIPS 204 §2.3 mod± q)', () => {
	test('every output coefficient lies in [-(q-1)/2, (q-1)/2] and is ≡ input mod q', () => {
		const w = getWasm();
		const rand = prng(0x52454443);  // 'REDC'
		const A = w.getPolySlot0();
		for (let trial = 0; trial < 20; trial++) {
			// Use unbounded i32 inputs so reduce has real work to do.
			const a: number[] = new Array(N);
			for (let i = 0; i < N; i++) a[i] = (rand() | 0);  // i32-cast
			writePoly(a, A);
			w.poly_reduce(A);
			const r = readPoly(A);
			for (let i = 0; i < N; i++) {
				expect(r[i]).toBeGreaterThanOrEqual(-HALF_Q);
				expect(r[i]).toBeLessThanOrEqual(HALF_Q);
				const diff = a[i] - r[i];
				expect(((diff % Q) + Q) % Q).toBe(0);
			}
		}
	});
});

// ── GATE: poly_caddq ───────────────────────────────────────────────────────

describe('Gate, poly_caddq (canonicalise to [0, q-1])', () => {
	test('negatives gain +q, non-negatives unchanged', () => {
		const w = getWasm();
		const A = w.getPolySlot0();
		const a = zeroPoly();
		a[0] = -1; a[1] = -(Q - 1); a[2] = 0; a[3] = Q - 1; a[4] = -HALF_Q;
		writePoly(a, A);
		w.poly_caddq(A);
		const r = readPoly(A);
		expect(r[0]).toBe(Q - 1);
		expect(r[1]).toBe(1);
		expect(r[2]).toBe(0);
		expect(r[3]).toBe(Q - 1);
		expect(r[4]).toBe(Q - HALF_Q);
	});
});

// ── GATE: poly_pointwise_montgomery ────────────────────────────────────────

describe('Gate, poly_pointwise_montgomery (FIPS 204 Algorithm 45)', () => {
	test('coefficient-wise: c[i] = montgomery_reduce(a[i] · b[i])', () => {
		const w = getWasm();
		const rand = prng(0x504D4F4E);  // 'PMON'
		const A = w.getPolySlot0(), B = w.getPolySlot1(), R0 = w.getPolySlot2();
		const a = randCoeffs(rand, Q, false);
		const b = randCoeffs(rand, Q, false);
		writePoly(a, A); writePoly(b, B);
		w.poly_pointwise_montgomery(R0, A, B);
		const r = readPoly(R0);
		for (let i = 0; i < N; i++) {
			const expected = w.montgomery_reduce(BigInt(a[i]) * BigInt(b[i]));
			expect(r[i]).toBe(expected);
		}
	});

	test('NTT round-trip: invntt(NTT(a) ◦ tomont(NTT(b))) ≡ schoolbook(a, b)', () => {
		const w = getWasm();
		const rand = prng(0x4E545452);  // 'NTTR'
		// Use small coefficients to keep schoolbook cheap and the NTT outputs
		// well within i32. The round-trip works for any inputs in [0, q-1].
		const A = w.getPolySlot0(), B = w.getPolySlot1();
		const C = w.getPolySlot2();    // NTT(a) ◦ tomont(NTT(b))
		const a: number[] = new Array(N).fill(0).map(() => rand() % 13 - 6);
		const b: number[] = new Array(N).fill(0).map(() => rand() % 13 - 6);
		// Centered → canonical [0, q) for the round-trip.
		const aPos = a.map(v => modQ(v, Q));
		const bPos = b.map(v => modQ(v, Q));
		writePoly(aPos, A);
		writePoly(bPos, B);

		// Compute Â = NTT(a), B̂ = NTT(b). Both in regular (non-Mont) form per
		// our mldsa NTT convention (the closing fqmul cancels Mont factor).
		w.ntt(A);
		w.ntt(B);

		// poly_pointwise_montgomery(c, â, b̂) gives c[i] = montgomery_reduce(â[i]·b̂[i])
		// = â[i]·b̂[i]·R⁻¹. To obtain the regular-form Hadamard product â[i]·b̂[i],
		// we pre-scale b̂ by R = 2³². i.e. use b̂' = b̂ · R, then pointwise gives â·b̂.
		// Then invntt yields a*b in regular form.
		const Bmont = w.getPolySlot3();
		const bHat = readPoly(B);
		// Multiply each coefficient by R = 2³² mod q via mont mul with constant R²·R⁻¹ = R.
		// Easiest: store R-scaled values directly using BigInt math, then write back.
		const bHatMont = bHat.map(v => Number((BigInt(v) * R) % Q_BIG));
		writePoly(bHatMont, Bmont);
		w.poly_pointwise_montgomery(C, A, Bmont);
		w.invntt(C);
		w.poly_freeze(C);  // canonicalise to [0, q)

		const got = readPoly(C);
		const want = schoolbookMul(aPos, bPos);
		for (let i = 0; i < N; i++) {
			expect(got[i]).toBe(want[i]);
		}
	});
});

// ── GATE: poly_chknorm ─────────────────────────────────────────────────────

describe('Gate, poly_chknorm (||·||∞ < bound, FIPS 204 §2.3)', () => {
	test('all-zero polynomial passes any positive bound', () => {
		const w = getWasm();
		const A = w.getPolySlot0();
		writePoly(zeroPoly(), A);
		expect(w.poly_chknorm(A, 1)).toBe(0);
		expect(w.poly_chknorm(A, 100000)).toBe(0);
	});

	test('boundary: |c| == bound triggers, |c| == bound-1 does not', () => {
		const w = getWasm();
		const A = w.getPolySlot0();
		const a = zeroPoly(); a[100] = 50;
		writePoly(a, A);
		expect(w.poly_chknorm(A, 51)).toBe(0);
		expect(w.poly_chknorm(A, 50)).toBe(1);
		// Negative side
		a[100] = -50;
		writePoly(a, A);
		expect(w.poly_chknorm(A, 51)).toBe(0);
		expect(w.poly_chknorm(A, 50)).toBe(1);
	});
});
