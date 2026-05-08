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
// test/unit/mldsa/rounding.test.ts
//
// GATE: ML-DSA rounding kernels — Power2Round, Decompose, HighBits, LowBits,
// MakeHint, UseHint (FIPS 204 §7.4 Algorithms 35–40). Each kernel is property-
// tested against the spec's algebraic identity over a randomised batch.

import { describe, test, expect, beforeAll } from 'vitest';
import { loadMldsa, getWasm, readPoly, writePoly, prng } from './helpers.js';

const Q = 8380417;
const N = 256;
const D = 13;
const TWO_D = 1 << D;
const HALF_TWO_D = 1 << (D - 1);

// γ₂ for parameter sets:
const GAMMA2_44 = (Q - 1) / 88;     // 95232  (ML-DSA-44)
const GAMMA2_65_87 = (Q - 1) / 32;  // 261888 (ML-DSA-65 / ML-DSA-87)

beforeAll(async () => {
	await loadMldsa();
});

// ── GATE: power2round ──────────────────────────────────────────────────────

describe('Gate — power2round (FIPS 204 Algorithm 35)', () => {
	test('identity r ≡ r1·2^d + r0 (mod q) and r0 ∈ (-2^(d-1), 2^(d-1)]', () => {
		const w = getWasm();
		const A = w.getPolySlot0(), R1 = w.getPolySlot1(), R0 = w.getPolySlot2();
		const rand = prng(0x50325244);  // 'P2RD'
		const a: number[] = new Array(N);
		// Hand-pick boundary cases plus randomised bulk.
		a[0] = 0;
		a[1] = Q - 1;
		a[2] = HALF_TWO_D;             // r0 = 4096 boundary (inclusive upper)
		a[3] = HALF_TWO_D + 1;         // r0 should wrap to negative
		a[4] = TWO_D;                  // r1 = 1, r0 = 0
		for (let i = 5; i < N; i++) a[i] = rand() % Q;
		writePoly(a, A);
		w.power2round(R1, R0, A);
		const r1 = readPoly(R1);
		const r0 = readPoly(R0);
		for (let i = 0; i < N; i++) {
			// r0 in (-2^(d-1), 2^(d-1)]
			expect(r0[i]).toBeGreaterThan(-HALF_TWO_D);
			expect(r0[i]).toBeLessThanOrEqual(HALF_TWO_D);
			// r1 in [0, ⌈(q-1)/2^d⌉]
			expect(r1[i]).toBeGreaterThanOrEqual(0);
			expect(r1[i]).toBeLessThan(1 << 10);
			// r ≡ r1·2^d + r0 (mod q)
			const recon = ((BigInt(r1[i]) * BigInt(TWO_D) + BigInt(r0[i])) % BigInt(Q) + BigInt(Q)) % BigInt(Q);
			expect(Number(recon)).toBe(a[i]);
		}
	});
});

// ── GATE: decompose ────────────────────────────────────────────────────────

describe('Gate — decompose (FIPS 204 Algorithm 36)', () => {
	for (const gamma2 of [GAMMA2_44, GAMMA2_65_87]) {
		test(`γ₂ = ${gamma2}: identity r ≡ r1·2γ₂ + r0 (mod q)`, () => {
			const w = getWasm();
			const A = w.getPolySlot0(), R1 = w.getPolySlot1(), R0 = w.getPolySlot2();
			const rand = prng(0x44434D50 ^ gamma2);  // 'DCMP' ^ γ₂
			const a: number[] = new Array(N);
			// Boundary plus randomised.
			a[0] = 0;
			a[1] = Q - 1;
			a[2] = gamma2;
			a[3] = gamma2 + 1;
			a[4] = 2 * gamma2;
			a[5] = Q - 1 - gamma2 + 1;   // close to wrap boundary
			for (let i = 6; i < N; i++) a[i] = rand() % Q;
			writePoly(a, A);
			w.decompose(R1, R0, A, gamma2);
			const r1 = readPoly(R1);
			const r0 = readPoly(R0);
			const m = (Q - 1) / (2 * gamma2);
			for (let i = 0; i < N; i++) {
				// r1 ∈ [0, m). Spec also allows r1 = 0 with r0 = -1 in the wrap case.
				expect(r1[i]).toBeGreaterThanOrEqual(0);
				expect(r1[i]).toBeLessThan(m);
				// Reconstruction r ≡ r1·2γ₂ + r0 (mod q).
				const recon = ((BigInt(r1[i]) * BigInt(2 * gamma2) + BigInt(r0[i])) % BigInt(Q) + BigInt(Q)) % BigInt(Q);
				expect(Number(recon)).toBe(a[i]);
			}
		});
	}
});

// ── GATE: highbits / lowbits ──────────────────────────────────────────────

describe('Gate — highbits / lowbits (FIPS 204 Algorithms 37, 38)', () => {
	test('highbits == decompose.r1 and lowbits == decompose.r0', () => {
		const w = getWasm();
		const A = w.getPolySlot0();
		const R1_DEC = w.getPolySlot1(), R0_DEC = w.getPolySlot2();
		const HB     = w.getPolySlot3(), LB     = w.getPolySlot4();
		const rand = prng(0x484C4253);  // 'HLBS'
		const a: number[] = new Array(N);
		for (let i = 0; i < N; i++) a[i] = rand() % Q;
		writePoly(a, A);
		w.decompose(R1_DEC, R0_DEC, A, GAMMA2_65_87);
		w.highbits(HB, A, GAMMA2_65_87);
		w.lowbits(LB, A, GAMMA2_65_87);
		const r1 = readPoly(R1_DEC);
		const r0 = readPoly(R0_DEC);
		const hb = readPoly(HB);
		const lb = readPoly(LB);
		for (let i = 0; i < N; i++) {
			expect(hb[i]).toBe(r1[i]);
			expect(lb[i]).toBe(r0[i]);
		}
	});
});

// ── GATE: make_hint / use_hint ────────────────────────────────────────────

describe('Gate — make_hint / use_hint (FIPS 204 Algorithms 39, 40)', () => {
	// FIPS 204 Lemma (per Dilithium spec §2.4): if make_hint(z, w − z) = h then
	// use_hint(h, w − z) = HighBits(w). This is the round-trip identity that
	// the verification path relies on.
	test('round-trip: use_hint(make_hint(z, w-z), w-z) == HighBits(w) for small z', () => {
		const w = getWasm();
		const W      = w.getPolySlot0();   // w
		const Z      = w.getPolySlot1();   // z (small)
		const WMZ    = w.getPolySlot2();   // w - z (input to use_hint and make_hint's r)
		const H      = w.getPolySlot3();   // hint
		const USEH   = w.getPolySlot4();   // use_hint output
		const HBW    = w.getPolySlot5();   // HighBits(w)
		const rand = prng(0x4D4B4855);  // 'MKHU'
		const gamma2 = GAMMA2_65_87;
		const beta = gamma2 - 1;        // |z| < γ₂ keeps the hint round-trip valid
		const wPoly: number[] = new Array(N);
		const zPoly: number[] = new Array(N);
		const wmz:   number[] = new Array(N);
		for (let i = 0; i < N; i++) {
			wPoly[i] = rand() % Q;
			// z is small; magnitude up to γ₂ - 1 (but stays in canonical [0, q)
			// post-mod for the highbits domain).
			const zSmall = (rand() % (2 * beta + 1)) - beta;
			zPoly[i] = ((zSmall % Q) + Q) % Q;
			wmz[i]   = ((wPoly[i] - zPoly[i]) % Q + Q) % Q;
		}
		writePoly(wPoly, W);
		writePoly(zPoly, Z);
		writePoly(wmz, WMZ);

		// Per Alg 39 the hint is computed as h = make_hint(z, r) with r = w - z.
		// Spec line 1: r1 = HighBits(r); line 2: v1 = HighBits(r + z) = HighBits(w);
		// line 3: return [[r1 ≠ v1]].
		w.make_hint(H, Z, WMZ, gamma2);
		// Verifier-side: use_hint(h, w - z) should recover HighBits(w).
		w.use_hint(USEH, H, WMZ, gamma2);
		w.highbits(HBW, W, gamma2);

		const got  = readPoly(USEH);
		const want = readPoly(HBW);
		for (let i = 0; i < N; i++) expect(got[i]).toBe(want[i]);
	});

	test('make_hint = 0 iff HighBits(r) == HighBits(r+z) (definition)', () => {
		const w = getWasm();
		const Z      = w.getPolySlot0();
		const R      = w.getPolySlot1();
		const RZ     = w.getPolySlot2();   // r + z mod q
		const H      = w.getPolySlot3();
		const HBR    = w.getPolySlot4();
		const HBRZ   = w.getPolySlot5();
		const rand = prng(0x4D4B4830);  // 'MKH0'
		const gamma2 = GAMMA2_65_87;
		const r:  number[] = new Array(N);
		const z:  number[] = new Array(N);
		const rz: number[] = new Array(N);
		for (let i = 0; i < N; i++) {
			r[i]  = rand() % Q;
			const zSmall = (rand() % (2 * gamma2 + 1)) - gamma2;
			z[i]  = ((zSmall % Q) + Q) % Q;
			rz[i] = ((r[i] + z[i]) % Q + Q) % Q;
		}
		writePoly(r, R); writePoly(z, Z); writePoly(rz, RZ);
		w.make_hint(H, Z, R, gamma2);
		w.highbits(HBR, R, gamma2);
		w.highbits(HBRZ, RZ, gamma2);
		const h    = readPoly(H);
		const hbr  = readPoly(HBR);
		const hbrz = readPoly(HBRZ);
		for (let i = 0; i < N; i++) {
			expect(h[i]).toBe(hbr[i] === hbrz[i] ? 0 : 1);
		}
	});
});
