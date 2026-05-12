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
// test/unit/mldsa/ntt_simd_gate.test.ts
//
// GATE: ML-DSA SIMD NTT == scalar NTT for 100 random polys
// GATE: ML-DSA NTT round-trip identity (invntt(ntt(p)) == p)
//
// FIPS 204 Algorithms 41 (NTT) and 42 (NTT⁻¹). The SIMD path (ntt_simd /
// invntt_simd) is the production export under the public `ntt` / `invntt`
// aliases; the scalar path (`ntt_scalar` / `invntt_scalar`) is exposed for
// these gates only.

import { describe, test, expect, beforeAll } from 'vitest';
import { loadMldsa, getWasm, readPoly, writePoly, prng, randPoly, modQ } from './helpers.js';

const Q = 8380417;
const N = 256;

beforeAll(async () => {
	await loadMldsa();
});

// GATE: ML-DSA SIMD NTT == scalar NTT for 100 random polys

describe('Gate 1, SIMD NTT matches scalar NTT', () => {

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

	test('ntt (SIMD) == ntt_scalar for delta polynomial (coeff[42] = 1)', () => {
		const w = getWasm();
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const poly = new Array(N).fill(0);
		poly[42] = 1;
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
			// Build a valid NTT-domain poly via the scalar forward NTT
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
});

// GATE: ML-DSA NTT round-trip identity

describe('Gate 2, NTT round-trip recovers input', () => {

	test('invntt(ntt(p)) ≡ p (mod q) for 100 random polynomials', () => {
		const w = getWasm();
		const rand = prng(0x5254_5501);
		const s0 = w.getPolySlot0();
		for (let trial = 0; trial < 100; trial++) {
			const original = randPoly(Q, rand);
			writePoly(original, s0);
			w.ntt(s0);
			w.invntt(s0);
			const recovered = readPoly(s0);
			for (let i = 0; i < N; i++) {
				if (modQ(original[i], Q) !== modQ(recovered[i], Q)) {
					throw new Error(
						`trial=${trial} coeff[${i}]: original=${original[i]} `
						+ `recovered=${recovered[i]} (mod q: ${modQ(recovered[i], Q)})`,
					);
				}
			}
		}
	});

	test('invntt_scalar(ntt_scalar(p)) ≡ p (mod q) for 100 random polynomials', () => {
		const w = getWasm();
		const rand = prng(0x5254_5302);
		const s0 = w.getPolySlot0();
		for (let trial = 0; trial < 100; trial++) {
			const original = randPoly(Q, rand);
			writePoly(original, s0);
			w.ntt_scalar(s0);
			w.invntt_scalar(s0);
			const recovered = readPoly(s0);
			for (let i = 0; i < N; i++) {
				if (modQ(original[i], Q) !== modQ(recovered[i], Q)) {
					throw new Error(
						`trial=${trial} coeff[${i}]: original=${original[i]} `
						+ `recovered=${recovered[i]} (mod q: ${modQ(recovered[i], Q)})`,
					);
				}
			}
		}
	});
});

// Smoke check, Appendix B / §2.5 sanity:
//   - zetas[128] (Montgomery form) corresponds to ζ¹ = 1753 in regular form.
//   - BitRev8(128) = 1, BitRev8(1) = 128.

describe('Sanity, zetas table & BitRev8', () => {
	test('BitRev8 fixed points', () => {
		const w = getWasm();
		expect(w.BitRev8(0)).toBe(0);
		expect(w.BitRev8(1)).toBe(128);
		expect(w.BitRev8(128)).toBe(1);
		expect(w.BitRev8(255)).toBe(255);
		expect(w.BitRev8(0b10110010)).toBe(0b01001101);
	});

	test('zetas[0] = 0 (line 5 of Algorithm 41 starts m at 0; zetas[0] is unused)', () => {
		expect(getWasm().getZeta(0)).toBe(0);
	});

	test('zetas[128] in Montgomery form decodes to ζ = 1753', () => {
		// zetas[128] · 2⁻³² mod q = 1753, since BitRev8(128) = 1.
		// Use montgomery_reduce(zetas[128]) which gives zetas[128] · 2⁻³² mod q
		// (with magnitude < 2q; reduce to canonical residue in [0, q)).
		const w = getWasm();
		const zRaw = w.getZeta(128);
		const r = w.montgomery_reduce(BigInt(zRaw));
		expect(modQ(r, Q)).toBe(1753);
	});

	// Audit-grade table check: every entry recomputed independently from
	// ζ=1753 + BitRev₈ in BigInt and compared byte-for-byte.
	//
	// The round-trip identity (Gate 2) only proves the forward/inverse pair
	// is internally consistent, it would pass for any internally-consistent
	// table, including a corrupted one. This test is the only one that
	// catches a corrupted table before phase-4 ACVP keygen vectors run.
	test('zetas[k] = ζ^BitRev₈(k) · 2³² mod q (centered) for k ∈ [1, 256)', () => {
		const w = getWasm();
		const qBig = BigInt(Q);
		const zeta = 1753n;
		const R    = 1n << 32n;
		const halfQ = qBig / 2n;  // (q-1)/2 since q is odd

		// Local BitRev8, kept independent of the WASM export so a bug in
		// either table or BitRev8 surfaces here rather than masking each
		// other.
		const bitRev8 = (m: number): number => {
			let r = 0;
			for (let i = 0; i < 8; i++) r |= ((m >> i) & 1) << (7 - i);
			return r;
		};

		expect(w.getZeta(0)).toBe(0);  // zetas[0] is the unused sentinel slot

		for (let k = 1; k < 256; k++) {
			const exp = bitRev8(k);
			let v = 1n;
			for (let i = 0; i < exp; i++) v = (v * zeta) % qBig;
			let mont = (v * R) % qBig;
			if (mont > halfQ) mont -= qBig;  // center to (-q/2, q/2]
			const got = w.getZeta(k);
			if (BigInt(got) !== mont) {
				throw new Error(
					`zetas[${k}] mismatch: got ${got}, expected ${mont} (BitRev₈(${k})=${exp})`,
				);
			}
		}
	});
});
