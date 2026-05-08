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
// test/unit/mldsa/sampling.test.ts
//
// GATE: ML-DSA rejection sampling kernels.
//   • rej_ntt_poly       — FIPS 204 Algorithm 30 (CoeffFromThreeBytes per group)
//   • rej_bounded_poly   — FIPS 204 Algorithm 31 (CoeffFromHalfByte per nibble)
//   • sample_in_ball     — FIPS 204 Algorithm 29 (Fisher-Yates over signs/positions)
//
// The expected coefficient values for the rej_ntt_poly gate are derived
// independently from the spec definition (Algorithm 14, CoeffFromThreeBytes)
// — NOT copied from the implementation output.

import { describe, test, expect, beforeAll } from 'vitest';
import { loadMldsa, getWasm, readPoly, writeBytes, prng } from './helpers.js';

const Q = 8380417;
const N = 256;

beforeAll(async () => {
	await loadMldsa();
});

// ── GATE: rej_ntt_poly ─────────────────────────────────────────────────────

describe('Gate — rej_ntt_poly (FIPS 204 Algorithm 30, inner)', () => {
	// CoeffFromThreeBytes(b0, b1, b2):
	//   z = ((b2 & 0x7F) << 16) | (b1 << 8) | b0
	//   if z < q: accept, else reject.
	function expectedAcceptedCoeffs(buf: Uint8Array): number[] {
		const out: number[] = [];
		for (let p = 0; p + 3 <= buf.length; p += 3) {
			const z = ((buf[p + 2] & 0x7F) << 16) | (buf[p + 1] << 8) | buf[p];
			if (z < Q) out.push(z);
		}
		return out;
	}

	test('hand-crafted byte stream: every accepted coefficient matches CoeffFromThreeBytes', () => {
		const w = getWasm();
		const POLY = w.getPolySlot0();
		const BUF  = w.getXofPrfOffset();
		// Mix of clearly-in-range and clearly-out-of-range candidates.
		const bytes = new Uint8Array([
			0x00, 0x00, 0x00,    //   z = 0          → accept
			0x01, 0x00, 0x00,    //   z = 1          → accept
			0x00, 0x00, 0x01,    //   z = 2¹⁶        → accept
			0xFF, 0xFF, 0x7F,    //   z = 2²³ − 1    → reject (≥ q)
			0x00, 0x00, 0x80,    //   z = 0 (top bit cleared) → accept
			0x00, 0x00, 0x40,    //   z = 0x400000 = 4194304 → accept (< q = 8380417)
		]);
		writeBytes(bytes, BUF);
		const ctr = w.rej_ntt_poly(POLY, 0, BUF, bytes.length);
		const want = expectedAcceptedCoeffs(bytes);
		expect(ctr).toBe(want.length);
		const got = readPoly(POLY).slice(0, ctr);
		for (let i = 0; i < ctr; i++) expect(got[i]).toBe(want[i]);
	});

	test('1024 random bytes: result matches independent CoeffFromThreeBytes scan', () => {
		const w = getWasm();
		const POLY = w.getPolySlot0();
		const BUF  = w.getXofPrfOffset();
		const rand = prng(0x52454A4E);  // 'REJN'
		const bytes = new Uint8Array(1024);
		for (let i = 0; i < bytes.length; i++) bytes[i] = rand() & 0xFF;
		writeBytes(bytes, BUF);
		const ctr = w.rej_ntt_poly(POLY, 0, BUF, bytes.length);
		const want = expectedAcceptedCoeffs(bytes).slice(0, N);
		// rej_ntt_poly stops when N coefficients are accepted, so cap.
		expect(ctr).toBe(Math.min(want.length, N));
		const got = readPoly(POLY).slice(0, ctr);
		for (let i = 0; i < ctr; i++) expect(got[i]).toBe(want[i]);
	});

	test('resumable: two-call ctr accumulates correctly', () => {
		const w = getWasm();
		const POLY = w.getPolySlot0();
		const BUF  = w.getXofPrfOffset();
		const rand = prng(0x4E5232);    // 'NR2'
		const bytes = new Uint8Array(2048);
		for (let i = 0; i < bytes.length; i++) bytes[i] = rand() & 0xFF;
		const half = bytes.length / 2;
		writeBytes(bytes.slice(0, half), BUF);
		const c1 = w.rej_ntt_poly(POLY, 0, BUF, half);
		writeBytes(bytes.slice(half), BUF);
		const c2 = w.rej_ntt_poly(POLY, c1, BUF, half);
		// Total accepted should equal what a single concatenated scan produces,
		// up to N.
		const want = expectedAcceptedCoeffs(bytes).slice(0, N);
		expect(c1 + c2).toBe(Math.min(want.length, N));
	});
});

// ── GATE: rej_bounded_poly ─────────────────────────────────────────────────

describe('Gate — rej_bounded_poly (FIPS 204 Algorithm 31, inner)', () => {
	function expectedEta2(buf: Uint8Array): number[] {
		const out: number[] = [];
		for (let i = 0; i < buf.length && out.length < N; i++) {
			const z = buf[i];
			const z0 = z & 0x0F;
			const z1 = z >> 4;
			if (z0 < 15) out.push(2 - (z0 % 5));
			if (out.length < N && z1 < 15) out.push(2 - (z1 % 5));
		}
		return out;
	}

	function expectedEta4(buf: Uint8Array): number[] {
		const out: number[] = [];
		for (let i = 0; i < buf.length && out.length < N; i++) {
			const z = buf[i];
			const z0 = z & 0x0F;
			const z1 = z >> 4;
			if (z0 < 9) out.push(4 - z0);
			if (out.length < N && z1 < 9) out.push(4 - z1);
		}
		return out;
	}

	test('η = 2: acceptance set matches CoeffFromHalfByte (b < 15 → 2 − (b mod 5))', () => {
		const w = getWasm();
		const POLY = w.getPolySlot0();
		const BUF  = w.getXofPrfOffset();
		const rand = prng(0x45544132);  // 'ETA2'
		const bytes = new Uint8Array(512);
		for (let i = 0; i < bytes.length; i++) bytes[i] = rand() & 0xFF;
		writeBytes(bytes, BUF);
		const ctr = w.rej_bounded_poly(POLY, 0, BUF, bytes.length, 2);
		const want = expectedEta2(bytes);
		expect(ctr).toBe(Math.min(want.length, N));
		const got = readPoly(POLY).slice(0, ctr);
		for (let i = 0; i < ctr; i++) expect(got[i]).toBe(want[i]);
		// All coefficients in [-2, 2].
		for (const v of got) {
			expect(v).toBeGreaterThanOrEqual(-2);
			expect(v).toBeLessThanOrEqual(2);
		}
	});

	test('η = 4: acceptance set matches CoeffFromHalfByte (b < 9 → 4 − b)', () => {
		const w = getWasm();
		const POLY = w.getPolySlot0();
		const BUF  = w.getXofPrfOffset();
		const rand = prng(0x45544134);  // 'ETA4'
		const bytes = new Uint8Array(512);
		for (let i = 0; i < bytes.length; i++) bytes[i] = rand() & 0xFF;
		writeBytes(bytes, BUF);
		const ctr = w.rej_bounded_poly(POLY, 0, BUF, bytes.length, 4);
		const want = expectedEta4(bytes);
		expect(ctr).toBe(Math.min(want.length, N));
		const got = readPoly(POLY).slice(0, ctr);
		for (let i = 0; i < ctr; i++) expect(got[i]).toBe(want[i]);
		for (const v of got) {
			expect(v).toBeGreaterThanOrEqual(-4);
			expect(v).toBeLessThanOrEqual(4);
		}
	});
});

// ── GATE: sample_in_ball ───────────────────────────────────────────────────

describe('Gate — sample_in_ball (FIPS 204 Algorithm 29)', () => {
	for (const tau of [39, 49, 60]) {
		test(`τ = ${tau}: output has exactly τ ±1 coefficients, rest zero`, () => {
			const w = getWasm();
			const POLY = w.getPolySlot0();
			const SIGNS = w.getXofPrfOffset();          // 8 bytes
			const POSBUF = w.getXofPrfOffset() + 8;     // remainder
			// Zero the polynomial first.
			writeBytes(new Uint8Array(N * 4), POLY);

			const rand = prng(0x53494220 + tau);        // 'SIB ' + τ
			const signs = new Uint8Array(8);
			for (let i = 0; i < 8; i++) signs[i] = rand() & 0xFF;
			writeBytes(signs, SIGNS);

			// 256 bytes is more than enough for any τ ≤ 64 with overwhelming
			// probability — see SampleInBall byte-budget discussion in
			// sampling.ts header.
			const posBytes = new Uint8Array(256);
			for (let i = 0; i < posBytes.length; i++) posBytes[i] = rand() & 0xFF;
			writeBytes(posBytes, POSBUF);

			const ret = w.sample_in_ball(POLY, SIGNS, POSBUF, posBytes.length, tau, N - tau);
			expect(ret).toBe(N);

			const c = readPoly(POLY);
			let nonZero = 0;
			for (let i = 0; i < N; i++) {
				if (c[i] !== 0) {
					expect(c[i] === 1 || c[i] === -1).toBe(true);
					nonZero++;
				}
			}
			expect(nonZero).toBe(tau);
		});
	}

	test('resumable: returning < N lets caller squeeze more bytes and continue', () => {
		const w = getWasm();
		const POLY = w.getPolySlot0();
		const SIGNS = w.getXofPrfOffset();
		const POSBUF = w.getXofPrfOffset() + 8;

		writeBytes(new Uint8Array(N * 4), POLY);
		const tau = 60;

		// All-zero signs: every nonzero coefficient is +1.
		writeBytes(new Uint8Array(8), SIGNS);

		// Provide only 30 position bytes: exact ascending sequence so each is
		// guaranteed accepted on first try (j ≤ i always).
		const partial = new Uint8Array(30);
		for (let i = 0; i < partial.length; i++) partial[i] = i;
		writeBytes(partial, POSBUF);

		const r1 = w.sample_in_ball(POLY, SIGNS, POSBUF, partial.length, tau, N - tau);
		// We started at i = N - τ = 196 and have 30 bytes accepted, so i = 226.
		expect(r1).toBe(N - tau + 30);

		// Now squeeze the remaining 30 bytes.
		const more = new Uint8Array(30);
		for (let i = 0; i < more.length; i++) more[i] = 30 + i;
		writeBytes(more, POSBUF);
		const r2 = w.sample_in_ball(POLY, SIGNS, POSBUF, more.length, tau, r1);
		expect(r2).toBe(N);

		const c = readPoly(POLY);
		let nonZero = 0;
		for (const v of c) {
			if (v !== 0) {
				expect(v).toBe(1);   // signs all 0 ⇒ all +1
				nonZero++;
			}
		}
		expect(nonZero).toBe(tau);
	});
});
