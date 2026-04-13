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
// test/unit/kyber/poly_arithmetic.test.ts
//
// Gate-based tests for the kyber WASM module. FIPS 203 ML-KEM polynomial
// arithmetic: reduce, NTT, serialization, compression, sampling, constant-time.
//
// Gates must pass in order — each gate is a prerequisite for the next.

import { describe, test, expect, beforeAll } from 'vitest';
import {
	loadKyber, getWasm, mem, readBytes, writeBytes,
	readPoly, writePoly, writePolyvec, readPolyvec,
	prng, randPoly, randBytes, i16,
} from './helpers.js';

const Q = 3329;
const N = 256;
const HALF_Q = 1665;
const QINV = -3327;
const MONT = -1044;  // 2^16 mod q centered = 2285 - 3329

beforeAll(async () => {
	await loadKyber();
});

// GATE: ML-KEM polynomial instantiation: module loads, memory is 3 pages

describe('Gate 1 — instantiation and buffer layout', () => {
	test('module loads and memory is 3 pages', () => {
		const w = getWasm();
		expect(w.memory).toBeDefined();
		expect(w.memory.buffer.byteLength).toBe(3 * 64 * 1024);
	});

	test('getModuleId returns 5', () => {
		expect(getWasm().getModuleId()).toBe(5);
	});

	test('getMemoryPages returns 3', () => {
		expect(getWasm().getMemoryPages()).toBe(3);
	});

	test('poly slots are distinct, non-overlapping, 512 bytes each', () => {
		const w = getWasm();
		const slots = [
			w.getPolySlot0(), w.getPolySlot1(), w.getPolySlot2(), w.getPolySlot3(),
			w.getPolySlot4(), w.getPolySlot5(), w.getPolySlot6(), w.getPolySlot7(),
			w.getPolySlot8(), w.getPolySlot9(),
		];
		const size = w.getPolySlotSize();
		expect(size).toBe(512);
		for (let i = 0; i < slots.length; i++) {
			for (let j = i + 1; j < slots.length; j++) {
				const a0 = slots[i], a1 = slots[i] + size;
				const b0 = slots[j], b1 = slots[j] + size;
				// Non-overlapping: [a0,a1) and [b0,b1) don't intersect
				expect(a1 <= b0 || b1 <= a0).toBe(true);
			}
		}
	});

	test('polyvec slots are distinct, non-overlapping, 2048 bytes each', () => {
		const w = getWasm();
		const slots = [
			w.getPolyvecSlot0(), w.getPolyvecSlot1(), w.getPolyvecSlot2(), w.getPolyvecSlot3(),
			w.getPolyvecSlot4(), w.getPolyvecSlot5(), w.getPolyvecSlot6(), w.getPolyvecSlot7(),
		];
		const size = w.getPolyvecSlotSize();
		expect(size).toBe(2048);
		for (let i = 0; i < slots.length; i++) {
			for (let j = i + 1; j < slots.length; j++) {
				const a0 = slots[i], a1 = slots[i] + size;
				const b0 = slots[j], b1 = slots[j] + size;
				expect(a1 <= b0 || b1 <= a0).toBe(true);
			}
		}
	});

	test('byte buffers do not overlap each other or slots', () => {
		const w = getWasm();
		const regions: [string, number, number][] = [
			['seed', w.getSeedOffset(),   32],
			['msg',  w.getMsgOffset(),    32],
			['pk',   w.getPkOffset(),     1568],
			['sk',   w.getSkOffset(),     1536],
			['ct',   w.getCtOffset(),     1568],
			['xof',  w.getXofPrfOffset(), 1024],
		];
		for (let i = 0; i < regions.length; i++) {
			for (let j = i + 1; j < regions.length; j++) {
				const [, a0, as] = regions[i];
				const [, b0, bs] = regions[j];
				const a1 = a0 + as, b1 = b0 + bs;
				expect(a1 <= b0 || b1 <= a0).toBe(true);
			}
		}
	});

	test('wipeBuffers() zeroes all mutable regions', () => {
		const w = getWasm();
		// Write known data into mutable region
		const start = w.getPolySlotBase();  // 4096
		const fill = new Uint8Array(100).fill(0xAB);
		mem().set(fill, start);
		mem().set(fill, w.getPolyvecSlot0());
		mem().set(fill, w.getSeedOffset());
		// Wipe
		w.wipeBuffers();
		// Verify zeros
		const after = mem().slice(start, start + 100);
		expect(Array.from(after).every(b => b === 0)).toBe(true);
		const pv = mem().slice(w.getPolyvecSlot0(), w.getPolyvecSlot0() + 100);
		expect(Array.from(pv).every(b => b === 0)).toBe(true);
		const seed = mem().slice(w.getSeedOffset(), w.getSeedOffset() + 32);
		expect(Array.from(seed).every(b => b === 0)).toBe(true);
	});
});

// GATE: ML-KEM polynomial arithmetic: Montgomery/Barrett reduce, fqmul, zetas

describe('Gate 2 — modular arithmetic', () => {
	test('QINV satisfies q * QINV ≡ 1 mod 2^16', () => {
		// QINV = -3327; q * QINV = 3329 * (-3327) ≡ 1 (mod 2^16)
		expect((Q * QINV) & 0xFFFF).toBe(1);
	});

	test('MONT equals 2^16 mod q centered', () => {
		// 2^16 mod 3329 = 2285; centered: 2285 - 3329 = -1044
		expect(2285 - Q).toBe(MONT);
		expect((1 << 16) % Q).toBe(2285);
	});

	test('montgomery_reduce(0) == 0', () => {
		expect(i16(getWasm().montgomery_reduce(0))).toBe(0);
	});

	test('montgomery_reduce satisfies a·R^{-1} mod q for valid inputs', () => {
		const w = getWasm();
		// R = 2^16, R_sq = R^2 mod q = (2^16)^2 mod 3329.
		// 2^16 mod 3329 = 2285. 2285^2 mod 3329 = 5220225 mod 3329.
		// 5220225 / 3329 ≈ 1568. 1568 * 3329 = 5219872. 5220225 - 5219872 = 353.
		// Verify: 2285 * 2285 = 5218225. Actually let me compute properly.
		// 2285^2 = 5_221_225. 5_221_225 mod 3329: 5_221_225 / 3329 = 1568.xxx
		// 1568 * 3329 = 5_219_872. 5_221_225 - 5_219_872 = 1353.
		// So R^2 mod q = 1353. montgomery_reduce(a * R_sq) == a * R mod q...
		// Actually: montgomery_reduce(a * R) = a*R * R^{-1} mod q = a mod q.
		// To test: montgomery_reduce((i32)a * R) should give a mod q for a in [0, q).
		// But R = 2^16 = 65536 and AS takes i32 input bounded in range.
		// Test: for a small set of known values.
		const _cases: [number, number][] = [
			[1, 1],           // montgomery_reduce(1 * 2^16) = 1 (if 2^16 mod q = MONT+q)
			[0, 0],
		];
		// Direct test: montgomery_reduce(a * R) mod q == a for a in [0, q)
		// But R = 65536 and a * R overflows i32 for a > 32767.
		// Test with small a where a * R fits in i32 range (a * 65536 < 2^31):
		// a < 32768.
		const R = (1 << 16);
		for (let a = 0; a < 50; a++) {
			const result = i16(w.montgomery_reduce(a * R));
			// montgomery_reduce(a * R) = a * R * R^{-1} mod q = a mod q
			// result should be a mod q (centered in [-(q-1), q-1])
			const expected = a % Q;
			// The output is in {-(q-1), ..., q-1} — could be negative if > q/2.
			// Since a < 50 < q, it won't be negative. Just check modular equivalence.
			expect(((result - expected) % Q + Q) % Q).toBe(0);
		}
	});

	test('barrett_reduce returns values in [-(q-1)/2, (q-1)/2]', () => {
		const w = getWasm();
		const rand = prng(0xBEEF_1234);
		const limit = (Q - 1) >> 1;  // 1664
		for (let trial = 0; trial < 500; trial++) {
			// Random i16 in [-32768, 32767]
			const a = i16((rand() & 0xFFFF));
			const result = i16(w.barrett_reduce(a));
			expect(result).toBeGreaterThanOrEqual(-limit);
			expect(result).toBeLessThanOrEqual(limit);
		}
	});

	test('barrett_reduce is idempotent', () => {
		const w = getWasm();
		const rand = prng(0xDEAD_C0DE);
		for (let trial = 0; trial < 200; trial++) {
			const a = i16((rand() & 0xFFFF));
			const once = i16(w.barrett_reduce(a));
			const twice = i16(w.barrett_reduce(once));
			expect(twice).toBe(once);
		}
	});

	test('barrett_reduce preserves residue class mod q', () => {
		const w = getWasm();
		const rand = prng(0xCAFE_BABE);
		for (let trial = 0; trial < 200; trial++) {
			const a = i16((rand() & 0xFFFF));
			const result = i16(w.barrett_reduce(a));
			// result ≡ a (mod q)
			expect(((a - result) % Q + Q) % Q).toBe(0);
		}
	});

	test('fqmul(a, b) == fqmul(b, a) for random a, b in [-(q-1), q-1]', () => {
		const w = getWasm();
		const rand = prng(0xF00D_1234);
		for (let trial = 0; trial < 100; trial++) {
			const a = i16(rand() % Q);
			const b = i16(rand() % Q);
			const ab = i16(w.fqmul(a, b));
			const ba = i16(w.fqmul(b, a));
			expect(ab).toBe(ba);
		}
	});

	test('fqmul(a, b) result is in {-(q-1), ..., q-1}', () => {
		const w = getWasm();
		const rand = prng(0x1234_5678);
		for (let trial = 0; trial < 200; trial++) {
			const a = i16(rand() % Q);
			const b = i16(rand() % Q);
			const result = i16(w.fqmul(a, b));
			expect(result).toBeGreaterThanOrEqual(-(Q - 1));
			expect(result).toBeLessThanOrEqual(Q - 1);
		}
	});
});

// GATE: ML-KEM NTT: FIPS 203 forward/inverse NTT roundtrip

describe('Gate 3 — NTT zetas and transforms', () => {
	// BitRev7: reverse the low 7 bits of i
	function bitRev7(i: number): number {
		let r = 0;
		for (let b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b);
		return r;
	}

	// modpow: a^exp mod m
	function modpow(base: number, exp: number, mod: number): number {
		let result = 1n;
		let b = BigInt(base), e = BigInt(exp); const m = BigInt(mod);
		b = b % m;
		while (e > 0n) {
			if (e & 1n) result = result * b % m;
			b = b * b % m;
			e >>= 1n;
		}
		return Number(result);
	}

	// Center a value in [-(q-1)/2, (q-1)/2]
	function center(x: number, q: number): number {
		const half = (q - 1) >> 1;
		if (x > half) return x - q;
		return x;
	}

	test('zetas table matches independently derived values (GATE)', () => {
		const w = getWasm();
		// ω = 17, q = 3329, R = 2^16 mod q = 2285
		const omega = 17, q = Q, R = 2285;
		for (let i = 0; i < 128; i++) {
			const power = bitRev7(i);
			// zeta = ω^power * R mod q, centered
			const raw = (modpow(omega, power, q) * R) % q;
			const expected = center(raw, q);
			const actual = i16(w.getZeta(i));
			expect(actual).toBe(expected);
		}
	});

	test('NTT of zero polynomial is zero', () => {
		const w = getWasm();
		const slot = w.getPolySlot0();
		w.wipeBuffers();
		w.poly_ntt(slot);
		const result = readPoly(slot);
		expect(result.every(c => c === 0)).toBe(true);
	});

	test('NTT roundtrip: invntt(ntt(f)) recovers f for 100 random polynomials', () => {
		const w = getWasm();
		const rand = prng(0x4E54_5444);
		const slot = w.getPolySlot0();

		for (let trial = 0; trial < 100; trial++) {
			const original = randPoly(Q, rand);
			writePoly(original, slot);
			w.poly_ntt(slot);
			w.poly_invntt(slot);
			w.poly_reduce(slot);
			const recovered = readPoly(slot);
			for (let i = 0; i < N; i++) {
				// invntt(ntt(f)) = f * R mod q (Montgomery domain).
				// Apply montgomery_reduce to remove the extra R factor.
				const normalized = i16(w.montgomery_reduce(recovered[i]));
				expect(((original[i] - normalized) % Q + Q) % Q).toBe(0);
			}
		}
	});

	test('NTT linearity: ntt(a+b) == ntt(a) + ntt(b) mod q', () => {
		const w = getWasm();
		const rand = prng(0x4C494E45);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const s2 = w.getPolySlot2();

		for (let trial = 0; trial < 20; trial++) {
			const a = randPoly(Q, rand);
			const b = randPoly(Q, rand);
			// sum = a + b (unreduced)
			const sum = a.map((v, i) => v + b[i]);

			// NTT of each
			writePoly(a, s0); w.poly_ntt(s0);
			writePoly(b, s1); w.poly_ntt(s1);
			writePoly(sum, s2); w.poly_ntt(s2);
			// s3 = NTT(a) + NTT(b)
			writePoly(a, s0); w.poly_ntt(s0);
			writePoly(b, s1); w.poly_ntt(s1);
			// recompute s3
			const na = readPoly(s0), nb = readPoly(s1), ns = readPoly(s2);
			for (let i = 0; i < N; i++) {
				// NTT(a+b)[i] ≡ NTT(a)[i] + NTT(b)[i] (mod q)
				expect(((ns[i] - na[i] - nb[i]) % Q + Q) % Q).toBe(0);
			}
		}
	});

	test('basemul commutativity: a*b == b*a in NTT domain', () => {
		const w = getWasm();
		const rand = prng(0xBA5E_5678);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const s2 = w.getPolySlot2();
		const s3 = w.getPolySlot3();

		for (let trial = 0; trial < 50; trial++) {
			const a = randPoly(Q, rand);
			const b = randPoly(Q, rand);
			writePoly(a, s0); w.poly_ntt(s0);
			writePoly(b, s1); w.poly_ntt(s1);
			// r0 = a*b, r1 = b*a
			w.poly_basemul_montgomery(s2, s0, s1);
			w.poly_basemul_montgomery(s3, s1, s0);
			w.poly_reduce(s2);
			w.poly_reduce(s3);
			const r0 = readPoly(s2), r1 = readPoly(s3);
			for (let i = 0; i < N; i++) {
				expect(((r0[i] - r1[i]) % Q + Q) % Q).toBe(0);
			}
		}
	});
});

// GATE: ML-KEM serialization and compression: FIPS 203 encode/decode/compress

describe('Gate 4 — serialization and compression', () => {
	const POLY_BYTES = 384;

	test('poly_tobytes produces exactly 384 bytes', () => {
		const w = getWasm();
		const rand = prng(0xB07E_0001);
		const poly = randPoly(Q, rand);
		w.wipeBuffers();
		writePoly(poly, w.getPolySlot0());
		// Write to seed area (32 bytes) is too small; use PK offset for output
		// Actually use XOF area for 1024 bytes of output space
		const outOff = w.getXofPrfOffset();
		w.poly_tobytes(outOff, w.getPolySlot0());
		// Verify only 384 bytes changed (not more)
		const after = mem().slice(outOff + POLY_BYTES, outOff + POLY_BYTES + 4);
		expect(Array.from(after).every(b => b === 0)).toBe(true);
	});

	test('poly frombytes/tobytes roundtrip is exact', () => {
		const w = getWasm();
		const rand = prng(0xB97E_5678);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const outOff = w.getPkOffset();

		for (let trial = 0; trial < 20; trial++) {
			const original = randPoly(Q, rand);
			// Reduce to [0, q) — tobytes expects non-negative coefficients, handles
			// negative via +q adjustment, so all values mod q in [0,q) are fine.
			writePoly(original, s0);
			w.poly_tobytes(outOff, s0);
			w.poly_frombytes(s1, outOff);
			const recovered = readPoly(s1);
			for (let i = 0; i < N; i++) {
				expect(recovered[i]).toBe(original[i]);
			}
		}
	});

	test('poly_compress(4) produces exactly 128 bytes', () => {
		const w = getWasm();
		const rand = prng(0xC001_0001);
		w.wipeBuffers();
		writePoly(randPoly(Q, rand), w.getPolySlot0());
		const outOff = w.getXofPrfOffset();
		w.poly_compress(outOff, w.getPolySlot0(), 4);
		const after = mem().slice(outOff + 128, outOff + 132);
		expect(Array.from(after).every(b => b === 0)).toBe(true);
	});

	test('poly_compress(5) produces exactly 160 bytes', () => {
		const w = getWasm();
		const rand = prng(0xC001_0002);
		w.wipeBuffers();
		writePoly(randPoly(Q, rand), w.getPolySlot0());
		const outOff = w.getXofPrfOffset();
		w.poly_compress(outOff, w.getPolySlot0(), 5);
		const after = mem().slice(outOff + 160, outOff + 164);
		expect(Array.from(after).every(b => b === 0)).toBe(true);
	});

	test('poly compress/decompress error bound dv=4', () => {
		const w = getWasm();
		const rand = prng(0xC001_4444);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const outOff = w.getXofPrfOffset();
		const dv = 4;
		// Error bound: q / 2^(dv+1) = 3329 / 32 ≈ 104.03, round up to 105
		const bound = Math.ceil(Q / (1 << (dv + 1)));

		for (let trial = 0; trial < 50; trial++) {
			const poly = randPoly(Q, rand);
			writePoly(poly, s0);
			w.poly_compress(outOff, s0, dv);
			w.poly_decompress(s1, outOff, dv);
			const recovered = readPoly(s1);
			for (let i = 0; i < N; i++) {
				const diff = Math.abs(poly[i] - recovered[i]);
				const err = Math.min(diff, Q - diff);
				expect(err).toBeLessThanOrEqual(bound);
			}
		}
	});

	test('poly compress/decompress error bound dv=5', () => {
		const w = getWasm();
		const rand = prng(0xC001_5555);
		const s0 = w.getPolySlot0();
		const s1 = w.getPolySlot1();
		const outOff = w.getXofPrfOffset();
		const dv = 5;
		// Error bound: q / 2^(dv+1) = 3329 / 64 ≈ 52.02, round up to 53
		const bound = Math.ceil(Q / (1 << (dv + 1)));

		for (let trial = 0; trial < 50; trial++) {
			const poly = randPoly(Q, rand);
			writePoly(poly, s0);
			w.poly_compress(outOff, s0, dv);
			w.poly_decompress(s1, outOff, dv);
			const recovered = readPoly(s1);
			for (let i = 0; i < N; i++) {
				const diff = Math.abs(poly[i] - recovered[i]);
				const err = Math.min(diff, Q - diff);
				expect(err).toBeLessThanOrEqual(bound);
			}
		}
	});

	test('poly_frommsg: each coefficient is 0 or HALF_Q=1665', () => {
		const w = getWasm();
		const rand = prng(0xF00D_BEEF);
		const msgOff = w.getMsgOffset();
		const polyOff = w.getPolySlot0();

		for (let trial = 0; trial < 20; trial++) {
			const msg = randBytes(32, rand);
			writeBytes(msg, msgOff);
			w.poly_frommsg(polyOff, msgOff);
			const poly = readPoly(polyOff);
			for (let i = 0; i < N; i++) {
				expect(poly[i] === 0 || poly[i] === HALF_Q).toBe(true);
			}
		}
	});

	test('poly_frommsg / poly_tomsg roundtrip', () => {
		const w = getWasm();
		const rand = prng(0xF00D_0011);
		const msgOff = w.getMsgOffset();
		const polyOff = w.getPolySlot0();
		const outOff = w.getSeedOffset();

		for (let trial = 0; trial < 50; trial++) {
			const msg = randBytes(32, rand);
			writeBytes(msg, msgOff);
			w.poly_frommsg(polyOff, msgOff);
			w.poly_tomsg(outOff, polyOff);
			const recovered = readBytes(outOff, 32);
			expect(Array.from(recovered)).toEqual(Array.from(msg));
		}
	});

	test('polyvec frombytes/tobytes roundtrip k=2,3,4', () => {
		const w = getWasm();
		const rand = prng(0xAEC0_5678);
		const pvOff = w.getPolyvecSlot0();
		const outOff = w.getSkOffset();  // 1536 bytes: enough for k=4

		for (const k of [2, 3, 4]) {
			const vecs: number[][] = [];
			for (let p = 0; p < k; p++) vecs.push(randPoly(Q, rand));
			writePolyvec(vecs, pvOff);
			w.polyvec_tobytes(outOff, pvOff, k);
			const pvOff2 = w.getPolyvecSlot1();
			w.polyvec_frombytes(pvOff2, outOff, k);
			const recovered = readPolyvec(pvOff2, k);
			for (let p = 0; p < k; p++) {
				for (let i = 0; i < N; i++) {
					expect(recovered[p][i]).toBe(vecs[p][i]);
				}
			}
		}
	});

	test('polyvec compress/decompress error bound du=10 k=2,3', () => {
		const w = getWasm();
		const rand = prng(0xAEC0_1010);
		const pvOff = w.getPolyvecSlot0();
		const outOff = w.getCtOffset();  // 1568 bytes: enough for k=4 du=11 (4*44=176 per poly... no)
		const du = 10;
		// du=10: each poly → 320 bytes. k=3: 960 bytes. k=4: 1280 bytes. CT is 1568 bytes. OK.
		// Error bound: q / 2^(du+1) = 3329 / 2048 ≈ 1.63, round up to 2
		const bound = Math.ceil(Q / (1 << (du + 1)));

		for (const k of [2, 3]) {
			for (let trial = 0; trial < 10; trial++) {
				const vecs: number[][] = [];
				for (let p = 0; p < k; p++) vecs.push(randPoly(Q, rand));
				writePolyvec(vecs, pvOff);
				w.polyvec_compress(outOff, pvOff, k, du);
				const pvOff2 = w.getPolyvecSlot1();
				w.polyvec_decompress(pvOff2, outOff, k, du);
				const recovered = readPolyvec(pvOff2, k);
				for (let p = 0; p < k; p++) {
					for (let i = 0; i < N; i++) {
						const diff = Math.abs(vecs[p][i] - recovered[p][i]);
						const err = Math.min(diff, Q - diff);
						expect(err).toBeLessThanOrEqual(bound);
					}
				}
			}
		}
	});

	test('polyvec compress/decompress error bound du=11 k=2,3', () => {
		const w = getWasm();
		const rand = prng(0xAEC0_1111);
		const pvOff = w.getPolyvecSlot0();
		const outOff = w.getCtOffset();
		const du = 11;
		// Error bound: q / 2^(du+1) = 3329 / 4096 ≈ 0.81, round up to 1
		const bound = Math.ceil(Q / (1 << (du + 1)));

		for (const k of [2, 3]) {
			for (let trial = 0; trial < 10; trial++) {
				const vecs: number[][] = [];
				for (let p = 0; p < k; p++) vecs.push(randPoly(Q, rand));
				writePolyvec(vecs, pvOff);
				w.polyvec_compress(outOff, pvOff, k, du);
				const pvOff2 = w.getPolyvecSlot1();
				w.polyvec_decompress(pvOff2, outOff, k, du);
				const recovered = readPolyvec(pvOff2, k);
				for (let p = 0; p < k; p++) {
					for (let i = 0; i < N; i++) {
						const diff = Math.abs(vecs[p][i] - recovered[p][i]);
						const err = Math.min(diff, Q - diff);
						expect(err).toBeLessThanOrEqual(bound);
					}
				}
			}
		}
	});
});

// GATE: ML-KEM sampling: rejection sampling and CBD bounds

describe('Gate 5 — CBD and rejection sampling', () => {
	test('cbd2 (poly_getnoise eta=2): all coefficients in [-2, 2]', () => {
		const w = getWasm();
		const rand = prng(0xCBD2_0001);
		const polyOff = w.getPolySlot0();
		const bufOff = w.getXofPrfOffset();

		for (let trial = 0; trial < 1000; trial++) {
			const buf = randBytes(128, rand);
			writeBytes(buf, bufOff);
			w.poly_getnoise(polyOff, bufOff, 2);
			const poly = readPoly(polyOff);
			for (let i = 0; i < N; i++) {
				expect(poly[i]).toBeGreaterThanOrEqual(-2);
				expect(poly[i]).toBeLessThanOrEqual(2);
			}
		}
	});

	// FIPS 203 §4.2.2 spec: cbd2 reads exactly 128 bytes and writes exactly 256
	// coefficients (N/8 = 32 outer iterations × 8 coeffs/iter). The three tests
	// below pin those guarantees so a future off-by-2× regression (i<64) cannot
	// survive a test run — the existing range-only test cannot detect it because
	// a-b ∈ [-2,2] holds structurally regardless of how many iterations run.

	test('cbd2 (eta=2): output is independent of input bytes 128..255', () => {
		const w = getWasm();
		const rand = prng(0xCBD2_FACE);
		const polyOff = w.getPolySlot0();
		const bufOff = w.getXofPrfOffset();

		const head = randBytes(128, rand);

		w.wipeBuffers();
		writeBytes(head, bufOff);
		writeBytes(new Uint8Array(128).fill(0x00), bufOff + 128);
		w.poly_getnoise(polyOff, bufOff, 2);
		const polyA = readPoly(polyOff);

		w.wipeBuffers();
		writeBytes(head, bufOff);
		writeBytes(new Uint8Array(128).fill(0xFF), bufOff + 128);
		w.poly_getnoise(polyOff, bufOff, 2);
		const polyB = readPoly(polyOff);

		for (let i = 0; i < N; i++) expect(polyA[i]).toBe(polyB[i]);
	});

	test('cbd2 (eta=2): does not write past the 512-byte destination polynomial', () => {
		const w = getWasm();
		const rand = prng(0xCBD2_BEEF);
		const polyOff = w.getPolySlot0();
		const bufOff = w.getXofPrfOffset();
		const adjacentOff = w.getPolySlot1();

		w.wipeBuffers();
		const sentinel = new Uint8Array(512).fill(0xA5);
		writeBytes(sentinel, adjacentOff);

		const buf = randBytes(128, rand);
		writeBytes(buf, bufOff);
		w.poly_getnoise(polyOff, bufOff, 2);

		const after = readBytes(adjacentOff, 512);
		for (let i = 0; i < 512; i++) expect(after[i]).toBe(0xA5);
	});

	test('cbd2 (eta=2): KAT — matches FIPS 203 Algorithm 7 reference for fixed input', () => {
		// Inline FIPS 203 §4.2.2 / pq-crystals/kyber ref/cbd.c reference.
		// Mirrors the AS implementation but with the spec-correct N/8 = 32 bound.
		const refCbd2 = (b: Uint8Array): number[] => {
			const out: number[] = new Array(256);
			for (let i = 0; i < 32; i++) {
				const t = (b[4 * i] | (b[4 * i + 1] << 8) | (b[4 * i + 2] << 16) | (b[4 * i + 3] << 24)) >>> 0;
				let d = t & 0x55555555;
				d = (d + ((t >>> 1) & 0x55555555)) >>> 0;
				for (let j = 0; j < 8; j++) {
					const a = (d >>> (4 * j    )) & 3;
					const b2 = (d >>> (4 * j + 2)) & 3;
					out[8 * i + j] = a - b2;
				}
			}
			return out;
		};

		const w = getWasm();
		const rand = prng(0xCBD2_CAFE);
		const polyOff = w.getPolySlot0();
		const bufOff = w.getXofPrfOffset();

		for (let trial = 0; trial < 100; trial++) {
			w.wipeBuffers();
			const buf = randBytes(128, rand);
			writeBytes(buf, bufOff);
			w.poly_getnoise(polyOff, bufOff, 2);
			const got = readPoly(polyOff);
			const want = refCbd2(buf);
			for (let i = 0; i < N; i++) expect(got[i]).toBe(want[i]);
		}
	});

	test('cbd3 (poly_getnoise eta=3): all coefficients in [-3, 3]', () => {
		const w = getWasm();
		const rand = prng(0xCBD3_0001);
		const polyOff = w.getPolySlot0();
		const bufOff = w.getXofPrfOffset();

		for (let trial = 0; trial < 1000; trial++) {
			const buf = randBytes(192, rand);
			writeBytes(buf, bufOff);
			w.poly_getnoise(polyOff, bufOff, 3);
			const poly = readPoly(polyOff);
			for (let i = 0; i < N; i++) {
				expect(poly[i]).toBeGreaterThanOrEqual(-3);
				expect(poly[i]).toBeLessThanOrEqual(3);
			}
		}
	});

	test('rej_uniform: all accepted coefficients are in [0, q)', () => {
		const w = getWasm();
		const rand = prng(0xE320_0001);
		const polyOff = w.getPolySlot0();
		const bufOff = w.getXofPrfOffset();

		for (let trial = 0; trial < 50; trial++) {
			w.wipeBuffers();
			const buf = randBytes(768, rand);
			writeBytes(buf, bufOff);
			const written = w.rej_uniform(polyOff, 0, bufOff, 768);
			const poly = readPoly(polyOff);
			for (let i = 0; i < written; i++) {
				expect(poly[i]).toBeGreaterThanOrEqual(0);
				expect(poly[i]).toBeLessThan(Q);
			}
		}
	});

	test('rej_uniform: large buffer fills 256 coefficients', () => {
		const w = getWasm();
		// A 768-byte buffer provides 512 candidate 12-bit values.
		// Acceptance probability is q/4096 = 3329/4096 ≈ 81%. Expected accepted per 512 ≈ 415.
		// We need 256 accepted. With 768 bytes (512 candidates) this is extremely likely.
		const rand = prng(0xE320_F011);
		const polyOff = w.getPolySlot0();
		const bufOff = w.getXofPrfOffset();

		for (let trial = 0; trial < 20; trial++) {
			w.wipeBuffers();
			const buf = randBytes(768, rand);
			writeBytes(buf, bufOff);
			const written = w.rej_uniform(polyOff, 0, bufOff, 768);
			// Should have filled 256 in most cases with 768 bytes
			// (min expected ~415 candidates accepted from 512, need only 256)
			expect(written).toBe(N);
		}
	});

	test('rej_uniform ctrStart: resumes from correct index', () => {
		const w = getWasm();
		const rand = prng(0xE320_C001);
		const polyOff = w.getPolySlot0();
		const bufOff = w.getXofPrfOffset();

		w.wipeBuffers();
		const buf = randBytes(768, rand);
		writeBytes(buf, bufOff);
		// Fill first 128, then fill remaining 128
		const wrote1 = w.rej_uniform(polyOff, 0, bufOff, 384);
		const wrote2 = w.rej_uniform(polyOff, wrote1, bufOff, 768);
		// All should be in [0, q)
		const total = wrote1 + wrote2;
		const poly = readPoly(polyOff);
		for (let i = 0; i < total; i++) {
			expect(poly[i]).toBeGreaterThanOrEqual(0);
			expect(poly[i]).toBeLessThan(Q);
		}
	});
});

// GATE: ML-KEM constant-time operations: CT verify and cmov

describe('Gate 6 — constant-time compare and cmov', () => {
	test('ct_verify returns 0 for identical arrays', () => {
		const w = getWasm();
		const rand = prng(0xC7E1_0001);
		const aOff = w.getMsgOffset();   // 32 bytes
		const bOff = w.getSeedOffset();  // 32 bytes

		for (let trial = 0; trial < 50; trial++) {
			const data = randBytes(32, rand);
			writeBytes(data, aOff);
			writeBytes(data, bOff);
			expect(w.ct_verify(aOff, bOff, 32)).toBe(0);
		}
	});

	test('ct_verify returns 1 when arrays differ', () => {
		const w = getWasm();
		const rand = prng(0xC7E1_0002);
		const aOff = w.getMsgOffset();
		const bOff = w.getSeedOffset();

		for (let trial = 0; trial < 50; trial++) {
			const a = randBytes(32, rand);
			const b = randBytes(32, rand);
			// Make sure they differ by flipping one byte
			b[0] = (b[0] ^ 0xFF) & 0xFF;
			writeBytes(a, aOff);
			writeBytes(b, bOff);
			expect(w.ct_verify(aOff, bOff, 32)).toBe(1);
		}
	});

	test('ct_verify returns 1 for single-bit difference', () => {
		const w = getWasm();
		const aOff = w.getMsgOffset();
		const bOff = w.getSeedOffset();
		const data = new Uint8Array(32).fill(0xAA);

		for (let bit = 0; bit < 8; bit++) {
			writeBytes(data, aOff);
			const b = data.slice();
			b[15] ^= (1 << bit);
			writeBytes(b, bOff);
			expect(w.ct_verify(aOff, bOff, 32)).toBe(1);
		}
	});

	test('ct_verify on length 0 returns 0', () => {
		const w = getWasm();
		// Zero-length comparison — vacuously equal
		expect(w.ct_verify(w.getMsgOffset(), w.getSeedOffset(), 0)).toBe(0);
	});

	test('ct_cmov(r, x, n, 1) copies x to r', () => {
		const w = getWasm();
		const rand = prng(0xC7CA_0001);
		const rOff = w.getMsgOffset();
		const xOff = w.getSeedOffset();

		for (let trial = 0; trial < 50; trial++) {
			const r = randBytes(32, rand);
			const x = randBytes(32, rand);
			writeBytes(r, rOff);
			writeBytes(x, xOff);
			w.ct_cmov(rOff, xOff, 32, 1);
			const result = readBytes(rOff, 32);
			expect(Array.from(result)).toEqual(Array.from(x));
		}
	});

	test('ct_cmov(r, x, n, 0) leaves r unchanged', () => {
		const w = getWasm();
		const rand = prng(0xC7CA_0000);
		const rOff = w.getMsgOffset();
		const xOff = w.getSeedOffset();

		for (let trial = 0; trial < 50; trial++) {
			const r = randBytes(32, rand);
			const x = randBytes(32, rand);
			writeBytes(r, rOff);
			writeBytes(x, xOff);
			w.ct_cmov(rOff, xOff, 32, 0);
			const result = readBytes(rOff, 32);
			expect(Array.from(result)).toEqual(Array.from(r));
		}
	});

	test('ct_cmov with b=1 then b=0 leaves final result as x from the b=1 call', () => {
		const w = getWasm();
		const rOff = w.getMsgOffset();
		const xOff = w.getSeedOffset();
		const r = new Uint8Array(32).fill(0x11);
		const x = new Uint8Array(32).fill(0x22);
		const y = new Uint8Array(32).fill(0x33);
		writeBytes(r, rOff);
		writeBytes(x, xOff);
		w.ct_cmov(rOff, xOff, 32, 1);  // r = x = 0x22
		writeBytes(y, xOff);
		w.ct_cmov(rOff, xOff, 32, 0);  // r unchanged = 0x22
		const result = readBytes(rOff, 32);
		expect(result[0]).toBe(0x22);
	});
});
