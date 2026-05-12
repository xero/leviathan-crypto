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
// test/unit/mldsa/reduce.test.ts
//
// GATE: ML-DSA reduction primitives, Montgomery (FIPS 204 Algorithm 49) and
// centered Barrett (FIPS 204 §2.3 mod± q). Validates the WASM exports against
// the spec definitions over hand-verified inputs and a randomised batch.

import { describe, test, expect, beforeAll } from 'vitest';
import { loadMldsa, getWasm, prng, modQ } from './helpers.js';

const Q  = 8380417;
const R  = 1n << 32n;
const HALF_Q = (Q - 1) / 2;  // 4190208

beforeAll(async () => {
	await loadMldsa();
});

// GATE: ML-DSA reduction primitives

describe('Gate, Montgomery reduction (FIPS 204 Algorithm 49)', () => {
	// Spec: r ≡ a · 2⁻³² (mod q), |r| < 2q.
	// Computed independently as BigInt: r* = (a · 2⁻³²) mod± q with |r*| ≤ q/2.
	// The WASM result r differs from r* by at most one q (slack permitted by spec),
	// so the gate checks r ≡ r* (mod q), i.e. (r − r*) is a multiple of q.

	function expectMontgomery(a: bigint): void {
		const r = getWasm().montgomery_reduce(a);
		// r* = a · R⁻¹ (mod q), centered into (-q/2, q/2]
		// R⁻¹ exists because q is prime; compute via solving (a · R⁻¹) mod q
		// iteratively: r_unsigned ≡ a · R⁻¹ (mod q)
		// Easier: r_unsigned · R ≡ a (mod q). So check (r * R) ≡ a (mod q).
		const rBig = BigInt(r);
		const lhs = (rBig * R) % BigInt(Q);
		const rhs = ((a % BigInt(Q)) + BigInt(Q)) % BigInt(Q);
		expect(((lhs - rhs) % BigInt(Q) + BigInt(Q)) % BigInt(Q)).toBe(0n);
		expect(Math.abs(r)).toBeLessThan(2 * Q);
	}

	test('a = 0 → r = 0', () => {
		expect(getWasm().montgomery_reduce(0n)).toBe(0);
	});

	test('a = q · 2³² (zero divisor of 2³² · q) → r ≡ q · 2³² · 2⁻³² ≡ 0', () => {
		expectMontgomery(BigInt(Q) * R);
	});

	test('a = 2³² → r ≡ 1 (mod q)', () => {
		// 2³² · 2⁻³² = 1
		expectMontgomery(R);
		const r = getWasm().montgomery_reduce(R);
		expect(modQ(r, Q)).toBe(1);
	});

	test('a = q − 1 → r · 2³² ≡ q − 1 (mod q)', () => {
		expectMontgomery(BigInt(Q - 1));
	});

	test('a = 2³¹·q (upper input bound, FIPS 204 Appendix A) → congruence holds', () => {
		// FIPS 204 says input |a| ≤ 2³¹·q ≈ 2⁵⁴; verify the boundary.
		expectMontgomery((1n << 31n) * BigInt(Q) - 1n);
		expectMontgomery(-((1n << 31n) * BigInt(Q) - 1n));
	});

	test('100 random i64 inputs, congruence and bound', () => {
		const rand = prng(0x4D444D54);  // 'MDMT'
		for (let i = 0; i < 100; i++) {
			// Sample |a| ≤ 2³¹ · q (worst case allowed by FIPS 204 Appendix A)
			const sign = (rand() & 1) === 0 ? 1n : -1n;
			const lo = BigInt(rand() >>> 0);
			const hi = BigInt(rand() >>> 0);
			const mag = ((hi << 32n) | lo) & ((1n << 54n) - 1n);  // |a| ≤ 2⁵⁴
			expectMontgomery(sign * mag);
		}
	});
});

describe('Gate, Barrett reduction (FIPS 204 §2.3, mod± q)', () => {
	// Spec: r ≡ a (mod q) with r ∈ [-(q-1)/2, (q-1)/2].
	function expectBarrett(a: number): void {
		const r = getWasm().barrett_reduce(a);
		expect(r).toBeGreaterThanOrEqual(-HALF_Q);
		expect(r).toBeLessThanOrEqual(HALF_Q);
		// (a − r) is a multiple of q
		const diff = a - r;
		// Use modular check; diff fits in i32 (|a| ≤ 2³¹, |r| ≤ q/2)
		expect(((diff % Q) + Q) % Q).toBe(0);
	}

	test('boundary cases', () => {
		expectBarrett(0);
		expectBarrett(1);
		expectBarrett(-1);
		expectBarrett(Q);
		expectBarrett(-Q);
		expectBarrett(Q - 1);
		expectBarrett(-(Q - 1));
		expectBarrett(2 * Q);
		expectBarrett(-2 * Q);
		expectBarrett(HALF_Q);
		expectBarrett(-HALF_Q);
		expectBarrett(HALF_Q + 1);
		expectBarrett(-HALF_Q - 1);
	});

	test('extreme i32 values', () => {
		expectBarrett(0x7FFFFFFF);
		expectBarrett(-0x80000000);
		expectBarrett(0x7FFFFFFF - 1);
		expectBarrett(-0x80000000 + 1);
	});

	test('200 random i32 inputs', () => {
		const rand = prng(0x42525430);  // 'BRT0'
		for (let i = 0; i < 200; i++) {
			const a = (rand() | 0);  // i32 cast
			expectBarrett(a);
		}
	});
});

describe('Gate, fqmul = montgomery_reduce(a · b)', () => {
	test('fqmul matches montgomery_reduce on the i64 product', () => {
		const w = getWasm();
		const rand = prng(0x46514D4C);  // 'FQML'
		for (let i = 0; i < 50; i++) {
			const a = ((rand() % (2 * Q)) - Q) | 0;
			const b = ((rand() % (2 * Q)) - Q) | 0;
			const expected = w.montgomery_reduce(BigInt(a) * BigInt(b));
			const got = w.fqmul(a, b);
			expect(got).toBe(expected);
		}
	});
});
