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
/**
 * constantTimeEqual — branch-free tail.
 *
 * Covers the WASM SIMD path (the only path):
 *   - Equality over every boundary length (0, 1, 15, 16, 17, 31, 32, 33, 32768).
 *   - Inequality when exactly one bit is flipped at every position, across
 *     multiple lengths. Catches regressions where a rewrite misses a byte.
 *   - Max-length boundary (32768 pass, 32769 throws RangeError).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { constantTimeEqual, CT_MAX_BYTES, _ctResetForTesting } from '../../../src/ts/utils.js';

const LENGTHS_EQ = [0, 1, 15, 16, 17, 31, 32, 33, 100, CT_MAX_BYTES] as const;
const LENGTHS_NEQ = [1, 16, 17, 31, 32, 33, 100, CT_MAX_BYTES] as const;

function filled(len: number, seed = 0xa5): Uint8Array {
	const out = new Uint8Array(len);
	// Deterministic LCG so different lengths produce distinct content.
	let s = seed >>> 0 || 1;
	for (let i = 0; i < len; i++) {
		s = (s * 1664525 + 1013904223) >>> 0;
		out[i] = s & 0xff;
	}
	return out;
}

function runMatrix(): void {
	describe('equal inputs', () => {
		for (const n of LENGTHS_EQ) {
			it(`len=${n} → true`, () => {
				const a = filled(n);
				const b = a.slice();
				expect(constantTimeEqual(a, b)).toBe(true);
			});
		}
	});

	describe('unequal inputs — one bit flipped at every position', () => {
		for (const n of LENGTHS_NEQ) {
			it(`len=${n} → false for every single-bit flip`, () => {
				const a = filled(n);
				// Spot-check a handful of positions for long lengths to keep runtime bounded.
				const positions = n <= 100
					? Array.from({ length: n }, (_, i) => i)
					: [0, 1, 15, 16, 17, 31, 32, 33, n - 33, n - 17, n - 16, n - 1];
				for (const pos of positions) {
					const b = a.slice();
					b[pos] ^= 0x01;
					expect(constantTimeEqual(a, b)).toBe(false);
				}
			});
		}
	});

	it('every bit position within a byte produces inequality', () => {
		const a = filled(32);
		for (let bit = 0; bit < 8; bit++) {
			const b = a.slice();
			b[7] ^= 1 << bit;
			expect(constantTimeEqual(a, b)).toBe(false);
		}
	});
}

describe('constantTimeEqual', () => {
	beforeAll(() => {
		_ctResetForTesting();
	});
	runMatrix();

	it('max-length boundary: CT_MAX_BYTES passes, CT_MAX_BYTES + 1 throws', () => {
		const ok = new Uint8Array(CT_MAX_BYTES);
		expect(constantTimeEqual(ok, ok)).toBe(true);
		const over = new Uint8Array(CT_MAX_BYTES + 1);
		expect(() => constantTimeEqual(over, over)).toThrow(RangeError);
	});
});
