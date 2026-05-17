//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//
/**
 * Scalar multiplication invariants.
 *   - [0]G == O
 *   - [1]G == G
 *   - [2]G == double(G)
 *   - pointMulBase(s) == pointMul(s, G) for several scalars
 *   - [s + t]G == [s]G + [t]G  (homomorphism)
 *   - [s][t]G == [s*t]G        (scalar composition)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { loadP256, testSlot, type P256Exports } from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

function scalarFromInt(off: number, n: number): void {
	const view = new Uint8Array(wasm.memory.buffer, off, 32);
	view.fill(0);
	// BE: byte 31 is LSB
	view[31] = (n >>>  0) & 0xFF;
	view[30] = (n >>>  8) & 0xFF;
	view[29] = (n >>> 16) & 0xFF;
	view[28] = (n >>> 24) & 0xFF;
}

describe('p256 scalar multiplication', () => {
	it('[0]G == identity', () => {
		wasm.wipeBuffers();
		const scal = testSlot(0);
		const P = testSlot(64);
		const O = testSlot(160);
		scalarFromInt(scal, 0);
		wasm.pointMulBase(scal, P);
		wasm.pointZero(O);
		expect(wasm.pointEqual(P, O)).toBe(1);
	}, 30000);

	it('[1]G == G', () => {
		wasm.wipeBuffers();
		const scal = testSlot(0);
		const P = testSlot(64);
		const G = testSlot(160);
		scalarFromInt(scal, 1);
		wasm.pointMulBase(scal, P);
		wasm.pointBasepoint(G);
		expect(wasm.pointEqual(P, G)).toBe(1);
	}, 30000);

	it('[2]G == double(G)', () => {
		wasm.wipeBuffers();
		const scal = testSlot(0);
		const P = testSlot(64);
		const G = testSlot(160);
		const G2 = testSlot(256);
		scalarFromInt(scal, 2);
		wasm.pointMulBase(scal, P);
		wasm.pointBasepoint(G);
		wasm.pointDouble(G2, G);
		expect(wasm.pointEqual(P, G2)).toBe(1);
	}, 30000);

	it('pointMulBase(s) == pointMul(s, G) for s in {3, 7, 42}', () => {
		for (const s of [3, 7, 42]) {
			wasm.wipeBuffers();
			const scal = testSlot(0);
			const base = testSlot(64);
			const variable = testSlot(160);
			const G = testSlot(256);
			scalarFromInt(scal, s);
			wasm.pointMulBase(scal, base);
			wasm.pointBasepoint(G);
			wasm.pointMul(scal, G, variable);
			expect(wasm.pointEqual(base, variable)).toBe(1);
		}
	}, 60000);

	// Group-homomorphism of fixed-base scalar mult: [s + t]G must equal
	// [s]G + [t]G for every (s, t) pair. The 32-bit-int helper keeps
	// s + t well under n, so the substrate's scalarAdd reduction is a
	// no-op here; the test exercises the algorithmic correspondence
	// between additive scalar combination and additive point combination
	// independent of mod-n behaviour.
	it('[s + t]G == [s]G + [t]G for 4 deterministic (s, t) pairs', () => {
		const pairs: [number, number][] = [
			[1, 2],
			[7, 13],
			[12345, 67890],
			[0x7FFFFFFF, 0x0001_2345],
		];
		for (const [s, t] of pairs) {
			wasm.wipeBuffers();
			const sScal  = testSlot(0);
			const tScal  = testSlot(32);
			const sumSc  = testSlot(64);
			const sG     = testSlot(96);
			const tG     = testSlot(192);
			const lhs    = testSlot(288);   // [s + t]G
			const rhs    = testSlot(384);   // [s]G + [t]G
			scalarFromInt(sScal, s);
			scalarFromInt(tScal, t);
			wasm.scalarAdd(sumSc, sScal, tScal);
			wasm.pointMulBase(sumSc, lhs);
			wasm.pointMulBase(sScal, sG);
			wasm.pointMulBase(tScal, tG);
			wasm.pointAdd(rhs, sG, tG);
			expect(wasm.pointEqual(lhs, rhs)).toBe(1);
		}
	}, 60000);

	// Scalar-composition: [s]([t]G) must equal [s*t]G for every (s, t)
	// pair. (s, t) are kept under 2^16 so s*t fits in 32 bits, well
	// under n, again making the mod-n reduction a no-op so the test
	// isolates the composition law from the scalar-field reduction.
	it('[s]([t]G) == [s*t]G for 4 deterministic (s, t) pairs', () => {
		const pairs: [number, number][] = [
			[2, 3],
			[7, 11],
			[123, 456],
			[0xABCD, 0x1234],
		];
		for (const [s, t] of pairs) {
			wasm.wipeBuffers();
			const sScal  = testSlot(0);
			const tScal  = testSlot(32);
			const prod   = testSlot(64);
			const tG     = testSlot(96);
			const lhs    = testSlot(192);   // [s]([t]G)
			const rhs    = testSlot(288);   // [s*t]G
			scalarFromInt(sScal, s);
			scalarFromInt(tScal, t);
			wasm.scalarMul(prod, sScal, tScal);
			wasm.pointMulBase(tScal, tG);
			wasm.pointMul(sScal, tG, lhs);
			wasm.pointMulBase(prod, rhs);
			expect(wasm.pointEqual(lhs, rhs)).toBe(1);
		}
	}, 120000);
});
