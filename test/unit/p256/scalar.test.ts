//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//
/**
 * Scalar arithmetic invariants mod n (the P-256 base point order).
 * Mirror the field test structure; each test is a substrate-gate
 * algebraic identity over Z_n.
 *
 *   - scalarIsCanonical accepts [0, n), rejects n and n+1
 *   - scalarIsZero true on the all-zero buffer only
 *   - scalarIsHighS true iff s > n/2
 *   - scalarMul commutativity, scalarInv correctness
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadP256, hexToBytes, writeBytes, testSlot,
	N_HEX, N_MINUS_1_HEX,
	type P256Exports,
} from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

describe('p256 scalar invariants', () => {
	it('scalarIsCanonical accepts 0 and n-1, rejects n', () => {
		wasm.wipeBuffers();
		const zero = testSlot(0);
		const nm1  = testSlot(32);
		const n    = testSlot(64);

		new Uint8Array(wasm.memory.buffer, zero, 32).fill(0);
		writeBytes(wasm.memory, nm1, hexToBytes(N_MINUS_1_HEX));
		writeBytes(wasm.memory, n,   hexToBytes(N_HEX));

		expect(wasm.scalarIsCanonical(zero)).toBe(1);
		expect(wasm.scalarIsCanonical(nm1)).toBe(1);
		expect(wasm.scalarIsCanonical(n)).toBe(0);
	});

	it('scalarIsZero true only on 0', () => {
		wasm.wipeBuffers();
		const zero = testSlot(0);
		const one  = testSlot(32);
		new Uint8Array(wasm.memory.buffer, zero, 32).fill(0);
		const oneBytes = new Uint8Array(32);
		oneBytes[31] = 1;
		writeBytes(wasm.memory, one, oneBytes);

		expect(wasm.scalarIsZero(zero)).toBe(1);
		expect(wasm.scalarIsZero(one)).toBe(0);
	});

	it('scalarIsHighS true for n-1, false for 1', () => {
		wasm.wipeBuffers();
		const nm1 = testSlot(0);
		const one = testSlot(32);
		writeBytes(wasm.memory, nm1, hexToBytes(N_MINUS_1_HEX));
		const oneBytes = new Uint8Array(32);
		oneBytes[31] = 1;
		writeBytes(wasm.memory, one, oneBytes);

		expect(wasm.scalarIsHighS(nm1)).toBe(1);
		expect(wasm.scalarIsHighS(one)).toBe(0);
	});

	it('scalarMul commutativity: a * b == b * a', () => {
		wasm.wipeBuffers();
		const a = testSlot(0);
		const b = testSlot(32);
		const ab = testSlot(64);
		const ba = testSlot(96);

		// Two arbitrary canonical scalars.
		writeBytes(wasm.memory, a, hexToBytes(
			'1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
		));
		writeBytes(wasm.memory, b, hexToBytes(
			'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321'
		));

		wasm.scalarMul(ab, a, b);
		wasm.scalarMul(ba, b, a);

		const abBytes = new Uint8Array(wasm.memory.buffer, ab, 32);
		const baBytes = new Uint8Array(wasm.memory.buffer, ba, 32);
		for (let i = 0; i < 32; i++) {
			expect(abBytes[i]).toBe(baBytes[i]);
		}
	});

	it('scalarInv: a * inv(a) == 1', () => {
		wasm.wipeBuffers();
		const a = testSlot(0);
		const inv = testSlot(32);
		const prod = testSlot(64);

		const aBytes = new Uint8Array(32);
		aBytes[31] = 7;   // a = 7
		writeBytes(wasm.memory, a, aBytes);

		wasm.scalarInv(inv, a);
		wasm.scalarMul(prod, a, inv);

		const prodView = new Uint8Array(wasm.memory.buffer, prod, 32);
		// Expected: 1 in BE = 0...01
		expect(prodView[31]).toBe(1);
		for (let i = 0; i < 31; i++) expect(prodView[i]).toBe(0);
	}, 30000);

	it('scalarReduce: input n reduces to 0', () => {
		wasm.wipeBuffers();
		const n = testSlot(0);
		const out = testSlot(32);
		writeBytes(wasm.memory, n, hexToBytes(N_HEX));

		wasm.scalarReduce(out, n);
		const outView = new Uint8Array(wasm.memory.buffer, out, 32);
		for (let i = 0; i < 32; i++) expect(outView[i]).toBe(0);
	});
});
