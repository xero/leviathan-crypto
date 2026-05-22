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
	N_HEX, N_MINUS_1_HEX, RNG,
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

	it('scalarInv: stress test, a * inv(a) == 1 across 200 random + edge inputs', () => {
		// Exercises the safegcd substrate across a broader input space than
		// the single a=7 above. Catches off-by-one in iteration count,
		// sign-handling errors at termination, or any mask-logic bug that
		// only surfaces on specific bit patterns.
		wasm.wipeBuffers();
		const a    = testSlot(0);
		const inv  = testSlot(32);
		const prod = testSlot(64);

		// Edge cases: a = 1, a = 2, a = n-1, a = n-2, a = n/2 (high-S boundary).
		const edges: Uint8Array[] = [];
		{
			const e1 = new Uint8Array(32); e1[31] = 1; edges.push(e1);
			const e2 = new Uint8Array(32); e2[31] = 2; edges.push(e2);
			edges.push(hexToBytes(N_MINUS_1_HEX));
			const nm2 = hexToBytes(N_MINUS_1_HEX); nm2[31] -= 1; edges.push(nm2);
			// n/2 (= scalarIsHighS boundary)
			const nh = hexToBytes(N_HEX);
			// Compute n/2 BE: right-shift the BE bytes by 1.
			let carry = 0;
			for (let i = 0; i < 32; i++) {
				const v = nh[i];
				nh[i] = (carry << 7) | (v >>> 1);
				carry = v & 1;
			}
			edges.push(nh);
		}

		for (const e of edges) {
			writeBytes(wasm.memory, a, e);
			wasm.scalarInv(inv, a);
			wasm.scalarMul(prod, a, inv);
			const view = new Uint8Array(wasm.memory.buffer, prod, 32);
			expect(view[31]).toBe(1);
			for (let i = 0; i < 31; i++) expect(view[i]).toBe(0);
		}

		// 200 deterministic random inputs in [1, n-1]. Using the xorshift32
		// RNG from util.ts (per AGENTS.md curve25519 test guidance: no
		// crypto.getRandomValues in unit tests).
		const rng = new RNG(0xC0FFEE);
		for (let trial = 0; trial < 200; trial++) {
			const aBytes = rng.bytes(32);
			// Force the high bit clear so the value is < n (n's top byte is 0xFF
			// but n has 0x00 in bytes 4-7, so values with top byte < 0xFF are
			// always canonical < n). Also force non-zero by setting LSB if all
			// zero.
			aBytes[0] = aBytes[0] & 0x7F;  // top bit clear -> value < 2^255 < n
			let allZero = true;
			for (let i = 0; i < 32; i++) {
				if (aBytes[i] !== 0) {
					allZero = false;
					break;
				}
			}
			if (allZero) aBytes[31] = 1;

			writeBytes(wasm.memory, a, aBytes);
			wasm.scalarInv(inv, a);
			wasm.scalarMul(prod, a, inv);

			const view = new Uint8Array(wasm.memory.buffer, prod, 32);
			expect(view[31]).toBe(1);
			for (let i = 0; i < 31; i++) expect(view[i]).toBe(0);
		}
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
