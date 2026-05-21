//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//
/**
 * GF(p256) field-arithmetic invariants. Each test exercises a single
 * algebraic identity that holds over Z_p256:
 *
 *   - Additive: a + 0 == a, a + (-a) == 0, (a + b) + c == a + (b + c)
 *   - Multiplicative: a * 1 == a, a * 0 == 0, a * inv(a) == 1
 *   - Distributive: a * (b + c) == a*b + a*c
 *   - Round-trip: feFromBytes(feToBytes(x)) == x for canonical x
 *
 * The substrate Solinas reduction is exercised by every feMul / feSqr
 * call here; failures in the reduction would surface as additive-
 * inverse or multiplicative-inverse failures (the same gates a TS-
 * level wrapper test would catch). Per AGENTS.md §3 these invariants
 * are gates: if the gate fails, the implementation is debugged, never
 * the test.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadP256, hexToBytes, RNG, testSlot,
	type P256Exports,
} from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

function feLoadBytes(off: number, hex: string): void {
	const bytes = hexToBytes(hex);
	const tmp = testSlot(900);
	new Uint8Array(wasm.memory.buffer, tmp, 32).set(bytes);
	wasm.feFromBytes(off, tmp);
}

describe('p256 field invariants', () => {
	const a = testSlot(0);
	const b = testSlot(32);
	const c = testSlot(64);
	const zero = testSlot(96);
	const one = testSlot(128);
	const t1 = testSlot(160);
	const t2 = testSlot(192);
	const t3 = testSlot(224);

	beforeAll(() => {
		wasm.wipeBuffers();
		// Two deterministic non-trivial field elements derived from
		// xorshift32. The test does not depend on their specific
		// values; only that they're non-zero and non-equal.
		const rng = new RNG(0xdeadbeef);
		new Uint8Array(wasm.memory.buffer, testSlot(900), 32).set(rng.bytes(32));
		wasm.feFromBytes(a, testSlot(900));
		new Uint8Array(wasm.memory.buffer, testSlot(900), 32).set(rng.bytes(32));
		wasm.feFromBytes(b, testSlot(900));
		new Uint8Array(wasm.memory.buffer, testSlot(900), 32).set(rng.bytes(32));
		wasm.feFromBytes(c, testSlot(900));

		new Uint8Array(wasm.memory.buffer, zero, 32).fill(0);
		feLoadBytes(one,
			'0000000000000000000000000000000000000000000000000000000000000001');
	});

	it('a + 0 == a', () => {
		wasm.feAdd(t1, a, zero);
		expect(wasm.feIsEqual(t1, a)).toBe(1);
	});

	it('a + (-a) == 0', () => {
		wasm.feNeg(t1, a);
		wasm.feAdd(t2, a, t1);
		expect(wasm.feIsZero(t2)).toBe(1);
	});

	it('(a + b) + c == a + (b + c)', () => {
		wasm.feAdd(t1, a, b);
		wasm.feAdd(t1, t1, c);
		wasm.feAdd(t2, b, c);
		wasm.feAdd(t2, a, t2);
		expect(wasm.feIsEqual(t1, t2)).toBe(1);
	});

	it('a * 1 == a', () => {
		wasm.feMul(t1, a, one);
		expect(wasm.feIsEqual(t1, a)).toBe(1);
	});

	it('a * 0 == 0', () => {
		wasm.feMul(t1, a, zero);
		expect(wasm.feIsZero(t1)).toBe(1);
	});

	it('a * inv(a) == 1', () => {
		wasm.feInv(t1, a);
		wasm.feMul(t2, a, t1);
		expect(wasm.feIsEqual(t2, one)).toBe(1);
	});

	it('a * (b + c) == a*b + a*c', () => {
		wasm.feAdd(t1, b, c);
		wasm.feMul(t1, a, t1);           // a * (b + c)
		wasm.feMul(t2, a, b);
		wasm.feMul(t3, a, c);
		wasm.feAdd(t2, t2, t3);          // a*b + a*c
		expect(wasm.feIsEqual(t1, t2)).toBe(1);
	});

	it('feFromBytes(feToBytes(x)) == x round-trip', () => {
		const bytesOut = testSlot(900);
		wasm.feToBytes(bytesOut, a);
		wasm.feFromBytes(t1, bytesOut);
		expect(wasm.feIsEqual(t1, a)).toBe(1);
	});
});
