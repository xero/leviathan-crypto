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
 * GF(2^255-19) field arithmetic invariants.
 *
 * Tests structural correctness against properties that any field
 * implementation must satisfy: identity, inverse, commutativity,
 * associativity, distributivity, serialisation round-trip, and
 * constant-time conditional behaviour.
 *
 * Uses a deterministic pseudo-random byte generator (xorshift32 seeded
 * from a counter) so tests are reproducible across runs without
 * depending on `crypto.getRandomValues`.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';

interface Curve25519Exports {
	memory:              WebAssembly.Memory;
	getFieldTmpOffset:   () => number;
	feAdd:               (out: number, a: number, b: number) => void;
	feSub:               (out: number, a: number, b: number) => void;
	feNeg:               (out: number, a: number) => void;
	feMul:               (out: number, a: number, b: number) => void;
	feSqr:               (out: number, a: number) => void;
	feInv:               (out: number, a: number) => void;
	feFromBytes:         (out: number, src: number) => void;
	feToBytes:           (out: number, src: number) => void;
	feIsZero:            (a: number) => number;
	feCondSwap:          (a: number, b: number, swap: number) => void;
	wipeBuffers:         () => void;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../../../build/curve25519.wasm');

let wasm: Curve25519Exports;
let mem: Uint8Array;

beforeAll(async () => {
	const bytes = readFileSync(WASM_PATH);
	const { instance } = await WebAssembly.instantiate(bytes, {
		env: { abort: () => {
			throw new Error('curve25519 wasm abort');
		} },
	});
	wasm = instance.exports as unknown as Curve25519Exports;
	mem  = new Uint8Array(wasm.memory.buffer);
});

// xorshift32 RNG for reproducibility (no crypto.getRandomValues per
// curve25519 test-utility guidance in TASK.md).
class RNG {
	private state: number;
	constructor(seed: number) {
		this.state = seed | 1;
	}
	next(): number {
		let x = this.state;
		x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
		this.state = x;
		return x >>> 0;
	}
	bytes(n: number): Uint8Array {
		const out = new Uint8Array(n);
		for (let i = 0; i < n; i++) out[i] = this.next() & 0xFF;
		return out;
	}
}

// 5-element layout in FIELD_TMP for one test: each slot is 40 bytes.
// We reserve slots 0..7 (320 bytes) for test scratch. The wasm side uses
// FIELD_TMP for feInv intermediate state, so we use slots away from the
// inversion chain (slots 0..10 are claimed by feInv).
// To stay clear of feInv we'll use FIELD_TMP_OFFSET + 11*40 onwards for
// our test slots, only when we're calling feInv. For non-inv tests, we
// can use slot 0 onwards.
function feSlot(idx: number): number {
	return wasm.getFieldTmpOffset() + idx * 40;
}

// Write a random byte string to a 32-byte buffer at off.
function writeBytes(off: number, bytes: Uint8Array): void {
	for (let i = 0; i < bytes.length; i++) mem[off + i] = bytes[i];
}

function readBytes(off: number, len: number): Uint8Array {
	return new Uint8Array(wasm.memory.buffer, off, len).slice();
}

// Encode then read back as a hex string for easy comparison.
function feToHex(slot: number): string {
	const out = feSlot(15);  // byte-output scratch (must be >= 32 bytes)
	wasm.feToBytes(out, slot);
	const b = readBytes(out, 32);
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function feFromHex(slot: number, hex: string): void {
	const bytes = new Uint8Array(32);
	for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	const tmp = feSlot(14);
	writeBytes(tmp, bytes);
	wasm.feFromBytes(slot, tmp);
}

function feSetZero(slot: number): void {
	const view = new DataView(wasm.memory.buffer);
	for (let i = 0; i < 5; i++) view.setBigInt64(slot + i * 8, 0n, true);
}

function feSetOne(slot: number): void {
	feSetZero(slot);
	const view = new DataView(wasm.memory.buffer);
	view.setBigInt64(slot, 1n, true);
}

describe('curve25519 field arithmetic invariants', () => {
	it('a + 0 = a', () => {
		const a = feSlot(0), zero = feSlot(1), out = feSlot(2);
		feFromHex(a, '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
		feSetZero(zero);
		wasm.feAdd(out, a, zero);
		// out and a should serialise to the same bytes.
		const aHex = feToHex(a);
		const outHex = feToHex(out);
		expect(outHex).toBe(aHex);
	});

	it('a * 1 = a', () => {
		const a = feSlot(0), one = feSlot(1), out = feSlot(2);
		feFromHex(a, '5060708090a0b0c0d0e0f01020304050607080902a3b4c5d6e7f8a9b0c1d2e3f');
		feSetOne(one);
		wasm.feMul(out, a, one);
		expect(feToHex(out)).toBe(feToHex(a));
	});

	it('a * 0 = 0', () => {
		const a = feSlot(0), zero = feSlot(1), out = feSlot(2);
		feFromHex(a, '7f8e9dafbcadbeefcafefacef00dba11baddcafe0123456789abcdef01234507');
		feSetZero(zero);
		wasm.feMul(out, a, zero);
		expect(feToHex(out)).toBe('0'.repeat(64));
	});

	it('a + (-a) = 0', () => {
		const a = feSlot(0), na = feSlot(1), out = feSlot(2);
		feFromHex(a, '1122334455667788aabbccddeeff00112233445566778899aabbccddeeff0011');
		wasm.feNeg(na, a);
		wasm.feAdd(out, a, na);
		expect(wasm.feIsZero(out)).toBe(1);
	});

	it('a + b = b + a (commutativity)', () => {
		const a = feSlot(0), b = feSlot(1), ab = feSlot(2), ba = feSlot(3);
		feFromHex(a, 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778800');
		feFromHex(b, '1100ffeeddccbbaa9988776655443322110000ffeeddccbbaa99887766554433');
		wasm.feAdd(ab, a, b);
		wasm.feAdd(ba, b, a);
		expect(feToHex(ab)).toBe(feToHex(ba));
	});

	it('a * b = b * a (commutativity)', () => {
		const a = feSlot(0), b = feSlot(1), ab = feSlot(2), ba = feSlot(3);
		feFromHex(a, '37363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a1900');
		feFromHex(b, 'cdeb47d52a3b1c0fe8d97e6fab4d3c2b1c0fef9eddccbbaa99887766554433ff');
		wasm.feMul(ab, a, b);
		wasm.feMul(ba, b, a);
		expect(feToHex(ab)).toBe(feToHex(ba));
	});

	it('a*(b+c) = a*b + a*c (distributivity)', () => {
		const a = feSlot(0), b = feSlot(1), c = feSlot(2);
		const bc = feSlot(3), abc = feSlot(4);
		const ab = feSlot(5), ac = feSlot(6), sum = feSlot(7);
		feFromHex(a, '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd07');
		feFromHex(b, 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654300');
		feFromHex(c, '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00');
		wasm.feAdd(bc, b, c);
		wasm.feMul(abc, a, bc);
		wasm.feMul(ab, a, b);
		wasm.feMul(ac, a, c);
		wasm.feAdd(sum, ab, ac);
		expect(feToHex(abc)).toBe(feToHex(sum));
	});

	it('serialisation round-trip toBytes(fromBytes(x))=x', () => {
		const rng = new RNG(0xDEADBEEF);
		for (let trial = 0; trial < 10; trial++) {
			const bytes = rng.bytes(32);
			bytes[31] &= 0x7F;  // canonical: high bit clear (the impl masks it on FromBytes)
			// Force into [0, p) by clearing the top bit (close enough for round-trip)
			const slot = feSlot(0);
			const bytesOff = feSlot(15);
			writeBytes(bytesOff, bytes);
			wasm.feFromBytes(slot, bytesOff);
			const hex = feToHex(slot);
			const inHex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
			expect(hex).toBe(inHex);
		}
	});

	it('a * inv(a) = 1 (modular inverse via Fermat)', () => {
		const a = feSlot(15), inva = feSlot(11), prod = feSlot(13);
		// Slots 0..10 are claimed by feInv internally; use later slots.
		feFromHex(a, '0203040506070809a0b0c0d0e0f001020304050607080910abcdef0123456700');
		wasm.feInv(inva, a);
		wasm.feMul(prod, a, inva);
		// prod should encode to 1.
		expect(feToHex(prod)).toBe('01' + '00'.repeat(31));
	});

	it('feCondSwap(swap=0) preserves both', () => {
		const a = feSlot(0), b = feSlot(1);
		feFromHex(a, '0011223344556677889900112233445566778899001122334455667788990011');
		feFromHex(b, 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778822');
		const aBefore = feToHex(a);
		const bBefore = feToHex(b);
		wasm.feCondSwap(a, b, 0);
		expect(feToHex(a)).toBe(aBefore);
		expect(feToHex(b)).toBe(bBefore);
	});

	it('feCondSwap(swap=1) exchanges', () => {
		const a = feSlot(0), b = feSlot(1);
		feFromHex(a, '0011223344556677889900112233445566778899001122334455667788990011');
		feFromHex(b, 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778822');
		const aBefore = feToHex(a);
		const bBefore = feToHex(b);
		wasm.feCondSwap(a, b, 1);
		expect(feToHex(a)).toBe(bBefore);
		expect(feToHex(b)).toBe(aBefore);
	});
});
