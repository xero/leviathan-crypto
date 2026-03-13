// test/unit/sha3/shake_xof.test.ts
//
// SHAKE128 and SHAKE256 XOF multi-squeeze tests.
// Verifies that sequential squeeze() calls produce contiguous output:
// squeeze(a) followed by squeeze(b) yields bytes [0,a) and [a,a+b) of the XOF stream.
//
// NOTE: SHAKE128 and SHAKE256 share a single WASM 'sha3' module instance.
// Instances must not be interleaved — each test uses one instance at a time.

import { describe, test, expect, beforeAll } from 'vitest';
import { init, SHAKE128, SHAKE256 } from '../../../src/ts/index.js';
import { shake128Vectors, shake256Vectors } from '../../vectors/sha3.js';
import {
	shake128MultiSqueezeVectors,
	shake256MultiSqueezeVectors,
} from '../../vectors/shake_xof.js';

function toHex(b: Uint8Array): string {
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
	const b = new Uint8Array(hex.length / 2);
	for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return b;
}

beforeAll(async () => {
	await init('sha3');
});

// ── SHAKE128 multi-squeeze KAT ───────────────────────────────────────────────

describe('SHAKE128 multi-squeeze KAT', () => {
	for (const vec of shake128MultiSqueezeVectors) {
		test(vec.description, () => {
			const h = new SHAKE128();
			h.absorb(fromHex(vec.input));
			const chunks = vec.squeezes.map(n => toHex(h.squeeze(n)));
			expect(chunks).toEqual(vec.expectedChunks);
			h.dispose();
		});
	}
});

// ── SHAKE128 byte-by-byte squeeze ────────────────────────────────────────────

describe('SHAKE128 byte-by-byte squeeze', () => {
	test('MS-4: squeeze(1) × 32 concatenates to same output as squeeze(32)', () => {
		// Reference: shake128Vectors[0] — FIPS 202 empty message, 32-byte output
		const ref = shake128Vectors[0].expected;
		const h = new SHAKE128();
		h.absorb(new Uint8Array(0));
		const bytes = Array.from({ length: 32 }, () => toHex(h.squeeze(1)));
		expect(bytes.join('')).toBe(ref);
		h.dispose();
	});
});

// ── SHAKE128 reset clears multi-squeeze state ────────────────────────────────

describe('SHAKE128 reset after multi-squeeze', () => {
	test('MS-9: reset() after multi-squeeze produces same output as a fresh squeeze', () => {
		// Reference: shake128Vectors[0] — FIPS 202 empty message, 32-byte output
		const ref = shake128Vectors[0].expected;
		const h = new SHAKE128();

		// dirty the instance with a multi-squeeze across the rate boundary
		h.absorb(new Uint8Array(0));
		h.squeeze(100);
		h.squeeze(100);

		// reset and re-run — must produce clean output, not a continuation
		h.reset();
		h.absorb(new Uint8Array(0));
		const out = toHex(h.squeeze(32));

		expect(out).toBe(ref);
		h.dispose();
	});
});

// ── SHAKE256 multi-squeeze KAT ───────────────────────────────────────────────

describe('SHAKE256 multi-squeeze KAT', () => {
	for (const vec of shake256MultiSqueezeVectors) {
		test(vec.description, () => {
			const h = new SHAKE256();
			h.absorb(fromHex(vec.input));
			const chunks = vec.squeezes.map(n => toHex(h.squeeze(n)));
			expect(chunks).toEqual(vec.expectedChunks);
			h.dispose();
		});
	}
});

// ── SHAKE256 byte-by-byte squeeze ────────────────────────────────────────────

describe('SHAKE256 byte-by-byte squeeze', () => {
	test('MS-8: squeeze(1) × 32 concatenates to same output as squeeze(32)', () => {
		// Reference: shake256Vectors[0] — FIPS 202 empty message, 32-byte output
		const ref = shake256Vectors[0].expected;
		const h = new SHAKE256();
		h.absorb(new Uint8Array(0));
		const bytes = Array.from({ length: 32 }, () => toHex(h.squeeze(1)));
		expect(bytes.join('')).toBe(ref);
		h.dispose();
	});
});
