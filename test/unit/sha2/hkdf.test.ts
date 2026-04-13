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
import { describe, test, expect, beforeAll } from 'vitest';
import { init, HKDF_SHA256, HKDF_SHA512 } from '../../../src/ts/index.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { hkdfSha256Vectors, hkdfSha512Vectors } from '../../vectors/sha2.js';

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return bytes;
}

beforeAll(async () => {
	await init({ sha2: sha2Wasm });
});

// ── HKDF_SHA256 — RFC vectors ───────────────────────────────────────────────

describe('HKDF_SHA256 — RFC vectors', () => {
	// GATE: HKDF-SHA-256: RFC 5869 §A.1
	// Vector: sha2.ts[hkdfSha256Vectors[0]]
	test('A.1 derive() OKM matches', () => {
		const v = hkdfSha256Vectors[0];
		const h = new HKDF_SHA256();
		const okm = h.derive(fromHex(v.ikm), fromHex(v.salt), fromHex(v.info), v.length);
		expect(toHex(okm)).toBe(v.okm);
		h.dispose();
	});

	test('A.2 derive() OKM matches', () => {
		const v = hkdfSha256Vectors[1];
		const h = new HKDF_SHA256();
		const okm = h.derive(fromHex(v.ikm), fromHex(v.salt), fromHex(v.info), v.length);
		expect(toHex(okm)).toBe(v.okm);
		h.dispose();
	});

	test('A.3 derive() OKM matches (no salt, no info)', () => {
		const v = hkdfSha256Vectors[2];
		const h = new HKDF_SHA256();
		const okm = h.derive(fromHex(v.ikm), null, new Uint8Array(0), v.length);
		expect(toHex(okm)).toBe(v.okm);
		h.dispose();
	});
});

// ── HKDF_SHA256 — extract() isolation ───────────────────────────────────────

describe('HKDF_SHA256 — extract() isolation', () => {
	test('A.1 extract(salt, ikm) PRK matches', () => {
		const v = hkdfSha256Vectors[0];
		const h = new HKDF_SHA256();
		const prk = h.extract(fromHex(v.salt), fromHex(v.ikm));
		expect(toHex(prk)).toBe(v.prk);
		h.dispose();
	});

	test('A.3 extract(null, ikm) PRK matches', () => {
		const v = hkdfSha256Vectors[2];
		const h = new HKDF_SHA256();
		const prk = h.extract(null, fromHex(v.ikm));
		expect(toHex(prk)).toBe(v.prk);
		h.dispose();
	});

	test('extract(null, ikm) === extract(new Uint8Array(32), ikm)', () => {
		const ikm = fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
		const h = new HKDF_SHA256();
		const a = h.extract(null, ikm);
		const b = h.extract(new Uint8Array(32), ikm);
		expect(toHex(a)).toBe(toHex(b));
		h.dispose();
	});

	test('extract(new Uint8Array(0), ikm) === extract(new Uint8Array(32), ikm)', () => {
		const ikm = fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
		const h = new HKDF_SHA256();
		const a = h.extract(new Uint8Array(0), ikm);
		const b = h.extract(new Uint8Array(32), ikm);
		expect(toHex(a)).toBe(toHex(b));
		h.dispose();
	});
});

// ── HKDF_SHA256 — expand() isolation ────────────────────────────────────────

describe('HKDF_SHA256 — expand() isolation', () => {
	test('A.1 expand(prk, info, 42) OKM matches', () => {
		const v = hkdfSha256Vectors[0];
		const h = new HKDF_SHA256();
		const okm = h.expand(fromHex(v.prk!), fromHex(v.info), v.length);
		expect(toHex(okm)).toBe(v.okm);
		h.dispose();
	});

	test('A.3 expand(prk, empty info, 42) OKM matches', () => {
		const v = hkdfSha256Vectors[2];
		const h = new HKDF_SHA256();
		const okm = h.expand(fromHex(v.prk!), new Uint8Array(0), v.length);
		expect(toHex(okm)).toBe(v.okm);
		h.dispose();
	});
});

// ── HKDF_SHA256 — derive() consistency ──────────────────────────────────────

describe('HKDF_SHA256 — derive() consistency', () => {
	test('derive() === expand(extract(salt, ikm), info, length) for A.1', () => {
		const v = hkdfSha256Vectors[0];
		const h = new HKDF_SHA256();
		const derived = h.derive(fromHex(v.ikm), fromHex(v.salt), fromHex(v.info), v.length);
		const prk = h.extract(fromHex(v.salt), fromHex(v.ikm));
		const expanded = h.expand(prk, fromHex(v.info), v.length);
		expect(toHex(derived)).toBe(toHex(expanded));
		h.dispose();
	});

	test('derive() === expand(extract(salt, ikm), info, length) for A.3', () => {
		const v = hkdfSha256Vectors[2];
		const h = new HKDF_SHA256();
		const derived = h.derive(fromHex(v.ikm), null, new Uint8Array(0), v.length);
		const prk = h.extract(null, fromHex(v.ikm));
		const expanded = h.expand(prk, new Uint8Array(0), v.length);
		expect(toHex(derived)).toBe(toHex(expanded));
		h.dispose();
	});
});

// ── HKDF_SHA256 — RangeError guards ────────────────────────────────────────

describe('HKDF_SHA256 — RangeError guards', () => {
	test('expand() throws RangeError for length < 1', () => {
		const h = new HKDF_SHA256();
		const prk = new Uint8Array(32);
		expect(() => h.expand(prk, new Uint8Array(0), 0)).toThrow(RangeError);
		h.dispose();
	});

	test('expand() throws RangeError for length > 8160', () => {
		const h = new HKDF_SHA256();
		const prk = new Uint8Array(32);
		expect(() => h.expand(prk, new Uint8Array(0), 8161)).toThrow(RangeError);
		h.dispose();
	});

	test('expand() throws RangeError for PRK of wrong length', () => {
		const h = new HKDF_SHA256();
		const prk = new Uint8Array(16);
		expect(() => h.expand(prk, new Uint8Array(0), 32)).toThrow(RangeError);
		h.dispose();
	});
});

// ── HKDF_SHA256 — dispose ──────────────────────────────────────────────────

describe('HKDF_SHA256 — dispose', () => {
	test('dispose() does not throw', () => {
		const h = new HKDF_SHA256();
		expect(() => h.dispose()).not.toThrow();
	});
});

// ── HKDF_SHA512 — generated vectors ────────────────────────────────────────

describe('HKDF_SHA512 — generated vectors', () => {
	test('S512-1 derive() OKM matches', () => {
		const v = hkdfSha512Vectors[0];
		const h = new HKDF_SHA512();
		const okm = h.derive(fromHex(v.ikm), fromHex(v.salt), fromHex(v.info), v.length);
		expect(toHex(okm)).toBe(v.okm);
		h.dispose();
	});

	test('S512-2 derive() OKM matches', () => {
		const v = hkdfSha512Vectors[1];
		const h = new HKDF_SHA512();
		const okm = h.derive(fromHex(v.ikm), fromHex(v.salt), fromHex(v.info), v.length);
		expect(toHex(okm)).toBe(v.okm);
		h.dispose();
	});

	test('S512-3 derive() OKM matches (no salt, no info)', () => {
		const v = hkdfSha512Vectors[2];
		const h = new HKDF_SHA512();
		const okm = h.derive(fromHex(v.ikm), null, new Uint8Array(0), v.length);
		expect(toHex(okm)).toBe(v.okm);
		h.dispose();
	});
});

// ── HKDF_SHA512 — salt default ─────────────────────────────────────────────

describe('HKDF_SHA512 — salt default', () => {
	test('extract(null, ikm) === extract(new Uint8Array(64), ikm)', () => {
		const ikm = fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
		const h = new HKDF_SHA512();
		const a = h.extract(null, ikm);
		const b = h.extract(new Uint8Array(64), ikm);
		expect(toHex(a)).toBe(toHex(b));
		h.dispose();
	});
});

// ── HKDF_SHA512 — RangeError guards ────────────────────────────────────────

describe('HKDF_SHA512 — RangeError guards', () => {
	test('expand() throws RangeError for length > 16320', () => {
		const h = new HKDF_SHA512();
		const prk = new Uint8Array(64);
		expect(() => h.expand(prk, new Uint8Array(0), 16321)).toThrow(RangeError);
		h.dispose();
	});

	test('expand() throws RangeError for PRK of wrong length (32 bytes)', () => {
		const h = new HKDF_SHA512();
		const prk = new Uint8Array(32);
		expect(() => h.expand(prk, new Uint8Array(0), 64)).toThrow(RangeError);
		h.dispose();
	});
});

// ── HKDF_SHA512 — dispose ──────────────────────────────────────────────────

describe('HKDF_SHA512 — dispose', () => {
	test('dispose() does not throw', () => {
		const h = new HKDF_SHA512();
		expect(() => h.dispose()).not.toThrow();
	});
});
