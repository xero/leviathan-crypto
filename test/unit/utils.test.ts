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
import { describe, test, expect } from 'vitest';
import {
	hexToBytes, bytesToHex, utf8ToBytes, bytesToUtf8,
	base64ToBytes, bytesToBase64,
	constantTimeEqual, wipe, xor, concat,
	randomBytes,
} from '../../src/ts/index.js';

// ── hexToBytes / bytesToHex ─────────────────────────────────────────────────

describe('hexToBytes / bytesToHex', () => {
	test('empty string round-trips', () => {
		expect(bytesToHex(hexToBytes(''))).toBe('');
	});

	test('single byte', () => {
		expect(bytesToHex(hexToBytes('ff'))).toBe('ff');
		expect(bytesToHex(hexToBytes('0a'))).toBe('0a');
	});

	test('32 bytes round-trip', () => {
		const hex = 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a';
		expect(bytesToHex(hexToBytes(hex))).toBe(hex);
	});

	test('uppercase input accepted', () => {
		expect(bytesToHex(hexToBytes('DEADBEEF'))).toBe('deadbeef');
	});

	test('0x prefix stripped', () => {
		expect(bytesToHex(hexToBytes('0xCAFE'))).toBe('cafe');
	});

	test('odd-length input padded', () => {
		const bytes = hexToBytes('abc');
		expect(bytes.length).toBe(2);
		expect(bytesToHex(bytes)).toBe('abc0');
	});
});

// ── utf8ToBytes / bytesToUtf8 ───────────────────────────────────────────────

describe('utf8ToBytes / bytesToUtf8', () => {
	test('ASCII round-trip', () => {
		expect(bytesToUtf8(utf8ToBytes('hello'))).toBe('hello');
	});

	test('multibyte UTF-8 round-trip', () => {
		const str = 'caf\u00e9 \u2603 \ud83d\ude00';
		expect(bytesToUtf8(utf8ToBytes(str))).toBe(str);
	});

	test('empty string', () => {
		expect(bytesToUtf8(utf8ToBytes(''))).toBe('');
	});
});

// ── base64ToBytes / bytesToBase64 ───────────────────────────────────────────

describe('base64ToBytes / bytesToBase64', () => {
	test('standard base64 round-trip', () => {
		const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
		const b64 = bytesToBase64(bytes);
		expect(b64).toBe('SGVsbG8=');
		const decoded = base64ToBytes(b64);
		expect(decoded).toEqual(bytes);
	});

	test('url-safe base64 round-trip', () => {
		const bytes = new Uint8Array([0xff, 0xfe, 0xfd]);
		const b64url = bytesToBase64(bytes, true);
		expect(b64url).not.toContain('+');
		expect(b64url).not.toContain('/');
		const decoded = base64ToBytes(b64url);
		expect(decoded).toEqual(bytes);
	});

	test('invalid input returns undefined', () => {
		expect(base64ToBytes('abc')).toBeUndefined(); // not multiple of 4
	});

	test('empty input', () => {
		expect(bytesToBase64(new Uint8Array(0))).toBe('');
		expect(base64ToBytes('')).toEqual(new Uint8Array(0));
	});
});

// ── constantTimeEqual ───────────────────────────────────────────────────────

describe('constantTimeEqual', () => {
	test('equal arrays return true', () => {
		const a = new Uint8Array([1, 2, 3, 4]);
		expect(constantTimeEqual(a, new Uint8Array([1, 2, 3, 4]))).toBe(true);
	});

	test('unequal arrays return false', () => {
		const a = new Uint8Array([1, 2, 3, 4]);
		expect(constantTimeEqual(a, new Uint8Array([1, 2, 3, 5]))).toBe(false);
	});

	test('different lengths return false', () => {
		expect(constantTimeEqual(new Uint8Array(3), new Uint8Array(4))).toBe(false);
	});

	test('empty arrays are equal', () => {
		expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
	});

	test('large input does not short-circuit', () => {
		const size = 100_000;
		const a = new Uint8Array(size).fill(0xAA);
		const b = new Uint8Array(size).fill(0xAA);
		b[0] = 0xBB; // differ at first byte
		const c = new Uint8Array(size).fill(0xAA);
		c[size - 1] = 0xBB; // differ at last byte

		// Both should return false — timing difference is not testable
		// deterministically, but we verify correctness
		expect(constantTimeEqual(a, b)).toBe(false);
		expect(constantTimeEqual(a, c)).toBe(false);
	});
});

// ── wipe ────────────────────────────────────────────────────────────────────

describe('wipe', () => {
	test('zeros Uint8Array', () => {
		const a = new Uint8Array([1, 2, 3, 4, 5]);
		wipe(a);
		expect(a.every(b => b === 0)).toBe(true);
	});

	test('zeros Uint32Array', () => {
		const a = new Uint32Array([0xDEAD, 0xBEEF]);
		wipe(a);
		expect(a.every(b => b === 0)).toBe(true);
	});
});

// ── xor ─────────────────────────────────────────────────────────────────────

describe('xor', () => {
	test('known values', () => {
		const a = new Uint8Array([0xFF, 0x00, 0xAA]);
		const b = new Uint8Array([0x0F, 0xF0, 0x55]);
		expect(xor(a, b)).toEqual(new Uint8Array([0xF0, 0xF0, 0xFF]));
	});

	test('XOR with self yields zeros', () => {
		const a = new Uint8Array([1, 2, 3]);
		expect(xor(a, a)).toEqual(new Uint8Array(3));
	});

	test('throws on length mismatch', () => {
		expect(() => xor(new Uint8Array(3), new Uint8Array(4))).toThrow(RangeError);
	});
});

// ── concat ──────────────────────────────────────────────────────────────────

describe('concat', () => {
	test('known values', () => {
		const a = new Uint8Array([1, 2]);
		const b = new Uint8Array([3, 4, 5]);
		expect(concat(a, b)).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
	});

	test('empty left', () => {
		const b = new Uint8Array([1, 2]);
		expect(concat(new Uint8Array(0), b)).toEqual(b);
	});

	test('empty right', () => {
		const a = new Uint8Array([1, 2]);
		expect(concat(a, new Uint8Array(0))).toEqual(a);
	});

	test('both empty', () => {
		expect(concat(new Uint8Array(0), new Uint8Array(0))).toEqual(new Uint8Array(0));
	});
});

// ── randomBytes ─────────────────────────────────────────────────────────────

describe('randomBytes', () => {
	test('returns correct length', () => {
		expect(randomBytes(32).length).toBe(32);
		expect(randomBytes(0).length).toBe(0);
		expect(randomBytes(1).length).toBe(1);
	});

	test('returns Uint8Array', () => {
		expect(randomBytes(16)).toBeInstanceOf(Uint8Array);
	});

	test('two calls produce different output', () => {
		const a = randomBytes(32);
		const b = randomBytes(32);
		// Probability of collision is 2^-256 — effectively impossible
		expect(constantTimeEqual(a, b)).toBe(false);
	});
});
