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

	test('odd-length input throws', () => {
		expect(() => hexToBytes('abc')).toThrow(RangeError);
		expect(() => hexToBytes('0xabc')).toThrow(RangeError); // odd after prefix strip
	});

	test('invalid hex character throws', () => {
		// `parseInt('0g', 16)` returns 0 — it stops at the first invalid
		// character after parsing a valid prefix, rather than failing. That
		// silently produced the wrong byte. The regex guard now rejects any
		// input outside `[0-9a-fA-F]` up front.
		expect(() => hexToBytes('0g')).toThrow(RangeError);
		expect(() => hexToBytes('zzzz')).toThrow(RangeError);
		expect(() => hexToBytes('deadxx')).toThrow(RangeError);
	});

	test('mixed-case input still works', () => {
		expect(bytesToHex(hexToBytes('deadBEEF'))).toBe('deadbeef');
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
		expect(b64url).not.toContain('=');
		expect(b64url).not.toContain('%3d');
		const decoded = base64ToBytes(b64url);
		expect(decoded).toEqual(bytes);
	});

	test('invalid input throws', () => {
		// Throws RangeError on illegal charsets and rem=1 inputs, matching the
		// throw-don't-return-null convention used everywhere else in the lib.
		expect(() => base64ToBytes('!!!!')).toThrow(RangeError);  // invalid charset
		expect(() => base64ToBytes('!!!')).toThrow(RangeError);   // odd-plus-garbage
		expect(() => base64ToBytes('a')).toThrow(RangeError);     // rem=1, always invalid
	});

	test('empty input', () => {
		expect(bytesToBase64(new Uint8Array(0))).toBe('');
		expect(base64ToBytes('')).toEqual(new Uint8Array(0));
	});

	test('base64url unpadded input decodes correctly', () => {
		// rem=2 case: 1 byte encodes to 2 base64url chars (needs == to pad)
		const one = new Uint8Array([0xf0]);
		const enc = bytesToBase64(one, true);
		expect(enc.length % 4).not.toBe(0); // confirm it is unpadded
		expect(base64ToBytes(enc)).toEqual(one);

		// rem=3 case: 2 bytes encode to 3 base64url chars (needs = to pad)
		const two = new Uint8Array([0xf0, 0x0f]);
		const enc2 = bytesToBase64(two, true);
		expect(enc2.length % 4).not.toBe(0);
		expect(base64ToBytes(enc2)).toEqual(two);
	});

	test('base64ToBytes accepts legacy %3d padding', () => {
		// %3d was the old bytesToBase64(x, true) output — must remain decodable
		const one = new Uint8Array([0xf0]);
		const oldStyle = bytesToBase64(one)
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '%3d');
		expect(base64ToBytes(oldStyle)).toEqual(one);
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

	test('oversized input throws RangeError', () => {
		const big = new Uint8Array(33_000);
		expect(() => constantTimeEqual(big, big)).toThrow(RangeError);
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

	test('three arrays', () => {
		const a = new Uint8Array([1]);
		const b = new Uint8Array([2, 3]);
		const c = new Uint8Array([4, 5, 6]);
		expect(concat(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
	});

	test('single array returns copy', () => {
		const a = new Uint8Array([1, 2, 3]);
		const result = concat(a);
		expect(result).toEqual(a);
		expect(result).not.toBe(a); // must be a new allocation
	});

	test('no args returns empty', () => {
		expect(concat()).toEqual(new Uint8Array(0));
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
