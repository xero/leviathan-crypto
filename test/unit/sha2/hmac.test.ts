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
import { init, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384 } from '../../../src/ts/index.js';
import {
	hmacSha256Vectors, hmacSha512Vectors, hmacSha384Vectors,
} from '../../vectors/sha2.js';

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return bytes;
}

beforeAll(async () => {
	await init('sha2');
});

// ── Gate 5: HMAC-SHA256 TC1 (RFC 4231 §4.2) ───────────────────────────────
// GATE
describe('Gate 5 — HMAC-SHA256 TC1', () => {
	test('HMAC-SHA256 TC1 matches RFC 4231 §4.2', () => {
		const vec = hmacSha256Vectors[0];
		const h = new HMAC_SHA256();
		const tag = h.hash(fromHex(vec.key), fromHex(vec.input));
		expect(toHex(tag)).toBe(vec.expected);
		h.dispose();
	});
});

// ── Gate 6: HMAC-SHA512 TC6 (RFC 4231 §4.7, 131-byte key) ─────────────────
// GATE
describe('Gate 6 — HMAC-SHA512 TC6', () => {
	test('HMAC-SHA512 TC6 matches RFC 4231 §4.7 (key > block size)', () => {
		const vec = hmacSha512Vectors[2]; // TC6
		const h = new HMAC_SHA512();
		const tag = h.hash(fromHex(vec.key), fromHex(vec.input));
		expect(toHex(tag)).toBe(vec.expected);
		h.dispose();
	});
});

// ── HMAC-SHA256 ────────────────────────────────────────────────────────────

describe('HMAC-SHA256', () => {
	for (const vec of hmacSha256Vectors) {
		test(vec.description, () => {
			const h = new HMAC_SHA256();
			const tag = h.hash(fromHex(vec.key), fromHex(vec.input));
			expect(toHex(tag)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── HMAC-SHA512 ────────────────────────────────────────────────────────────

describe('HMAC-SHA512', () => {
	for (const vec of hmacSha512Vectors) {
		test(vec.description, () => {
			const h = new HMAC_SHA512();
			const tag = h.hash(fromHex(vec.key), fromHex(vec.input));
			expect(toHex(tag)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── HMAC-SHA384 ────────────────────────────────────────────────────────────

describe('HMAC-SHA384', () => {
	for (const vec of hmacSha384Vectors) {
		test(vec.description, () => {
			const h = new HMAC_SHA384();
			const tag = h.hash(fromHex(vec.key), fromHex(vec.input));
			expect(toHex(tag)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── leviathan cross-check ───────────────────────────────────────────────────

describe('leviathan cross-check', () => {
	const key = new Uint8Array(32).fill(0x42);
	const msg = new TextEncoder().encode('leviathan cross-check message');

	// Values verified against Node.js crypto.createHmac()
	const levHmac256 = 'b3e42787e890590efbfb8c8fb3a905b655bfa6b0e0e68d4c0883e861203b58fb';
	const levHmac512 = 'c024d889341c1c341f1b5e44bcdd82556e263e2d757dcba4d91550d8872594eced5fcab776bb9178e96c62a9933a01ab13e4b785877735e9c890bf8803f52cb0';
	const levHmac384 = 'e63f7b89cc4023b166b44377be5fdf171993c5f2d480b79b3ae015a002e23992cd75cc979706a922d2104b0690318d18';

	test('HMAC-SHA256 matches leviathan reference', () => {
		const h = new HMAC_SHA256();
		expect(toHex(h.hash(key, msg))).toBe(levHmac256);
		h.dispose();
	});

	test('HMAC-SHA512 matches leviathan reference', () => {
		const h = new HMAC_SHA512();
		expect(toHex(h.hash(key, msg))).toBe(levHmac512);
		h.dispose();
	});

	test('HMAC-SHA384 matches leviathan reference', () => {
		const h = new HMAC_SHA384();
		expect(toHex(h.hash(key, msg))).toBe(levHmac384);
		h.dispose();
	});
});
