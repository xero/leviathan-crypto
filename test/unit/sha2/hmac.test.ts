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
 * HMAC-SHA256, HMAC-SHA512, HMAC-SHA384 Known-Answer Tests — RFC 4231
 *
 * Source: RFC 4231 — HMAC-SHA Identifiers and Test Vectors
 * Files:  vectors/sha2.ts (hmacSha256Vectors, hmacSha512Vectors, hmacSha384Vectors, hmacCrossCheck)
 */
import { describe, test, expect, beforeAll } from 'vitest';
import { init, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384 } from '../../../src/ts/index.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import {
	hmacSha256Vectors, hmacSha512Vectors, hmacSha384Vectors,
	hmacCrossCheck,
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
	await init({ sha2: sha2Wasm });
});

// GATE: HMAC-SHA256 TC1: RFC 4231 §4.2
// Vector: sha2.ts[hmacSha256Vectors[0]]
describe('Gate 5 — HMAC-SHA256 TC1', () => {
	test('HMAC-SHA256 TC1 matches RFC 4231 §4.2', () => {
		const vec = hmacSha256Vectors[0];
		const h = new HMAC_SHA256();
		const tag = h.hash(fromHex(vec.key), fromHex(vec.input));
		expect(toHex(tag)).toBe(vec.expected);
		h.dispose();
	});
});

// GATE: HMAC-SHA512 TC6: RFC 4231 §4.7
// Vector: sha2.ts[hmacSha512Vectors[2]]
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
	test('HMAC-SHA256 matches leviathan reference', () => {
		const vec = hmacCrossCheck[0];
		const h = new HMAC_SHA256();
		expect(toHex(h.hash(fromHex(vec.key), fromHex(vec.msg)))).toBe(vec.expected);
		h.dispose();
	});

	test('HMAC-SHA512 matches leviathan reference', () => {
		const vec = hmacCrossCheck[1];
		const h = new HMAC_SHA512();
		expect(toHex(h.hash(fromHex(vec.key), fromHex(vec.msg)))).toBe(vec.expected);
		h.dispose();
	});

	test('HMAC-SHA384 matches leviathan reference', () => {
		const vec = hmacCrossCheck[2];
		const h = new HMAC_SHA384();
		expect(toHex(h.hash(fromHex(vec.key), fromHex(vec.msg)))).toBe(vec.expected);
		h.dispose();
	});
});
