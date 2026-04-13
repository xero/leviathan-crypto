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
import { init, SHA512, SHA384 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha512Vectors, sha384Vectors, sha512CrossCheck, sha384CrossCheck } from '../../vectors/sha2.js';

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

// GATE — SHA-512 "abc": FIPS 180-4 §C.1
// Vector: sha2.ts[sha512Vectors[1]]
describe('Gate 4 — SHA-512 "abc"', () => {
	test('SHA-512("abc") matches FIPS 180-4 §C.1', () => {
		const h = new SHA512();
		const digest = h.hash(new Uint8Array([0x61, 0x62, 0x63]));
		expect(toHex(digest)).toBe(sha512Vectors[1].expected);
		h.dispose();
	});
});

// ── SHA-512 ────────────────────────────────────────────────────────────────

describe('SHA-512', () => {
	for (const vec of sha512Vectors) {
		test(vec.description, () => {
			const h = new SHA512();
			const digest = h.hash(fromHex(vec.input));
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── SHA-384 ────────────────────────────────────────────────────────────────

describe('SHA-384', () => {
	for (const vec of sha384Vectors) {
		test(vec.description, () => {
			const h = new SHA384();
			const digest = h.hash(fromHex(vec.input));
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── Streaming ──────────────────────────────────────────────────────────────

describe('SHA-512 streaming', () => {
	test('split 512-byte input across 4 chunks matches single-call', () => {
		const input = new Uint8Array(512);
		for (let i = 0; i < 512; i++) input[i] = i & 0xff;

		const h = new SHA512();
		const expected = toHex(h.hash(input));

		const x = getInstance('sha2').exports as unknown as {
			memory: WebAssembly.Memory;
			getSha512InputOffset: () => number;
			getSha512OutOffset: () => number;
			sha512Init: () => void;
			sha512Update: (len: number) => void;
			sha512Final: () => void;
		};
		x.sha512Init();
		for (let i = 0; i < 4; i++) {
			const mem = new Uint8Array(x.memory.buffer);
			mem.set(input.subarray(i * 128, (i + 1) * 128), x.getSha512InputOffset());
			x.sha512Update(128);
		}
		x.sha512Final();
		const mem = new Uint8Array(x.memory.buffer);
		const result = toHex(mem.slice(x.getSha512OutOffset(), x.getSha512OutOffset() + 64));
		expect(result).toBe(expected);
		h.dispose();
	});
});

// ── leviathan cross-check ───────────────────────────────────────────────────

describe('leviathan cross-check', () => {
	test('SHA-512 matches leviathan reference for 4 inputs', () => {
		const h = new SHA512();
		for (const vec of sha512CrossCheck) {
			expect(toHex(h.hash(fromHex(vec.input))), vec.description).toBe(vec.expected);
		}
		h.dispose();
	});

	test('SHA-384 matches leviathan reference for 3 inputs', () => {
		const h = new SHA384();
		for (const vec of sha384CrossCheck) {
			expect(toHex(h.hash(fromHex(vec.input))), vec.description).toBe(vec.expected);
		}
		h.dispose();
	});
});
