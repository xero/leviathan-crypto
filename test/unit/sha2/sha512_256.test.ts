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
 * SHA-512/256 Known-Answer Tests, FIPS 180-4 §6.7.2
 *
 * Source: FIPS 180-4 (SHA Standard), §5.3.6.2 IV + §6.7.2 algorithm definition
 * Files:  vectors/sha2.ts (sha512_256Vectors, sha512_256CrossCheck)
 */
import { describe, test, expect, beforeAll } from 'vitest';
import { init, SHA512_256 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha512_256Vectors, sha512_256CrossCheck } from '../../vectors/sha2.js';

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

// GATE: SHA-512/256 empty message: FIPS 180-4 (boundary case)
// Vector: sha2.ts[sha512_256Vectors[0]]
describe('Gate, SHA-512/256 empty message', () => {
	test('SHA-512/256("") matches FIPS 180-4 §6.7.2 / §5.3.6.2 IV', () => {
		const h = new SHA512_256();
		const digest = h.hash(new Uint8Array(0));
		expect(toHex(digest)).toBe(sha512_256Vectors[0].expected);
		h.dispose();
	});
});

// ── SHA-512/256 ────────────────────────────────────────────────────────────

describe('SHA-512/256', () => {
	for (const vec of sha512_256Vectors) {
		test(vec.description, () => {
			const h = new SHA512_256();
			const digest = h.hash(fromHex(vec.input));
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── Streaming ──────────────────────────────────────────────────────────────

describe('SHA-512/256 streaming', () => {
	test('split 512-byte input across 4 chunks matches single-call', () => {
		const input = new Uint8Array(512);
		for (let i = 0; i < 512; i++) input[i] = i & 0xff;

		const h = new SHA512_256();
		const expected = toHex(h.hash(input));

		const x = getInstance('sha2').exports as unknown as {
			memory: WebAssembly.Memory;
			getSha512InputOffset: () => number;
			getSha512OutOffset: () => number;
			sha512_256Init: () => void;
			sha512Update: (len: number) => void;
			sha512_256Final: () => void;
		};
		x.sha512_256Init();
		for (let i = 0; i < 4; i++) {
			const mem = new Uint8Array(x.memory.buffer);
			mem.set(input.subarray(i * 128, (i + 1) * 128), x.getSha512InputOffset());
			x.sha512Update(128);
		}
		x.sha512_256Final();
		const mem = new Uint8Array(x.memory.buffer);
		const result = toHex(mem.slice(x.getSha512OutOffset(), x.getSha512OutOffset() + 32));
		expect(result).toBe(expected);
		h.dispose();
	});
});

// ── leviathan cross-check ───────────────────────────────────────────────────

describe('leviathan cross-check', () => {
	test('SHA-512/256 matches leviathan reference for 4 inputs', () => {
		const h = new SHA512_256();
		for (const vec of sha512_256CrossCheck) {
			expect(toHex(h.hash(fromHex(vec.input))), vec.description).toBe(vec.expected);
		}
		h.dispose();
	});
});
