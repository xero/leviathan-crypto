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
import { init, SHA256 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha256Vectors, sha256CrossCheck } from '../../vectors/sha2.js';

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

// GATE — SHA-256 empty message: FIPS 180-4 (boundary case)
// Vector: sha2.ts[sha256Vectors[0]]
describe('Gate 3 — SHA-256 empty message', () => {
	test('SHA-256("") matches FIPS 180-4', () => {
		const h = new SHA256();
		const digest = h.hash(new Uint8Array(0));
		expect(toHex(digest)).toBe(sha256Vectors[0].expected);
		h.dispose();
	});
});

// ── SHA-256 ────────────────────────────────────────────────────────────────

describe('SHA-256', () => {
	for (const vec of sha256Vectors) {
		test(vec.description, () => {
			const h = new SHA256();
			const digest = h.hash(fromHex(vec.input));
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── Streaming ──────────────────────────────────────────────────────────────

describe('SHA-256 streaming', () => {
	test('split 256-byte input across 4 chunks matches single-call', () => {
		const input = new Uint8Array(256);
		for (let i = 0; i < 256; i++) input[i] = i & 0xff;

		const h = new SHA256();
		const expected = toHex(h.hash(input));

		// Hash same input via WASM streaming in 4 × 64-byte chunks
		const x = getInstance('sha2').exports as unknown as {
			memory: WebAssembly.Memory;
			getSha256InputOffset: () => number;
			getSha256OutOffset: () => number;
			sha256Init: () => void;
			sha256Update: (len: number) => void;
			sha256Final: () => void;
		};
		x.sha256Init();
		for (let i = 0; i < 4; i++) {
			const mem = new Uint8Array(x.memory.buffer);
			mem.set(input.subarray(i * 64, (i + 1) * 64), x.getSha256InputOffset());
			x.sha256Update(64);
		}
		x.sha256Final();
		const mem = new Uint8Array(x.memory.buffer);
		const result = toHex(mem.slice(x.getSha256OutOffset(), x.getSha256OutOffset() + 32));
		expect(result).toBe(expected);
		h.dispose();
	});
});

// ── wipeBuffers ─────────────────────────────────────────────────────────────

describe('wipeBuffers', () => {
	test('zeros SHA-256 hash state after dispose', () => {
		const h = new SHA256();
		h.hash(new Uint8Array([0x61, 0x62, 0x63]));
		h.dispose();

		const x = getInstance('sha2').exports as unknown as {
			memory: WebAssembly.Memory;
			getSha256HOffset: () => number;
		};
		const mem = new Uint8Array(x.memory.buffer);
		const off = x.getSha256HOffset();
		let nonZero = 0;
		for (let i = 0; i < 32; i++) nonZero |= mem[off + i];
		expect(nonZero).toBe(0);
	});
});

// ── leviathan cross-check ───────────────────────────────────────────────────

describe('leviathan cross-check', () => {
	test('SHA-256 matches leviathan reference for 4 inputs', () => {
		const h = new SHA256();
		for (const vec of sha256CrossCheck) {
			expect(toHex(h.hash(fromHex(vec.input))), vec.description).toBe(vec.expected);
		}
		h.dispose();
	});
});
