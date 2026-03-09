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
import { sha512Vectors, sha384Vectors } from '../../vectors/sha2.js';

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

// ── Gate 4: SHA-512 "abc" ──────────────────────────────────────────────────
// GATE
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
	const crossInputs = [
		{ label: 'empty',     data: new Uint8Array(0) },
		{ label: '"abc"',     data: new Uint8Array([0x61, 0x62, 0x63]) },
		{ label: 'fox',       data: new TextEncoder().encode('The quick brown fox jumps over the lazy dog') },
		{ label: '"a"×200',   data: new Uint8Array(200).fill(0x61) },
	];

	// Values verified against Node.js crypto.createHash('sha512')
	const levSha512 = [
		'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
		'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
		'07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6',
		'4b11459c33f52a22ee8236782714c150a3b2c60994e9acee17fe68947a3e6789f31e7668394592da7bef827cddca88c4e6f86e4df7ed1ae6cba71f3e98faee9f',
	];

	const levSha384 = [
		'38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
		'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
		'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1',
	];

	test('SHA-512 matches leviathan reference for 4 inputs', () => {
		const h = new SHA512();
		for (let i = 0; i < crossInputs.length; i++) {
			expect(toHex(h.hash(crossInputs[i].data)), crossInputs[i].label).toBe(levSha512[i]);
		}
		h.dispose();
	});

	test('SHA-384 matches leviathan reference for 3 inputs', () => {
		const h = new SHA384();
		for (let i = 0; i < 3; i++) {
			expect(toHex(h.hash(crossInputs[i].data)), crossInputs[i].label).toBe(levSha384[i]);
		}
		h.dispose();
	});
});
