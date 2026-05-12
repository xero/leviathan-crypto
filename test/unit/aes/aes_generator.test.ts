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
// test/unit/aes/aes_generator.test.ts
//
// AESGenerator coverage. The test reconstructs the expected keystream
// independently using the raw AES WASM exports (loadKey + encryptBlock)
// , this is the cross-check pattern that proves AESGenerator does not
// silently diverge from the AES-256 ECB primitive.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { AESGenerator } from '../../../src/ts/aes/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';

beforeAll(async () => {
	await init({ aes: aesWasm });
});

interface AesMin {
	memory:           WebAssembly.Memory;
	getKeyOffset:     () => number;
	getBlockPtOffset: () => number;
	getBlockCtOffset: () => number;
	loadKey:          (n: number) => number;
	encryptBlock:     () => void;
	wipeBuffers:      () => void;
}

/**
 * Reconstruct the expected AESGenerator keystream by driving the raw AES
 * WASM exports with the same key + counter + counter-increment rule.
 */
function expected(key: Uint8Array, counter: Uint8Array, n: number): Uint8Array {
	const x = getInstance('aes').exports as unknown as AesMin;
	const mem = new Uint8Array(x.memory.buffer);
	const c = counter.slice();
	try {
		mem.set(key, x.getKeyOffset());
		expect(x.loadKey(32)).toBe(0);
		const blocks = Math.ceil(n / 16);
		const out = new Uint8Array(n);
		const ptOff = x.getBlockPtOffset();
		const ctOff = x.getBlockCtOffset();
		for (let i = 0; i < blocks; i++) {
			mem.set(c, ptOff);
			x.encryptBlock();
			const off = i * 16;
			const len = Math.min(16, n - off);
			out.set(mem.subarray(ctOff, ctOff + len), off);
			for (let j = 0; j < 16; j++) {
				if (++c[j] !== 0) break;
			}
		}
		return out;
	} finally {
		x.wipeBuffers();
	}
}

describe('AESGenerator, keystream cross-check vs raw AES', () => {
	const key = new Uint8Array(32);
	for (let i = 0; i < 32; i++) key[i] = (i * 7 + 1) & 0xff;
	const counter = new Uint8Array(16);
	for (let i = 0; i < 16; i++) counter[i] = (i * 13 + 5) & 0xff;

	// Empty, sub-block, exactly one block, partial second, multi-block,
	// large block. The upper-bound rejection is tested separately in the
	// argument-validation block; allocating 2^30 bytes here would OOM.
	const SIZES = [0, 1, 16, 17, 64, 1024, 1 << 20];

	for (const n of SIZES) {
		it(`n=${n}: matches raw AES counter-mode`, () => {
			const out = AESGenerator.generate(key, counter, n);
			const ref = expected(key, counter, n);
			expect(out.length).toBe(n);
			expect(Array.from(out)).toEqual(Array.from(ref));
		});
	}
});

describe('AESGenerator, counter increment carry', () => {
	it('rolls a byte from 0xff to 0x00 and carries to the next', () => {
		const key = new Uint8Array(32).fill(0x99);
		// Counter low byte at 0xfe so the second block flips it to 0xff and
		// the third triggers the carry from byte 0 → byte 1.
		const counter = new Uint8Array(16);
		counter[0] = 0xfe;
		const out = AESGenerator.generate(key, counter, 48);
		// Independently recompute via raw exports: same counter walk.
		const ref = expected(key, counter, 48);
		expect(Array.from(out)).toEqual(Array.from(ref));
	});
});

describe('AESGenerator, argument validation', () => {
	const key32 = new Uint8Array(32);
	const counter16 = new Uint8Array(16);

	it('rejects key.length !== 32', () => {
		expect(() => AESGenerator.generate(new Uint8Array(16), counter16, 16))
			.toThrow(/AESGenerator: key must be 32 bytes/);
		expect(() => AESGenerator.generate(new Uint8Array(31), counter16, 16))
			.toThrow(/AESGenerator: key must be 32 bytes/);
	});

	it('rejects counter.length !== 16', () => {
		expect(() => AESGenerator.generate(key32, new Uint8Array(15), 16))
			.toThrow(/AESGenerator: counter must be 16 bytes/);
		expect(() => AESGenerator.generate(key32, new Uint8Array(8), 16))
			.toThrow(/AESGenerator: counter must be 16 bytes/);
	});

	it('rejects negative or non-integer n', () => {
		expect(() => AESGenerator.generate(key32, counter16, -1))
			.toThrow(/AESGenerator: n must be a non-negative safe integer/);
		expect(() => AESGenerator.generate(key32, counter16, 1.5))
			.toThrow(/AESGenerator: n must be a non-negative safe integer/);
	});

	it('rejects n > 2^30', () => {
		expect(() => AESGenerator.generate(key32, counter16, (2 ** 30) + 1))
			.toThrow(/AESGenerator: n must be a non-negative safe integer/);
	});
});

describe('AESGenerator, non-mutation of caller buffers', () => {
	it('does not mutate the caller-provided counter', () => {
		const key = new Uint8Array(32).fill(0x77);
		const counter = new Uint8Array(16).fill(0xaa);
		const before = counter.slice();
		AESGenerator.generate(key, counter, 64);
		expect(Array.from(counter)).toEqual(Array.from(before));
	});
});
