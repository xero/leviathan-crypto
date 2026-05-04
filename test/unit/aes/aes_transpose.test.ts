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
// test/unit/aes/aes_transpose.test.ts
//
// Gate 1 — bit transposition round-trip.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { getInstance } from '../../../src/ts/init.js';
import { aes128CipherVectors } from '../../vectors/aes';
import { fromHex } from '../helpers';

beforeAll(async () => {
	await init({ aes: aesWasm });
});

interface AesDebugExports {
	memory:               WebAssembly.Memory;
	getBlockPt8xOffset:   () => number;
	getBlockCt8xOffset:   () => number;
	transposeRoundTrip:   () => void;
}

function getDebugExports(): AesDebugExports {
	return getInstance('aes').exports as unknown as AesDebugExports;
}

describe('AES bit transposition (Gate 1)', () => {
	// GATE: transposeIn followed by transposeOut must be the identity.
	// If this fails, the bitsliced layout in src/asm/aes/aes.ts is wrong.

	it('round-trip identity: 128 distinct bytes', () => {
		const x   = getDebugExports();
		const mem = new Uint8Array(x.memory.buffer);
		const input = new Uint8Array(128);
		for (let i = 0; i < 128; i++) input[i] = i;
		mem.set(input, x.getBlockPt8xOffset());
		x.transposeRoundTrip();
		const output = mem.slice(x.getBlockCt8xOffset(), x.getBlockCt8xOffset() + 128);
		expect(Array.from(output)).toEqual(Array.from(input));
	});

	it('round-trip identity: all zeros', () => {
		const x   = getDebugExports();
		const mem = new Uint8Array(x.memory.buffer);
		const input = new Uint8Array(128); // all zero
		mem.set(input, x.getBlockPt8xOffset());
		x.transposeRoundTrip();
		const output = mem.slice(x.getBlockCt8xOffset(), x.getBlockCt8xOffset() + 128);
		expect(Array.from(output)).toEqual(Array.from(input));
	});

	it('round-trip identity: all 0xFF', () => {
		const x   = getDebugExports();
		const mem = new Uint8Array(x.memory.buffer);
		const input = new Uint8Array(128).fill(0xff);
		mem.set(input, x.getBlockPt8xOffset());
		x.transposeRoundTrip();
		const output = mem.slice(x.getBlockCt8xOffset(), x.getBlockCt8xOffset() + 128);
		expect(Array.from(output)).toEqual(Array.from(input));
	});

	it('round-trip identity: FIPS 197 §B plaintext + 7 dummy blocks', () => {
		const x   = getDebugExports();
		const mem = new Uint8Array(x.memory.buffer);
		const pt  = fromHex(aes128CipherVectors[0].pt);
		const input = new Uint8Array(128);
		input.set(pt, 0);
		for (let b = 1; b < 8; b++) {
			for (let i = 0; i < 16; i++) {
				input[b * 16 + i] = (b * 16 + i) & 0xff;
			}
		}
		mem.set(input, x.getBlockPt8xOffset());
		x.transposeRoundTrip();
		const output = mem.slice(x.getBlockCt8xOffset(), x.getBlockCt8xOffset() + 128);
		expect(Array.from(output)).toEqual(Array.from(input));
	});
});
