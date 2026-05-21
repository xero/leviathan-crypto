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
// test/unit/aes/aes_round.test.ts
//
// Gate 3, single AES round vs FIPS 197 Appendix B intermediate states.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { getInstance } from '../../../src/ts/init.js';
import { aes128CipherVectors, aesRoundIntermediates128 } from '../../vectors/aes';
import { fromHex, toHex } from '../helpers';

beforeAll(async () => {
	await init({ aes: aesWasm });
});

interface AesDebugExports {
	memory:                  WebAssembly.Memory;
	getKeyOffset:            () => number;
	getBlockPt8xOffset:      () => number;
	getBlockCt8xOffset:      () => number;
	loadKey:                 (n: number) => number;
	singleRound:             (roundIdx: number) => void;
}

function getDebugExports(): AesDebugExports {
	return getInstance('aes').exports as unknown as AesDebugExports;
}

describe('AES single round (Gate 3)', () => {
	// GATE: applying SubBytes + ShiftRows + MixColumns + AddRoundKey for round
	// 1 to the FIPS 197 §B Round 1 start state must produce the §B Round 1
	// end state. Source values come from aesRoundIntermediates128
	// (FIPS 197 §B).
	it('FIPS 197 §B Round 1 produces expected end state', () => {
		const x   = getDebugExports();
		const mem = new Uint8Array(x.memory.buffer);
		const r1  = aesRoundIntermediates128[0];
		expect(r1.round).toBe(1);

		// Run the AES-128 key schedule from the §B example key.
		const key = fromHex(aes128CipherVectors[0].key);
		mem.set(key, x.getKeyOffset());
		expect(x.loadKey(16)).toBe(0);

		// Pre-load Round 1's start state into block 0; zero blocks 1..7.
		const start = fromHex(r1.start);
		mem.fill(0, x.getBlockPt8xOffset(), x.getBlockPt8xOffset() + 128);
		mem.set(start, x.getBlockPt8xOffset());

		// Apply round 1.
		x.singleRound(1);

		const got = mem.slice(x.getBlockCt8xOffset(), x.getBlockCt8xOffset() + 16);
		expect(toHex(got)).toBe(r1.end);
	});
});
