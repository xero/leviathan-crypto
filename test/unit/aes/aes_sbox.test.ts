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
// test/unit/aes/aes_sbox.test.ts
//
// Gate 2 — Canright bitsliced S-box vs FIPS 197 §5.1.1 Figure 7 (= aesSboxTable).

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { getInstance } from '../../../src/ts/init.js';
import { aesSboxTable } from '../../vectors/aes';

beforeAll(async () => {
	await init({ aes: aesWasm });
});

interface AesDebugExports {
	memory:             WebAssembly.Memory;
	getBlockPt8xOffset: () => number;
	getBlockCt8xOffset: () => number;
	sboxRoundTrip:      () => void;
}

function getDebugExports(): AesDebugExports {
	return getInstance('aes').exports as unknown as AesDebugExports;
}

describe('AES Canright S-box (Gate 2)', () => {
	// GATE: for every byte 0x00..0xFF, the bitsliced Canright S-box must
	// produce aesSboxTable[b] for input b. The aesSboxTable constant was
	// transcribed from FIPS 197 §5.1.1 Figure 7 in test/vectors/aes.ts.
	it('all 256 byte inputs match FIPS 197 S-box table', () => {
		const x   = getDebugExports();
		const mem = new Uint8Array(x.memory.buffer);
		const pt  = x.getBlockPt8xOffset();
		const ct  = x.getBlockCt8xOffset();
		for (let b = 0; b < 256; b++) {
			mem.fill(0, pt, pt + 128);
			mem[pt] = b;
			x.sboxRoundTrip();
			const got = mem[ct];
			expect(got, `S(${b.toString(16)}) — got 0x${got.toString(16)}, want 0x${aesSboxTable[b].toString(16)}`)
				.toBe(aesSboxTable[b]);
		}
	});
});
