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
	sboxWordExport:     (w: number) => number;
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

describe('AES Boyar-Peralta scalar S-box (key-schedule path)', () => {
	// GATE: for every byte 0x00..0xFF, the Boyar-Peralta scalar S-box
	// (used by `keyExpansion` for SubWord) must produce aesSboxTable[b]
	// for input b. Reference: SLP_AES_113 from Peralta's circuit-minimization
	// page (cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt) —
	// transcribed into `sboxWord` in src/asm/aes/aes.ts. Expected outputs
	// come from FIPS 197 §5.1.1 Figure 7 via the same `aesSboxTable`
	// constant used by Gate 2.
	it('all 256 byte inputs in each of 4 lane positions match FIPS 197 S-box table', () => {
		const x = getDebugExports();
		// Exhaustive lane-independence: place input b at lane L (others zero)
		// and verify every output lane independently. Output[L] must be S(b);
		// the three other output lanes must be S(0) = 0x63. 1024 invocations,
		// 4096 assertions — proves each of the four scalar circuits is correct
		// across the full 256-byte input space.
		for (let lane = 0; lane < 4; lane++) {
			const shift = lane * 8;
			for (let b = 0; b < 256; b++) {
				const w   = (b << shift) >>> 0;
				const out = x.sboxWordExport(w);
				for (let j = 0; j < 4; j++) {
					const inB   = j === lane ? b : 0;
					const outB  = (out >>> (j * 8)) & 0xff;
					const wantB = aesSboxTable[inB];
					expect(
						outB,
						`lane ${lane}, S(0x${b.toString(16)}) at byte ${j}: got 0x${outB.toString(16)}, want 0x${wantB.toString(16)}`,
					).toBe(wantB);
				}
			}
		}
	});

	it('packed 4-byte inputs match per-byte expectation', () => {
		const x = getDebugExports();
		// A handful of packed inputs covering corner cases (zero, one, mixed,
		// affine boundaries) and a few arbitrary 4-byte words. Each output
		// byte must independently match aesSboxTable on its source byte.
		const inputs = [
			0x00000000, 0xffffffff, 0x01020304, 0x53636363,
			0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0,
		];
		for (const w of inputs) {
			const out = x.sboxWordExport(w >>> 0);
			for (let j = 0; j < 4; j++) {
				const inB  = (w >>> (j * 8)) & 0xff;
				const outB = (out >>> (j * 8)) & 0xff;
				expect(outB, `byte ${j} of S(0x${w.toString(16)}): in=0x${inB.toString(16)} got=0x${outB.toString(16)} want=0x${aesSboxTable[inB].toString(16)}`)
					.toBe(aesSboxTable[inB]);
			}
		}
	});
});
