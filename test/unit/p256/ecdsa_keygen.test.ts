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
 * Validate `ecdsaKeygen` against ACVP keyGen records: derive pk from d
 * (passed as the seed), decompress, and confirm the resulting affine
 * (x, y) matches the ACVP-supplied (qx, qy). Mirrors the FIPS 186-5
 * §A.4 keygen contract — the substrate is fed d directly (caller is
 * responsible for ensuring d is in [1, n-1]; the substrate traps on
 * d == 0 mod n).
 *
 * Per AGENTS.md §3, ACVP expected values are sourced from
 * test/vectors/ecdsa_p256_keygen.ts (transcribed verbatim from
 * ACVP-Server) and never modified.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	ecdsa_p256_keygen_tg3, ecdsa_p256_keygen_tg4,
} from '../../vectors/ecdsa_p256_keygen.js';
import {
	loadP256, hexToBytes, bytesToHex, readBytes, writeBytes,
	testSlot,
	type P256Exports,
} from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

const allKeyGenVectors = [...ecdsa_p256_keygen_tg3, ...ecdsa_p256_keygen_tg4];

describe('p256 ecdsaKeygen', () => {
	for (const vec of allKeyGenVectors) {
		it(`tcId ${vec.tcId} derives matching (qx, qy) from d`, () => {
			wasm.wipeBuffers();
			const seedOff = testSlot(0);      // 32 bytes (= d)
			const pkOff   = testSlot(32);     // 33 bytes compressed
			const pOff    = testSlot(96);     // 96 bytes projective
			const xOff    = testSlot(192);    // 32 bytes affine x bytes BE
			const yOff    = testSlot(224);    // 32 bytes affine y bytes BE

			writeBytes(wasm.memory, seedOff, hexToBytes(vec.d));
			wasm.ecdsaKeygen(seedOff, pkOff);

			// Decompress the compressed pk and read out the affine
			// coordinates for comparison.
			expect(wasm.pointDecompress(pOff, pkOff)).toBe(1);

			// Compute affine (x, y) by feToBytes after pointAffinify.
			// (pointDecompress sets Z = 1, so affinify is essentially a
			// no-op, but the call exercises the full path.)
			const xFEoff = testSlot(256);
			const yFEoff = testSlot(288);
			wasm.pointAffinify(pOff, xFEoff, yFEoff);
			wasm.feToBytes(xOff, xFEoff);
			wasm.feToBytes(yOff, yFEoff);

			expect(bytesToHex(readBytes(wasm.memory, xOff, 32)).toLowerCase())
				.toBe(vec.qx.toLowerCase());
			expect(bytesToHex(readBytes(wasm.memory, yOff, 32)).toLowerCase())
				.toBe(vec.qy.toLowerCase());
		});
	}
});
