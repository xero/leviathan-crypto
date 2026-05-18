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
// RFC 9162 §2.1.4 consistency-proof verifier against the
// transparency-dev/merkle testdata/consistency corpus.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init, Sha256Hasher,
	verifyConsistencyProof,
	base64ToBytes,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { merkleConsistencyRecords } from '../../vectors/merkle_consistency.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

function decodeStd(s: string): Uint8Array {
	return base64ToBytes(s);
}

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	await init({ sha2: wasmBytes });
});

describe('verifyConsistencyProof against transparency-dev/merkle testdata', () => {
	for (const rec of merkleConsistencyRecords) {
		it(`${rec.source}: ${rec.desc}`, () => {
			const proof = (rec.proofB64 ?? []).map(decodeStd);
			const oldRoot = decodeStd(rec.root1B64);
			const newRoot = decodeStd(rec.root2B64);

			let result: boolean;
			try {
				result = verifyConsistencyProof({
					hasher: Sha256Hasher,
					oldSize: rec.size1,
					newSize: rec.size2,
					oldRoot,
					newRoot,
					proof,
				});
			} catch {
				result = false;
			}

			if (rec.wantErr) expect(result, 'expected reject').toBe(false);
			else expect(result, 'expected accept').toBe(true);
		});
	}
});
