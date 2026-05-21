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
// RFC 9162 §2.1.3 inclusion-proof verifier against the
// transparency-dev/merkle testdata/inclusion corpus. Every record:
// drive `verifyInclusionProof`, catch RangeError throws as a reject
// signal, compare the outcome against the record's `wantErr` flag.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init, Sha256Hasher,
	verifyInclusionProof,
	base64ToBytes,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { merkleInclusionRecords } from '../../vectors/merkle_inclusion.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

function decodeStd(s: string): Uint8Array {
	// transparency-dev's Go encoding/json emits std-padded base64. The
	// project's `base64ToBytes` accepts both url-safe and std forms.
	return base64ToBytes(s);
}

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	await init({ sha2: wasmBytes });
});

describe('verifyInclusionProof against transparency-dev/merkle testdata', () => {
	for (const rec of merkleInclusionRecords) {
		it(`${rec.source}: ${rec.desc}`, () => {
			const proof = (rec.proofB64 ?? []).map(decodeStd);
			const rootHash = decodeStd(rec.rootB64);
			const leafHash = decodeStd(rec.leafHashB64);

			let result: boolean;
			try {
				result = verifyInclusionProof({
					hasher: Sha256Hasher,
					leafHash,
					leafIndex: rec.leafIdx,
					treeSize: rec.treeSize,
					proof,
					rootHash,
				});
			} catch {
				// Contract violations (wrong-sized root, leafIdx out of range,
				// treeSize zero) throw RangeError; that is the boolean-false
				// equivalent for the corpus's wantErr flag.
				result = false;
			}

			if (rec.wantErr) expect(result, 'expected reject').toBe(false);
			else expect(result, 'expected accept').toBe(true);
		});
	}
});
