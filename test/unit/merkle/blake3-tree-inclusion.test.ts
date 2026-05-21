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
// RFC 9162 §2.1.3 inclusion-proof verification driven by the recorded
// BLAKE3 corpus. Every (size, leafIdx) pair runs through
// `verifyInclusionProof` with the recorded proof and `Blake3Hasher`,
// asserting acceptance. The same proofs also round-trip back through
// `Blake3Tree.getInclusionProof`, which proves the builder and the
// verifier agree on the wire format. The hash-agnostic `verify*`
// surface is the same for SHA-256 and BLAKE3; this test confirms the
// abstraction holds.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	Blake3Hasher, Blake3Tree,
	MemoryStorage,
	hexToBytes, utf8ToBytes,
	verifyInclusionProof,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { merkleBlake3Records } from '../../vectors/merkle_blake3.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/blake3.wasm'));
	await init({ blake3: wasmBytes });
});

function buildTree(n: number): Blake3Tree {
	const t = new Blake3Tree(new MemoryStorage());
	for (let i = 0; i < n; i++) t.append(utf8ToBytes(`leaf-${i}`));
	return t;
}

describe('Blake3Tree inclusion proofs against recorded vectors', () => {
	for (const rec of merkleBlake3Records) {
		if (rec.treeSize === 0) continue;
		it(`size ${rec.treeSize}: every recorded proof verifies and the builder reproduces it`, () => {
			const rootHash = hexToBytes(rec.rootHex);
			const tree = buildTree(rec.treeSize);
			for (let i = 0; i < rec.treeSize; i++) {
				const recordedProof = rec.inclusionHex[i].map(hexToBytes);
				const leafHash = Blake3Hasher.hashLeaf(utf8ToBytes(`leaf-${i}`));
				const accept = verifyInclusionProof({
					hasher: Blake3Hasher,
					leafHash,
					leafIndex: i,
					treeSize: rec.treeSize,
					proof: recordedProof,
					rootHash,
				});
				expect(accept, `size ${rec.treeSize} leaf ${i}: recorded proof rejected`).toBe(true);

				const builtProof = tree.getInclusionProof(i);
				expect(builtProof.length, `size ${rec.treeSize} leaf ${i}: built proof length`).toBe(recordedProof.length);
				for (let k = 0; k < builtProof.length; k++) {
					expect(builtProof[k], `size ${rec.treeSize} leaf ${i} step ${k}`).toEqual(recordedProof[k]);
				}
			}
		}, 60_000);
	}

	it('rejects a tampered proof step', () => {
		const rec = merkleBlake3Records.find(r => r.treeSize === 7)!;
		const rootHash = hexToBytes(rec.rootHex);
		const leafIdx  = 3;
		const recordedProof = rec.inclusionHex[leafIdx].map(hexToBytes);
		expect(recordedProof.length).toBeGreaterThan(0);
		const tampered = recordedProof.map(p => new Uint8Array(p));
		tampered[0][0] ^= 0x01;
		const leafHash = Blake3Hasher.hashLeaf(utf8ToBytes(`leaf-${leafIdx}`));
		const accept = verifyInclusionProof({
			hasher: Blake3Hasher,
			leafHash,
			leafIndex: leafIdx,
			treeSize: rec.treeSize,
			proof: tampered,
			rootHash,
		});
		expect(accept).toBe(false);
	});
});
