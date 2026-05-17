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
// RFC 9162 §2.1.4 consistency-proof verification driven by the recorded
// BLAKE3 corpus. Every (fromSize, treeSize) pair runs through
// `verifyConsistencyProof` with the recorded proof and `Blake3Hasher`,
// asserting acceptance. The same proofs also round-trip back through
// `Blake3Tree.getConsistencyProof`, which proves the builder and the
// verifier agree on the wire format.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	Blake3Hasher, Blake3Tree,
	MemoryStorage,
	hexToBytes, utf8ToBytes,
	verifyConsistencyProof,
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

describe('Blake3Tree consistency proofs against recorded vectors', () => {
	for (const rec of merkleBlake3Records) {
		if (rec.consistency.length === 0) continue;
		it(`size ${rec.treeSize}: every recorded consistency proof verifies and the builder reproduces it`, () => {
			const newRoot = hexToBytes(rec.rootHex);
			const tree = buildTree(rec.treeSize);
			for (const cons of rec.consistency) {
				const oldRoot = hexToBytes(cons.fromRootHex);
				const recordedProof = cons.proofHex.map(hexToBytes);
				const accept = verifyConsistencyProof({
					hasher: Blake3Hasher,
					oldSize: cons.fromSize,
					newSize: rec.treeSize,
					oldRoot,
					newRoot,
					proof: recordedProof,
				});
				expect(accept, `size ${rec.treeSize} from ${cons.fromSize}: recorded proof rejected`).toBe(true);

				const builtProof = tree.getConsistencyProof(cons.fromSize, rec.treeSize);
				expect(builtProof.length, `size ${rec.treeSize} from ${cons.fromSize}: built proof length`).toBe(recordedProof.length);
				for (let k = 0; k < builtProof.length; k++) {
					expect(builtProof[k], `size ${rec.treeSize} from ${cons.fromSize} step ${k}`).toEqual(recordedProof[k]);
				}
			}
		}, 60_000);
	}

	it('rejects a swapped root pair', () => {
		const rec = merkleBlake3Records.find(r => r.treeSize === 7)!;
		const cons = rec.consistency.find(c => c.fromSize === 4)!;
		const oldRoot = hexToBytes(cons.fromRootHex);
		const newRoot = hexToBytes(rec.rootHex);
		const proof = cons.proofHex.map(hexToBytes);
		const accept = verifyConsistencyProof({
			hasher: Blake3Hasher,
			oldSize: cons.fromSize,
			newSize: rec.treeSize,
			oldRoot: newRoot,
			newRoot: oldRoot,
			proof,
		});
		expect(accept).toBe(false);
	});
});
