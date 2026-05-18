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
// Free-function proof verifier negative-path coverage. Exercises the
// boundary between malformed-proof rejection (returns false) and
// contract violation (throws RangeError). The happy-path positive
// cases live in the round-trip and corpus-driven test files; this
// file owns the rejection matrix.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	MemoryStorage, Sha256Hasher, Sha256Tree,
	verifyInclusionProof, verifyConsistencyProof,
	buildInclusionProof, buildConsistencyProof,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

function leafBytes(i: number): Uint8Array {
	const out = new Uint8Array(32);
	for (let j = 0; j < 32; j++) out[j] = (i + j) & 0xff;
	return out;
}

function buildTree(n: number): Sha256Tree {
	const t = new Sha256Tree(new MemoryStorage());
	for (let i = 0; i < n; i++) t.append(leafBytes(i));
	return t;
}

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	await init({ sha2: wasmBytes });
});

describe('verifyInclusionProof: contract violations throw', () => {
	const t = (): Sha256Tree => buildTree(8);

	it('negative leafIndex throws', () => {
		const tree = t();
		expect(() => verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: Sha256Hasher.hashLeaf(leafBytes(0)),
			leafIndex: -1,
			treeSize: 8,
			proof: [],
			rootHash: tree.rootHash(),
		})).toThrow(RangeError);
	});

	it('leafIndex past treeSize throws', () => {
		const tree = t();
		expect(() => verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: Sha256Hasher.hashLeaf(leafBytes(0)),
			leafIndex: 8,
			treeSize: 8,
			proof: [],
			rootHash: tree.rootHash(),
		})).toThrow(RangeError);
	});

	it('zero treeSize throws', () => {
		expect(() => verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: Sha256Hasher.hashLeaf(leafBytes(0)),
			leafIndex: 0,
			treeSize: 0,
			proof: [],
			rootHash: new Uint8Array(32),
		})).toThrow(RangeError);
	});

	it('wrong-sized rootHash throws', () => {
		const tree = t();
		expect(() => verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: Sha256Hasher.hashLeaf(leafBytes(0)),
			leafIndex: 0,
			treeSize: 8,
			proof: tree.getInclusionProof(0),
			rootHash: new Uint8Array(16),
		})).toThrow(RangeError);
	});
});

describe('verifyInclusionProof: malformed proofs return false', () => {
	it('wrong-length leafHash returns false', () => {
		const tree = buildTree(8);
		const proof = tree.getInclusionProof(0);
		expect(verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: new Uint8Array(16),
			leafIndex: 0,
			treeSize: 8,
			proof,
			rootHash: tree.rootHash(),
		})).toBe(false);
	});

	it('proof length one short of expected returns false', () => {
		const tree = buildTree(8);
		const proof = tree.getInclusionProof(0).slice(0, 2);
		expect(verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: Sha256Hasher.hashLeaf(leafBytes(0)),
			leafIndex: 0,
			treeSize: 8,
			proof,
			rootHash: tree.rootHash(),
		})).toBe(false);
	});

	it('proof step with wrong byte length returns false', () => {
		const tree = buildTree(8);
		const proof = tree.getInclusionProof(0);
		proof[1] = new Uint8Array(16);
		expect(verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: Sha256Hasher.hashLeaf(leafBytes(0)),
			leafIndex: 0,
			treeSize: 8,
			proof,
			rootHash: tree.rootHash(),
		})).toBe(false);
	});

	it('wrong rootHash returns false', () => {
		const tree = buildTree(8);
		const wrongRoot = new Uint8Array(32).fill(0xaa);
		expect(verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: Sha256Hasher.hashLeaf(leafBytes(0)),
			leafIndex: 0,
			treeSize: 8,
			proof: tree.getInclusionProof(0),
			rootHash: wrongRoot,
		})).toBe(false);
	});

	it('proof reordered between two leaves returns false', () => {
		const tree = buildTree(8);
		const proofA = tree.getInclusionProof(0);
		const rootHash = tree.rootHash();
		// Verify against the wrong leafIndex; the proof is structured
		// for leaf 0 but we claim leaf 7.
		expect(verifyInclusionProof({
			hasher: Sha256Hasher,
			leafHash: Sha256Hasher.hashLeaf(leafBytes(7)),
			leafIndex: 7,
			treeSize: 8,
			proof: proofA,
			rootHash,
		})).toBe(false);
	});
});

describe('verifyConsistencyProof: contract violations throw', () => {
	it('oldSize > newSize throws', () => {
		expect(() => verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 5, newSize: 3,
			oldRoot: new Uint8Array(32),
			newRoot: new Uint8Array(32),
			proof: [],
		})).toThrow(RangeError);
	});

	it('wrong-sized oldRoot throws', () => {
		const t = buildTree(8);
		expect(() => verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 3, newSize: 8,
			oldRoot: new Uint8Array(16),
			newRoot: t.rootHash(),
			proof: t.getConsistencyProof(3, 8),
		})).toThrow(RangeError);
	});

	it('wrong-sized newRoot throws', () => {
		const t = buildTree(8);
		expect(() => verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 3, newSize: 8,
			oldRoot: buildTree(3).rootHash(),
			newRoot: new Uint8Array(16),
			proof: t.getConsistencyProof(3, 8),
		})).toThrow(RangeError);
	});
});

describe('verifyConsistencyProof: malformed proofs return false', () => {
	it('non-empty proof when sizes are equal returns false', () => {
		const t = buildTree(8);
		const root = t.rootHash();
		expect(verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 8, newSize: 8,
			oldRoot: root, newRoot: root,
			proof: [new Uint8Array(32).fill(7)],
		})).toBe(false);
	});

	it('mismatched roots at equal sizes returns false', () => {
		const t = buildTree(8);
		const wrong = new Uint8Array(32).fill(0xbb);
		expect(verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 8, newSize: 8,
			oldRoot: t.rootHash(), newRoot: wrong,
			proof: [],
		})).toBe(false);
	});

	it('oldSize zero with non-empty new tree returns false', () => {
		const t = buildTree(8);
		expect(verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 0, newSize: 8,
			oldRoot: new Uint8Array(32),
			newRoot: t.rootHash(),
			proof: [],
		})).toBe(false);
	});

	it('empty proof for distinct non-zero sizes returns false', () => {
		const t = buildTree(8);
		expect(verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 3, newSize: 8,
			oldRoot: buildTree(3).rootHash(),
			newRoot: t.rootHash(),
			proof: [],
		})).toBe(false);
	});

	it('proof step with wrong byte length returns false', () => {
		const t = buildTree(8);
		const proof = t.getConsistencyProof(3, 8);
		proof[0] = new Uint8Array(16);
		expect(verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 3, newSize: 8,
			oldRoot: buildTree(3).rootHash(),
			newRoot: t.rootHash(),
			proof,
		})).toBe(false);
	});

	it('wrong oldRoot returns false even when newRoot matches the proof', () => {
		const t = buildTree(8);
		const wrongOld = new Uint8Array(32).fill(0xcc);
		expect(verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 3, newSize: 8,
			oldRoot: wrongOld, newRoot: t.rootHash(),
			proof: t.getConsistencyProof(3, 8),
		})).toBe(false);
	});
});

describe('builders drive the same wire format as the verifiers', () => {
	it('buildInclusionProof + verifyInclusionProof round-trip at size 13', () => {
		const tree = buildTree(13);
		const getNode = (level: number, index: number) =>
			(tree as unknown as { storage: MemoryStorage }).storage.getNode(level, index);
		for (let i = 0; i < 13; i++) {
			const proof = buildInclusionProof({
				hasher: Sha256Hasher,
				leafIndex: i,
				treeSize: 13,
				getNode,
			});
			expect(verifyInclusionProof({
				hasher: Sha256Hasher,
				leafHash: Sha256Hasher.hashLeaf(leafBytes(i)),
				leafIndex: i,
				treeSize: 13,
				proof,
				rootHash: tree.rootHash(),
			})).toBe(true);
		}
	});

	it('buildConsistencyProof + verifyConsistencyProof round-trip at sizes (5, 13)', () => {
		const tree = buildTree(13);
		const getNode = (level: number, index: number) =>
			(tree as unknown as { storage: MemoryStorage }).storage.getNode(level, index);
		const proof = buildConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 5, newSize: 13,
			getNode,
		});
		expect(verifyConsistencyProof({
			hasher: Sha256Hasher,
			oldSize: 5, newSize: 13,
			oldRoot: buildTree(5).rootHash(),
			newRoot: tree.rootHash(),
			proof,
		})).toBe(true);
	});

	it('builders throw on contract violations the verifiers throw on', () => {
		const tree = buildTree(4);
		const getNode = (level: number, index: number) =>
			(tree as unknown as { storage: MemoryStorage }).storage.getNode(level, index);
		expect(() => buildInclusionProof({
			hasher: Sha256Hasher, leafIndex: 4, treeSize: 4, getNode,
		})).toThrow(RangeError);
		expect(() => buildConsistencyProof({
			hasher: Sha256Hasher, oldSize: 5, newSize: 4, getNode,
		})).toThrow(RangeError);
	});
});
