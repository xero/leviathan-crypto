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
// Sha256Tree round-trip: append + rootHash, build + verify inclusion
// proofs for every leaf at every size 1..256, build + verify
// consistency proofs for every (oldSize, newSize) pair in 1..32.
// splitPoint and the node-index math live under their own describe
// block.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	MemoryStorage, Sha256Hasher, Sha256Tree,
	splitPoint,
	verifyInclusionProof, verifyConsistencyProof,
	bytesToHex,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

function leafBytes(i: number): Uint8Array {
	// Deterministic 32-byte payload keyed on i so tests are reproducible
	// without relying on a PRNG.
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

describe('splitPoint invariant k < n <= 2*k', () => {
	it('holds for n in 2..1024', () => {
		for (let n = 2; n <= 1024; n++) {
			const k = splitPoint(n);
			// k is a power of two
			expect((k & (k - 1)) === 0).toBe(true);
			expect(k).toBeLessThan(n);
			expect(n).toBeLessThanOrEqual(2 * k);
		}
	});

	it('rejects n < 2', () => {
		expect(() => splitPoint(1)).toThrow();
		expect(() => splitPoint(0)).toThrow();
		expect(() => splitPoint(-1)).toThrow();
		expect(() => splitPoint(1.5)).toThrow();
	});
});

describe('Sha256Tree append and rootHash', () => {
	it('empty tree root is SHA-256()', () => {
		const t = new Sha256Tree(new MemoryStorage());
		expect(t.size()).toBe(0);
		expect(bytesToHex(t.rootHash())).toBe(
			'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
		);
	});

	it('size-1 tree root equals hashLeaf of that single leaf', () => {
		const t = new Sha256Tree(new MemoryStorage());
		const leaf = leafBytes(0);
		const { leafIndex, leafHash } = t.append(leaf);
		expect(leafIndex).toBe(0);
		expect(t.size()).toBe(1);
		expect(t.rootHash()).toEqual(leafHash);
		expect(t.rootHash()).toEqual(Sha256Hasher.hashLeaf(leaf));
	});

	it('size-2 tree root equals hashInternal(hashLeaf(L0), hashLeaf(L1))', () => {
		const t = new Sha256Tree(new MemoryStorage());
		t.append(leafBytes(0));
		t.append(leafBytes(1));
		const expected = Sha256Hasher.hashInternal(
			Sha256Hasher.hashLeaf(leafBytes(0)),
			Sha256Hasher.hashLeaf(leafBytes(1)),
		);
		expect(t.rootHash()).toEqual(expected);
	});
});

describe('Sha256Tree inclusion proof round-trip', () => {
	it('every leaf in every size 1..256 verifies against the current root', () => {
		for (let n = 1; n <= 256; n++) {
			const t = buildTree(n);
			const rootHash = t.rootHash();
			for (let i = 0; i < n; i++) {
				const proof = t.getInclusionProof(i);
				const leafHash = Sha256Hasher.hashLeaf(leafBytes(i));
				const ok = verifyInclusionProof({
					hasher: Sha256Hasher, leafHash, leafIndex: i, treeSize: n, proof, rootHash,
				});
				expect(ok, `size ${n} leaf ${i}`).toBe(true);
			}
		}
	}, 30_000);

	it('mid-history proof verifies against the past root for size 64', () => {
		const t = buildTree(64);
		// Snapshot the root at sizes 7, 13, 32. Re-create those past
		// snapshots from fresh trees so we have an independent reference.
		for (const past of [7, 13, 32, 50]) {
			const refRoot = buildTree(past).rootHash();
			for (let i = 0; i < past; i++) {
				const proof = t.getInclusionProof(i, past);
				const leafHash = Sha256Hasher.hashLeaf(leafBytes(i));
				const ok = verifyInclusionProof({
					hasher: Sha256Hasher, leafHash, leafIndex: i, treeSize: past, proof, rootHash: refRoot,
				});
				expect(ok, `past size ${past}, leaf ${i}`).toBe(true);
			}
		}
	});
});

describe('Sha256Tree consistency proof round-trip', () => {
	it('every (oldSize, newSize) in 1..32 verifies', () => {
		const trees: Sha256Tree[] = [];
		const roots: Uint8Array[] = [];
		for (let n = 0; n <= 32; n++) {
			const t = buildTree(n);
			trees.push(t);
			roots.push(t.rootHash());
		}
		const current = trees[32]!;
		for (let oldSize = 1; oldSize <= 32; oldSize++) {
			for (let newSize = oldSize; newSize <= 32; newSize++) {
				const proof = current.getConsistencyProof(oldSize, newSize);
				const ok = verifyConsistencyProof({
					hasher: Sha256Hasher,
					oldSize, newSize,
					oldRoot: roots[oldSize]!,
					newRoot: roots[newSize]!,
					proof,
				});
				expect(ok, `old=${oldSize} new=${newSize}`).toBe(true);
			}
		}
	}, 30_000);

	it('rejects a swapped root pair', () => {
		const t = buildTree(8);
		const proof = t.getConsistencyProof(3, 7);
		const r3 = buildTree(3).rootHash();
		const r7 = buildTree(7).rootHash();
		expect(verifyConsistencyProof({
			hasher: Sha256Hasher, oldSize: 3, newSize: 7,
			oldRoot: r7, newRoot: r3, proof,
		})).toBe(false);
	});
});

describe('Sha256Tree contract violations', () => {
	it('getInclusionProof throws for leafIndex >= treeSize', () => {
		const t = buildTree(4);
		expect(() => t.getInclusionProof(4)).toThrow();
		expect(() => t.getInclusionProof(0, 5)).toThrow();
	});

	it('getConsistencyProof throws for newSize past current size', () => {
		const t = buildTree(4);
		expect(() => t.getConsistencyProof(1, 5)).toThrow();
	});

	it('getConsistencyProof throws when oldSize > newSize', () => {
		const t = buildTree(4);
		expect(() => t.getConsistencyProof(3, 2)).toThrow();
	});
});
