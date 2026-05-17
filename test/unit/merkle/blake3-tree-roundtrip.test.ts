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
// Blake3Tree round-trip: append + rootHash against the recorded
// per-size root, contract-violation throws on out-of-range arguments.
// Vectors come from `merkle_blake3.ts`, anchored to RustCrypto blake3
// by `scripts/verify-vectors/src/merkle_blake3.rs`.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	Blake3Hasher, Blake3Tree,
	MemoryStorage,
	bytesToHex, utf8ToBytes,
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

describe('Blake3Tree append and rootHash', () => {
	it('empty tree root matches the recorded BLAKE3() value', () => {
		const t = new Blake3Tree(new MemoryStorage());
		expect(t.size()).toBe(0);
		const expected = merkleBlake3Records.find(r => r.treeSize === 0)!.rootHex;
		expect(bytesToHex(t.rootHash())).toBe(expected);
	});

	it('size-1 tree root equals hashLeaf of that single leaf', () => {
		const t = new Blake3Tree(new MemoryStorage());
		const leaf = utf8ToBytes('leaf-0');
		const { leafIndex, leafHash } = t.append(leaf);
		expect(leafIndex).toBe(0);
		expect(t.size()).toBe(1);
		expect(t.rootHash()).toEqual(leafHash);
		expect(t.rootHash()).toEqual(Blake3Hasher.hashLeaf(leaf));
	});

	it('size-2 tree root equals hashInternal(hashLeaf(L0), hashLeaf(L1))', () => {
		const t = new Blake3Tree(new MemoryStorage());
		t.append(utf8ToBytes('leaf-0'));
		t.append(utf8ToBytes('leaf-1'));
		const expected = Blake3Hasher.hashInternal(
			Blake3Hasher.hashLeaf(utf8ToBytes('leaf-0')),
			Blake3Hasher.hashLeaf(utf8ToBytes('leaf-1')),
		);
		expect(t.rootHash()).toEqual(expected);
	});

	it('rootHash matches the vector for every recorded size', () => {
		for (const rec of merkleBlake3Records) {
			const t = buildTree(rec.treeSize);
			expect(bytesToHex(t.rootHash()), `size ${rec.treeSize}`).toBe(rec.rootHex);
		}
	}, 60_000);
});

describe('Blake3Tree contract violations', () => {
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
