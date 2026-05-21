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
// src/ts/merkle/sha256-tree.ts
//
// SHA-256 specialisation of the Hasher / MerkleTree interfaces. Wraps
// the existing `SHA256` class from the sha2 module under the RFC 9162
// (Certificate Transparency Version 2.0) §2.1.1 leaf and internal-node
// domain separators.
//
// Per-call WASM lifecycle: every Sha256Hasher method instantiates a
// fresh SHA256 inside a try / finally + dispose pattern. There is no
// long-lived module ownership; concurrent users are serialised by the
// per-module exclusivity guard in the sha2 substrate. This mirrors
// the SignatureSuite factories under src/ts/sign/suites/.

import { SHA256 } from '../sha2/index.js';
import {
	buildConsistencyProof,
	buildInclusionProof,
	subtreeHash,
} from './proof.js';
import type { GetNode } from './proof.js';
import type { Hasher, MerkleTree } from './tree.js';
import type { MerkleStorage } from './storage.js';

// ── Sha256Hasher const ──────────────────────────────────────────────────────

const SHA256_OUTPUT = 32;
const LEAF_PREFIX = new Uint8Array([0x00]);
const INTERNAL_PREFIX = new Uint8Array([0x01]);
const SHA256_WASM_MODULES = Object.freeze(['sha2'] as const);

function sha256Hash(input: Uint8Array): Uint8Array {
	const h = new SHA256();
	try {
		return h.hash(input);
	} finally {
		h.dispose();
	}
}

/**
 * RFC 9162 §2.1.1, Merkle Hash Trees. The CT-flavoured SHA-256 hash
 * function: empty-tree value `MTH({}) = SHA-256()`, leaf prefix `0x00`,
 * internal-node prefix `0x01`.
 *
 * Stateless and reentrant: each method takes the sha2 module fresh,
 * runs SHA-256 once, and releases. No `dispose()` is needed.
 */
export const Sha256Hasher: Hasher = Object.freeze({
	name: 'sha256',
	outputSize: SHA256_OUTPUT,
	wasmModules: SHA256_WASM_MODULES,

	hashEmpty(): Uint8Array {
		// RFC 9162 §2.1.1: MTH({}) is the hash of an empty bit-string.
		return sha256Hash(new Uint8Array(0));
	},

	hashLeaf(leaf: Uint8Array): Uint8Array {
		// RFC 9162 §2.1.1: MTH({d}) = HASH(0x00 || d). The 0x00 prefix
		// is the domain separator that prevents an internal-node hash
		// from being mistaken for a leaf hash.
		const buf = new Uint8Array(1 + leaf.length);
		buf.set(LEAF_PREFIX, 0);
		buf.set(leaf, 1);
		return sha256Hash(buf);
	},

	hashInternal(left: Uint8Array, right: Uint8Array): Uint8Array {
		// RFC 9162 §2.1.1: MTH(D[n]) = HASH(0x01 || MTH(D[0:k]) ||
		// MTH(D[k:n])). The 0x01 prefix is the other half of the
		// second-preimage-resistance domain separator.
		const buf = new Uint8Array(1 + left.length + right.length);
		buf.set(INTERNAL_PREFIX, 0);
		buf.set(left, 1);
		buf.set(right, 1 + left.length);
		return sha256Hash(buf);
	},
});

// ── Sha256Tree class ────────────────────────────────────────────────────────

/**
 * Stateful SHA-256 Merkle log. Stores leaf hashes and every perfect
 * aligned internal subtree's hash via the injected `MerkleStorage`;
 * partial right-edge subtrees are recomputed on demand from the
 * stored perfect subtrees.
 *
 * Constructed empty. `append` is the only mutator and is the leaf-hash
 * factory; consumers feed leaf bytes, not pre-computed leaf hashes.
 */
export class Sha256Tree implements MerkleTree {
	readonly hasher: Hasher = Sha256Hasher;
	private readonly storage: MerkleStorage;

	constructor(storage: MerkleStorage) {
		this.storage = storage;
	}

	size(): number {
		return this.storage.size();
	}

	rootHash(): Uint8Array {
		const n = this.storage.size();
		if (n === 0) return this.hasher.hashEmpty();
		const getNode: GetNode = (level, index) => this.storage.getNode(level, index);
		return subtreeHash(this.hasher, 0, n, getNode);
	}

	append(leafBytes: Uint8Array): { leafIndex: number; leafHash: Uint8Array } {
		const leafIndex = this.storage.size();
		const leafHash = this.hasher.hashLeaf(leafBytes);
		this.storage.appendLeaf(leafIndex, leafHash);
		// Propagate completed internal nodes up the right edge. RFC 9162
		// §2.1.1 makes the tree fill left-to-right; whenever a node lands
		// at an odd index its left sibling already exists, so the parent
		// becomes computable for free.
		let level = 0;
		let idx = leafIndex;
		while ((idx & 1) === 1) {
			const left = this.storage.getNode(level, idx - 1);
			const right = this.storage.getNode(level, idx);
			const parent = this.hasher.hashInternal(left, right);
			this.storage.putNode(level + 1, idx >>> 1, parent);
			idx = idx >>> 1;
			level++;
		}
		return { leafIndex, leafHash };
	}

	getInclusionProof(leafIndex: number, treeSize?: number): Uint8Array[] {
		const ts = treeSize ?? this.storage.size();
		if (!Number.isInteger(ts) || ts < 1 || ts > this.storage.size())
			throw new RangeError(
				`Sha256Tree.getInclusionProof: treeSize ${ts} out of range [1, ${this.storage.size()}]`,
			);
		const getNode: GetNode = (level, index) => this.storage.getNode(level, index);
		return buildInclusionProof({ hasher: this.hasher, leafIndex, treeSize: ts, getNode });
	}

	getConsistencyProof(oldSize: number, newSize: number): Uint8Array[] {
		if (!Number.isInteger(newSize) || newSize < 0 || newSize > this.storage.size())
			throw new RangeError(
				`Sha256Tree.getConsistencyProof: newSize ${newSize} out of range [0, ${this.storage.size()}]`,
			);
		const getNode: GetNode = (level, index) => this.storage.getNode(level, index);
		return buildConsistencyProof({ hasher: this.hasher, oldSize, newSize, getNode });
	}
}
