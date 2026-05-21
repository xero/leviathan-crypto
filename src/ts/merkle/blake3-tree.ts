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
// src/ts/merkle/blake3-tree.ts
//
// BLAKE3 Hasher / MerkleTree. Domain separation comes from BLAKE3's own
// §2.4 CHUNK_START / CHUNK_END / ROOT and §2.5 PARENT flags, not from
// RFC 6962-style 0x00 / 0x01 prefix bytes (those would be redundant and
// discard `compress4` parallelism at the internal-node layer).
//
// Composition:
//   hashEmpty()                = BLAKE3()                                §2.5
//   hashLeaf(leaf)             = BLAKE3(leaf)                            §2.4
//   hashInternal(left, right)  = _testParentCV(left, right, IV, 0, 0)    §2.5
//
// Parent compress runs with modeFlags = 0 and isRoot = 0 at every level.
// The root flag is the SignedLog layer's concern; the tree's top hash
// exits as a plain CV, keeping `hashInternal` symmetric.

import { BLAKE3 } from '../blake3/index.js';
import { getInstance } from '../init.js';
import type { Blake3Exports, Blake3TestExports } from '../blake3/types.js';
import {
	buildConsistencyProof,
	buildInclusionProof,
	subtreeHash,
} from './proof.js';
import type { GetNode } from './proof.js';
import type { Hasher, MerkleTree } from './tree.js';
import type { MerkleStorage } from './storage.js';

// ── Module access ───────────────────────────────────────────────────────────

// `Blake3TestExports` is internal to the BLAKE3 module surface and not
// re-exported from `src/ts/blake3/index.ts`. The cast here is explicitly
// authorized by the doc-comment on `Blake3TestExports`, which names the
// merkle module as one of the two permitted consumers.
type Blake3FullExports = Blake3Exports & Blake3TestExports;

function getBlake3Exports(): Blake3FullExports {
	return getInstance('blake3').exports as unknown as Blake3FullExports;
}

// ── Scratch layout for `_testParentCV` ──────────────────────────────────────
//
// Second-page offsets (past BUFFER_END = 26328 from
// `src/asm/blake3/buffers.ts`) are untouched by the §2.4 chunk pipeline
// and §2.5 tree-assembly queues; safe for caller-supplied scratch.

const PARENT_LEFT_OFF  = 65536;
const PARENT_RIGHT_OFF = PARENT_LEFT_OFF  + 32;
const PARENT_START_OFF = PARENT_RIGHT_OFF + 32;
const PARENT_OUT_OFF   = PARENT_START_OFF + 32;
const PARENT_SCRATCH_LEN = 128;

// BLAKE3 §2.2 Table 1: the BLAKE3 IV equals the FIPS 180-4 SHA-256 IV,
// packed as eight u32 little-endian words. The IV is the starting CV
// for default-mode parent compresses (BLAKE3 §2.5, Tree Mode).
const BLAKE3_IV_BYTES: Uint8Array = (() => {
	const iv32 = new Uint32Array([
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	]);
	return new Uint8Array(iv32.buffer);
})();

const BLAKE3_OUTPUT = 32;
const BLAKE3_WASM_MODULES = Object.freeze(['blake3'] as const);

// ── Blake3Hasher const ──────────────────────────────────────────────────────

/**
 * BLAKE3-native `Hasher` (BLAKE3 §2.3, §2.4, §2.5).
 *
 * Empty-tree value is `BLAKE3()`; leaves are `BLAKE3(leaf)`; internal
 * nodes are the §2.5 parent compress over the two child CVs with the
 * BLAKE3 IV as the starting CV and `modeFlags = 0`, `isRoot = 0`.
 *
 * Stateless and reentrant: each method acquires the blake3 module
 * fresh, runs the operation, and releases. No `dispose()` is needed.
 */
export const Blake3Hasher: Hasher = Object.freeze({
	name: 'blake3',
	outputSize: BLAKE3_OUTPUT,
	wasmModules: BLAKE3_WASM_MODULES,

	hashEmpty(): Uint8Array {
		// BLAKE3 §2.5, Tree Mode: the natural tree-mode root for an
		// empty input is `BLAKE3()` itself. The chunk machine handles
		// the single empty chunk (CHUNK_START | CHUNK_END | ROOT)
		// internally and returns the 32-byte XOF prefix.
		const h = new BLAKE3();
		try {
			return h.hash(new Uint8Array(0));
		} finally {
			h.dispose();
		}
	},

	hashLeaf(leaf: Uint8Array): Uint8Array {
		// BLAKE3 §2.4, Chunks: the chunk pipeline applies CHUNK_START,
		// CHUNK_END, and ROOT flags internally. The caller sees a plain
		// 32-byte hash; leaf-vs-internal domain separation is BLAKE3's
		// job through these flag bytes, not the caller's job through
		// prefix bytes.
		const h = new BLAKE3();
		try {
			return h.hash(leaf);
		} finally {
			h.dispose();
		}
	},

	hashInternal(left: Uint8Array, right: Uint8Array): Uint8Array {
		if (left.length !== BLAKE3_OUTPUT)
			throw new RangeError(
				`Blake3Hasher.hashInternal: left must be ${BLAKE3_OUTPUT} bytes, got ${left.length}`,
			);
		if (right.length !== BLAKE3_OUTPUT)
			throw new RangeError(
				`Blake3Hasher.hashInternal: right must be ${BLAKE3_OUTPUT} bytes, got ${right.length}`,
			);
		// BLAKE3 §2.5, Tree Mode: parent compress over (left || right)
		// with IV as the starting CV and PARENT as the only flag bit
		// (modeFlags = 0 selects default mode; isRoot = 0 keeps the
		// node generic so callers can stack identical compresses up
		// the tree).
		const x = getBlake3Exports();
		const mem = new Uint8Array(x.memory.buffer);
		mem.set(left,            PARENT_LEFT_OFF);
		mem.set(right,           PARENT_RIGHT_OFF);
		mem.set(BLAKE3_IV_BYTES, PARENT_START_OFF);
		try {
			x._testParentCV(
				PARENT_LEFT_OFF, PARENT_RIGHT_OFF,
				PARENT_START_OFF, 0, 0,
				PARENT_OUT_OFF,
			);
			return mem.slice(PARENT_OUT_OFF, PARENT_OUT_OFF + BLAKE3_OUTPUT);
		} finally {
			mem.fill(0, PARENT_LEFT_OFF, PARENT_LEFT_OFF + PARENT_SCRATCH_LEN);
			x.wipeBuffers();
		}
	},
});

// ── Blake3Tree class ────────────────────────────────────────────────────────

/**
 * Stateful BLAKE3 Merkle log. Same surface and storage discipline as
 * `Sha256Tree`: leaf hashes and every perfect aligned internal subtree
 * hash live in the injected `MerkleStorage`; partial right-edge subtrees
 * are recomputed on demand.
 *
 * `append` is the only mutator and is the leaf-hash factory; consumers
 * feed leaf bytes, not pre-computed leaf hashes.
 */
export class Blake3Tree implements MerkleTree {
	readonly hasher: Hasher = Blake3Hasher;
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
				`Blake3Tree.getInclusionProof: treeSize ${ts} out of range [1, ${this.storage.size()}]`,
			);
		const getNode: GetNode = (level, index) => this.storage.getNode(level, index);
		return buildInclusionProof({ hasher: this.hasher, leafIndex, treeSize: ts, getNode });
	}

	getConsistencyProof(oldSize: number, newSize: number): Uint8Array[] {
		if (!Number.isInteger(newSize) || newSize < 0 || newSize > this.storage.size())
			throw new RangeError(
				`Blake3Tree.getConsistencyProof: newSize ${newSize} out of range [0, ${this.storage.size()}]`,
			);
		const getNode: GetNode = (level, index) => this.storage.getNode(level, index);
		return buildConsistencyProof({ hasher: this.hasher, oldSize, newSize, getNode });
	}
}
