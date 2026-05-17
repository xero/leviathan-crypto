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
// src/ts/merkle/storage.ts
//
// MerkleStorage abstracts the per-node persistence layer a tree uses
// to materialise leaves and recomputed internal nodes. Two-axis key
// (level, index): level 0 is the leaf row, level >= 1 stores the hash
// of a perfect aligned subtree covering [index*2^level, (index+1)*2^level).
//
// MemoryStorage is the in-process implementation. File and database
// backends are extension surface and ship as consumer code.

/**
 * Minimum surface a backend exposes to drive a MerkleTree. Sync
 * everywhere: the merkle layer is synchronous and consumers that need
 * async IO wrap externally.
 *
 * Storage records only perfect aligned subtree hashes. Roots of
 * partial right-edge subtrees are recomputed on demand by the tree.
 */
export interface MerkleStorage {
	/** Number of leaves appended so far. */
	size(): number;
	/** Record a leaf hash at the given index. The implementation must reject out-of-order indices. */
	appendLeaf(leafIndex: number, leafHash: Uint8Array): void;
	/** Read the leaf hash at index. Throws if absent. */
	getLeaf(leafIndex: number): Uint8Array;
	/** Record an internal node hash at the given (level, index). */
	putNode(level: number, index: number, hash: Uint8Array): void;
	/** Read an internal-node hash. Throws if absent. */
	getNode(level: number, index: number): Uint8Array;
	/** Probe an internal-node slot without throwing. */
	hasNode(level: number, index: number): boolean;
}

/**
 * In-process storage backed by a Map keyed on `${level}:${index}`. Sync.
 * Suitable for tests, witnesses without persistent storage, and the
 * MerkleVerifier short-lived flow. Production logs that need durability
 * implement MerkleStorage over a file or DB and feed it to a
 * MerkleTree the same way.
 */
export class MemoryStorage implements MerkleStorage {
	private leafCount = 0;
	private readonly nodes = new Map<string, Uint8Array>();

	private static key(level: number, index: number): string {
		return `${level}:${index}`;
	}

	size(): number {
		return this.leafCount;
	}

	appendLeaf(leafIndex: number, leafHash: Uint8Array): void {
		if (leafIndex !== this.leafCount)
			throw new RangeError(
				`MemoryStorage.appendLeaf: out-of-order index ${leafIndex}, expected ${this.leafCount}`,
			);
		this.nodes.set(MemoryStorage.key(0, leafIndex), leafHash);
		this.leafCount++;
	}

	getLeaf(leafIndex: number): Uint8Array {
		const v = this.nodes.get(MemoryStorage.key(0, leafIndex));
		if (!v)
			throw new RangeError(`MemoryStorage.getLeaf: no leaf at index ${leafIndex}`);
		return v;
	}

	putNode(level: number, index: number, hash: Uint8Array): void {
		this.nodes.set(MemoryStorage.key(level, index), hash);
	}

	getNode(level: number, index: number): Uint8Array {
		const v = this.nodes.get(MemoryStorage.key(level, index));
		if (!v)
			throw new RangeError(`MemoryStorage.getNode: no node at (${level}, ${index})`);
		return v;
	}

	hasNode(level: number, index: number): boolean {
		return this.nodes.has(MemoryStorage.key(level, index));
	}
}
