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
// src/ts/merkle/tree.ts
//
// MerkleTree + Hasher interfaces and the spec-anchored node-index math.
// Hash-agnostic by design: every hash-touching surface (the tree class,
// the free-function proof verifiers, the proof builders) is parameterised
// by a `Hasher`, so SHA-256 and BLAKE3 trees share the same algorithmic
// core and the same proof wire format.

/**
 * Minimum surface a hash function must expose to drive RFC 9162
 * (Certificate Transparency Version 2.0) §2.1.1, Merkle Hash Trees.
 *
 * Implementations are `const` objects (no instantiation); each call site
 * acquires the underlying WASM module fresh, runs the operation, and
 * disposes. There is no long-lived state on a Hasher; concurrent users
 * are serialised by the per-module exclusivity guard at the WASM layer.
 */
export interface Hasher {
	/** Display name, used in error messages and the export catalog. */
	readonly name: string;
	/** Bytes per hash output. */
	readonly outputSize: number;
	/** WASM module ids this Hasher exercises during `init()`. */
	readonly wasmModules: readonly string[];
	/** RFC 9162 §2.1.1: MTH({}) = HASH(), the hash of the empty input. */
	hashEmpty(): Uint8Array;
	/** RFC 9162 §2.1.1: leaf domain separator `0x00` prefix. */
	hashLeaf(leaf: Uint8Array): Uint8Array;
	/** RFC 9162 §2.1.1: internal-node domain separator `0x01` prefix. */
	hashInternal(left: Uint8Array, right: Uint8Array): Uint8Array;
}

/**
 * Stateful Merkle tree with pluggable storage. Append a leaf, query
 * size + root, build inclusion and consistency proofs. The tree owns
 * the hash function via `hasher`; consumers do not pass it per call.
 */
export interface MerkleTree {
	readonly hasher: Hasher;
	size(): number;
	rootHash(): Uint8Array;
	append(leafBytes: Uint8Array): { leafIndex: number; leafHash: Uint8Array };
	getInclusionProof(leafIndex: number, treeSize?: number): Uint8Array[];
	getConsistencyProof(oldSize: number, newSize: number): Uint8Array[];
}

/**
 * RFC 9162 §2.1.4, Consistency Proof Verification: "k is the largest
 * power of two smaller than n". The split point at which an n-leaf
 * tree decomposes into a perfect left subtree of size k and a right
 * subtree of size n - k. Defined for n >= 2.
 *
 * Invariant for n >= 2: k < n <= 2*k.
 */
export function splitPoint(n: number): number {
	if (!Number.isInteger(n) || n < 2)
		throw new RangeError(`splitPoint: n must be an integer >= 2, got ${n}`);
	// Largest power of two strictly less than n: for n=2 -> 1, n=8 -> 4,
	// n=2^k -> 2^(k-1). Equivalent to 1 << (bitLength(n - 1) - 1).
	let k = 1;
	while (k * 2 < n) k *= 2;
	return k;
}

/**
 * `bits.Len64(x)` analogue: position of the most-significant set bit
 * of x, with `bitLen(0) = 0`. Used by the §2.1.3 / §2.1.4 inclusion
 * and consistency verifiers to split a proof into inner and border
 * segments.
 */
export function bitLen(x: number): number {
	if (!Number.isInteger(x) || x < 0)
		throw new RangeError(`bitLen: x must be a non-negative integer, got ${x}`);
	let n = 0;
	while (x > 0) {
		x = Math.floor(x / 2); n++;
	}
	return n;
}

/**
 * Popcount of a non-negative integer (`bits.OnesCount64` analogue).
 * Used to compute the "border" length of an inclusion proof per the
 * RFC 9162 §2.1.3 decomposition.
 */
export function popcount(x: number): number {
	if (!Number.isInteger(x) || x < 0)
		throw new RangeError(`popcount: x must be a non-negative integer, got ${x}`);
	let n = 0;
	while (x > 0) {
		if (x & 1) n++;
		x = Math.floor(x / 2);
	}
	return n;
}

/**
 * Number of trailing zero bits in a positive integer
 * (`bits.TrailingZeros64` analogue). Used by RFC 9162 §2.1.4 to step
 * the consistency verifier past the levels covered by the size1
 * subtree. Defined for x >= 1.
 */
export function trailingZeros(x: number): number {
	if (!Number.isInteger(x) || x < 1)
		throw new RangeError(`trailingZeros: x must be a positive integer, got ${x}`);
	let n = 0;
	while ((x & 1) === 0) {
		x = Math.floor(x / 2);
		n++;
	}
	return n;
}
