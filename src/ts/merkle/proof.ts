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
// src/ts/merkle/proof.ts
//
// Hash-agnostic, free-function proof verifiers and builders for the
// RFC 9162 (Certificate Transparency Version 2.0) §2.1.3 / §2.1.4
// proof formats. Every entry point takes a `Hasher`; SHA-256 and
// BLAKE3 trees share the same wire format and the same algorithmic
// core.
//
// Verifiers return boolean. Malformed-proof conditions (wrong inner /
// border length, mismatched root) return false. Contract violations
// (wrong-sized root for the hasher, leafIndex out of range, oldSize >
// newSize) throw RangeError; the caller is responsible for staying
// within the public contract.
//
// Builders accept a `getNode(level, index)` callback that abstracts
// the storage layer. Memory, file, and database backends drive the
// same builder without bringing storage details into the proof
// algorithms.

import { bitLen, popcount, splitPoint, trailingZeros } from './tree.js';
import type { Hasher } from './tree.js';
import { constantTimeEqual } from '../utils.js';

// ── Internal chaining primitives (RFC 9162 §2.1.3 / §2.1.4) ─────────────────

/**
 * Decompose an inclusion proof into its inner (path-up-the-tree) and
 * border (left siblings completing the right edge) segments. The sum
 * inner + border is the required proof length.
 *
 * RFC 9162 §2.1.3, Inclusion Proof Verification: the path from a leaf
 * at index to the root of a size-n tree has bitLen(index XOR (size-1))
 * inner levels and popcount(index >> inner) border levels.
 */
function decompInclProof(index: number, size: number): { inner: number; border: number } {
	const inner = bitLen(index ^ (size - 1));
	const border = popcount(Math.floor(index / 2 ** inner));
	return { inner, border };
}

/**
 * Chain `inner` proof entries up from `seed`. At level i, the bit
 * (index >> i) & 1 selects whether the sibling is on the left or the
 * right of `seed`. RFC 9162 §2.1.3.
 */
function chainInner(
	hasher: Hasher,
	seed: Uint8Array,
	proof: Uint8Array[],
	index: number,
): Uint8Array {
	let acc = seed;
	for (let i = 0; i < proof.length; i++) {
		const bit = Math.floor(index / 2 ** i) & 1;
		acc = bit === 0
			? hasher.hashInternal(acc, proof[i])
			: hasher.hashInternal(proof[i], acc);
	}
	return acc;
}

/**
 * Chain `inner` entries but only fold in left siblings (skip the right
 * ones). Used by the consistency verifier to reconstruct the OLD root
 * from the suffix shared with the inclusion proof. RFC 9162 §2.1.4.
 */
function chainInnerRight(
	hasher: Hasher,
	seed: Uint8Array,
	proof: Uint8Array[],
	index: number,
): Uint8Array {
	let acc = seed;
	for (let i = 0; i < proof.length; i++) {
		const bit = Math.floor(index / 2 ** i) & 1;
		if (bit === 1) acc = hasher.hashInternal(proof[i], acc);
	}
	return acc;
}

/**
 * Chain border entries: every remaining sibling is a left sibling
 * along the size-1 path back to the root. RFC 9162 §2.1.3.
 */
function chainBorderRight(
	hasher: Hasher,
	seed: Uint8Array,
	proof: Uint8Array[],
): Uint8Array {
	let acc = seed;
	for (const h of proof) acc = hasher.hashInternal(h, acc);
	return acc;
}

function assertHashLen(hasher: Hasher, label: string, h: Uint8Array): void {
	if (h.length !== hasher.outputSize)
		throw new RangeError(
			`${label}: wrong length ${h.length}, expected ${hasher.outputSize} for ${hasher.name}`,
		);
}

// ── Verifiers ───────────────────────────────────────────────────────────────

export interface VerifyInclusionInput {
	hasher: Hasher;
	leafHash: Uint8Array;
	leafIndex: number;
	treeSize: number;
	proof: readonly Uint8Array[];
	rootHash: Uint8Array;
}

/**
 * RFC 9162 §2.1.3, Inclusion Proof Verification. Returns true if the
 * proof reconstructs `rootHash` from `leafHash` at position
 * (leafIndex, treeSize). Wrong proof length, wrong leaf-hash size, or
 * a reconstructed root that differs from `rootHash` all return false.
 * Contract violations (negative or out-of-range index, treeSize <= 0,
 * wrong-sized rootHash) throw RangeError.
 *
 * `leafHash` is the leaf's MTH ({d_m} hashed under the leaf prefix), not
 * the raw leaf bytes. Thin verifiers receiving a leaf over the wire
 * should compute `hasher.hashLeaf(bytes)` before calling.
 */
export function verifyInclusionProof(input: VerifyInclusionInput): boolean {
	const { hasher, leafHash, leafIndex, treeSize, proof, rootHash } = input;
	if (!Number.isInteger(leafIndex) || leafIndex < 0)
		throw new RangeError(`verifyInclusionProof: leafIndex must be a non-negative integer, got ${leafIndex}`);
	if (!Number.isInteger(treeSize) || treeSize < 1)
		throw new RangeError(`verifyInclusionProof: treeSize must be a positive integer, got ${treeSize}`);
	if (leafIndex >= treeSize)
		throw new RangeError(`verifyInclusionProof: leafIndex ${leafIndex} >= treeSize ${treeSize}`);
	assertHashLen(hasher, 'verifyInclusionProof: rootHash', rootHash);

	if (leafHash.length !== hasher.outputSize) return false;

	const { inner, border } = decompInclProof(leafIndex, treeSize);
	if (proof.length !== inner + border) return false;
	for (const h of proof) {
		if (h.length !== hasher.outputSize) return false;
	}

	const innerProof = (proof as Uint8Array[]).slice(0, inner);
	const borderProof = (proof as Uint8Array[]).slice(inner);
	let res = chainInner(hasher, leafHash, innerProof, leafIndex);
	res = chainBorderRight(hasher, res, borderProof);
	return constantTimeEqual(res, rootHash);
}

export interface VerifyConsistencyInput {
	hasher: Hasher;
	oldSize: number;
	newSize: number;
	oldRoot: Uint8Array;
	newRoot: Uint8Array;
	proof: readonly Uint8Array[];
}

/**
 * RFC 9162 §2.1.4, Consistency Proof Verification. Returns true if
 * `proof` proves that the size-`oldSize` tree with root `oldRoot` is a
 * prefix of the size-`newSize` tree with root `newRoot`.
 *
 * Malformed-proof conditions (wrong proof length, non-empty proof when
 * one is forbidden, mismatched old/new root reconstruction) return
 * false. Contract violations (`oldSize > newSize`, wrong-sized root)
 * throw RangeError; the special "consistency from empty tree" form is
 * not part of the wire format and returns false.
 */
export function verifyConsistencyProof(input: VerifyConsistencyInput): boolean {
	const { hasher, oldSize, newSize, oldRoot, newRoot, proof } = input;
	if (!Number.isInteger(oldSize) || oldSize < 0)
		throw new RangeError(`verifyConsistencyProof: oldSize must be a non-negative integer, got ${oldSize}`);
	if (!Number.isInteger(newSize) || newSize < 0)
		throw new RangeError(`verifyConsistencyProof: newSize must be a non-negative integer, got ${newSize}`);
	if (oldSize > newSize)
		throw new RangeError(`verifyConsistencyProof: oldSize ${oldSize} > newSize ${newSize}`);

	// Equal-size shortcut: RFC says the proof is empty and roots match.
	// Byte-for-byte comparison; root hashes flow through unchanged because
	// no reconstruction runs, so hash-length validation does not apply.
	if (oldSize === newSize) {
		if (proof.length > 0) return false;
		return oldRoot.length === newRoot.length && constantTimeEqual(oldRoot, newRoot);
	}
	// "Consistency from empty tree" is undefined: the verifier cannot
	// recover oldRoot from no proof, so reject as malformed.
	if (oldSize === 0) return false;
	if (proof.length === 0) return false;

	assertHashLen(hasher, 'verifyConsistencyProof: oldRoot', oldRoot);
	assertHashLen(hasher, 'verifyConsistencyProof: newRoot', newRoot);
	for (const h of proof) {
		if (h.length !== hasher.outputSize) return false;
	}

	const { inner: innerFull, border } = decompInclProof(oldSize - 1, newSize);
	const shift = trailingZeros(oldSize);
	const inner = innerFull - shift;

	// If oldSize is a power of two, the verifier already knows the
	// subtree's root (== oldRoot) and the proof omits it. Otherwise the
	// proof's first element is the seed for both chains.
	const oldIsPow2 = oldSize === 2 ** shift;
	let seed: Uint8Array;
	let start: number;
	if (oldIsPow2) {
		seed = oldRoot;
		start = 0;
	} else {
		seed = proof[0];
		start = 1;
	}
	const expectedLen = start + inner + border;
	if (proof.length !== expectedLen) return false;

	const tail = (proof as Uint8Array[]).slice(start);
	const innerProof = tail.slice(0, inner);
	const borderProof = tail.slice(inner);

	// Bit pattern for chainInnerRight: we re-derive the oldRoot from
	// the proof. `mask` is (oldSize - 1) >> shift, the path bits above
	// the size-`oldSize` subtree's root level.
	const mask = Math.floor((oldSize - 1) / 2 ** shift);

	let hash1 = chainInnerRight(hasher, seed, innerProof, mask);
	hash1 = chainBorderRight(hasher, hash1, borderProof);
	if (!constantTimeEqual(hash1, oldRoot)) return false;

	let hash2 = chainInner(hasher, seed, innerProof, mask);
	hash2 = chainBorderRight(hasher, hash2, borderProof);
	return constantTimeEqual(hash2, newRoot);
}

// ── Builders ────────────────────────────────────────────────────────────────

/** Callback the builders use to read the tree without knowing how it is stored. */
export type GetNode = (level: number, index: number) => Uint8Array;

export interface BuildInclusionInput {
	hasher: Hasher;
	leafIndex: number;
	treeSize: number;
	getNode: GetNode;
}

/**
 * RFC 9162 §2.1.3: build the inclusion proof for leaf `leafIndex` in
 * a tree of size `treeSize`. The returned bytes are ordered from the
 * lowest level upward (leaf sibling first, root-adjacent last), the
 * order `verifyInclusionProof` consumes.
 */
export function buildInclusionProof(input: BuildInclusionInput): Uint8Array[] {
	const { hasher, leafIndex, treeSize, getNode } = input;
	if (!Number.isInteger(leafIndex) || leafIndex < 0)
		throw new RangeError(`buildInclusionProof: leafIndex must be a non-negative integer, got ${leafIndex}`);
	if (!Number.isInteger(treeSize) || treeSize < 1)
		throw new RangeError(`buildInclusionProof: treeSize must be a positive integer, got ${treeSize}`);
	if (leafIndex >= treeSize)
		throw new RangeError(`buildInclusionProof: leafIndex ${leafIndex} >= treeSize ${treeSize}`);

	return pathBuild(hasher, leafIndex, 0, treeSize, getNode);
}

export interface BuildConsistencyInput {
	hasher: Hasher;
	oldSize: number;
	newSize: number;
	getNode: GetNode;
}

/**
 * RFC 9162 §2.1.4: build the consistency proof between two tree
 * sizes. Returns an empty array when oldSize equals newSize or
 * oldSize is zero (the verifier rejects the latter, but the builder
 * is symmetric for inspection-time use).
 */
export function buildConsistencyProof(input: BuildConsistencyInput): Uint8Array[] {
	const { hasher, oldSize, newSize, getNode } = input;
	if (!Number.isInteger(oldSize) || oldSize < 0)
		throw new RangeError(`buildConsistencyProof: oldSize must be a non-negative integer, got ${oldSize}`);
	if (!Number.isInteger(newSize) || newSize < 0)
		throw new RangeError(`buildConsistencyProof: newSize must be a non-negative integer, got ${newSize}`);
	if (oldSize > newSize)
		throw new RangeError(`buildConsistencyProof: oldSize ${oldSize} > newSize ${newSize}`);
	if (oldSize === newSize || oldSize === 0) return [];

	return subProof(hasher, oldSize, 0, newSize, true, getNode);
}

// RFC 9162 §2.1.4 SUBPROOF(m, D[n], b). `lo` and `hi` parameterise
// the [lo, hi) range covered by the current subtree; `m` is the size
// of the older subtree being witnessed.
function subProof(
	hasher: Hasher,
	m: number,
	lo: number,
	hi: number,
	b: boolean,
	getNode: GetNode,
): Uint8Array[] {
	const n = hi - lo;
	if (m === n) {
		// Whole subtree: emit its root only if b == false.
		return b ? [] : [subtreeHash(hasher, lo, hi, getNode)];
	}
	const k = splitPoint(n);
	if (m <= k) {
		const sub = subProof(hasher, m, lo, lo + k, b, getNode);
		sub.push(subtreeHash(hasher, lo + k, hi, getNode));
		return sub;
	}
	const sub = subProof(hasher, m - k, lo + k, hi, false, getNode);
	sub.push(subtreeHash(hasher, lo, lo + k, getNode));
	return sub;
}

// Inclusion-proof path build: yields siblings ordered from the lowest
// level (leaf sibling) up. Sibling = root of the other half of the
// current subtree.
function pathBuild(
	hasher: Hasher,
	leafIndex: number,
	lo: number,
	hi: number,
	getNode: GetNode,
): Uint8Array[] {
	if (hi - lo <= 1) return [];
	const k = splitPoint(hi - lo);
	if (leafIndex - lo < k) {
		const sub = pathBuild(hasher, leafIndex, lo, lo + k, getNode);
		sub.push(subtreeHash(hasher, lo + k, hi, getNode));
		return sub;
	}
	const sub = pathBuild(hasher, leafIndex, lo + k, hi, getNode);
	sub.push(subtreeHash(hasher, lo, lo + k, getNode));
	return sub;
}

/**
 * RFC 9162 §2.1.1 MTH(D[lo:hi]). For a perfect aligned subtree the
 * value is stored at (level, index); otherwise the value is the
 * internal hash of the perfect left half and the recursive right
 * half. Visible to the tree class so `rootHash()` can share the
 * recursion with the builders.
 *
 * @internal
 */
export function subtreeHash(
	hasher: Hasher,
	lo: number,
	hi: number,
	getNode: GetNode,
): Uint8Array {
	const n = hi - lo;
	if (n === 1) return getNode(0, lo);
	const k = splitPoint(n);
	if (k === n / 2 && (lo % n) === 0) {
		// Perfect aligned subtree: a stored internal node.
		return getNode(bitLen(n) - 1, Math.floor(lo / n));
	}
	const left = subtreeHash(hasher, lo, lo + k, getNode);
	const right = subtreeHash(hasher, lo + k, hi, getNode);
	return hasher.hashInternal(left, right);
}
