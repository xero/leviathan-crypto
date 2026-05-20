#!/usr/bin/env node
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
/**
 * Generate the BLAKE3 Merkle-tree KAT corpus.
 *
 * SELF-GENERATED. Tree sizes 0, 1, 2, 4, 7, 1024 cover empty, single-leaf,
 * power-of-2, non-power-of-2, and a size that exercises BLAKE3's
 * `compress4` parallelism at the internal-node layer (BLAKE3 §5.3 SIMD).
 * Each record stores the root hash, an inclusion proof for every leaf,
 * and a consistency proof to every prior power-of-2 size.
 *
 * The resulting `test/vectors/merkle_blake3.ts` is independently
 * cross-checked by `scripts/verify-vectors/src/merkle_blake3.rs` against
 * the RustCrypto `blake3` crate; the two implementations are separate
 * lineages from the same BLAKE3 specification, so agreement on every
 * byte is the "two independent stacks agree" signal that anchors the
 * vector file as a spec-conformant gate corpus.
 *
 * Run once during implementation to seed the file; re-run only when the
 * corpus shape itself needs regeneration. The file is immutable per the
 * repo's "test vectors are immutable" rule once recorded.
 *
 * usage:  bunx tsx scripts/gen-merkle-blake3-vectors.ts
 * output: test/vectors/merkle_blake3.ts
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname }            from 'node:path';
import { fileURLToPath }                from 'node:url';
import {
	init,
	Blake3Hasher, Blake3Tree,
	MemoryStorage,
	bytesToHex, utf8ToBytes,
} from '../src/ts/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../build/blake3.wasm');
const OUT_PATH   = resolve(__dirname, '../test/vectors/merkle_blake3.ts');

// Pinned RustCrypto crate version used as the independent oracle. Kept
// in lock-step with the Cargo.toml pin under `scripts/verify-vectors/`.
const RUSTCRYPTO_BLAKE3_PIN = '1.8.5';

const TREE_SIZES = [0, 1, 2, 4, 7, 1024] as const;

await init({ blake3: readFileSync(WASM_PATH) });

function leafBytes(i: number): Uint8Array {
	return utf8ToBytes(`leaf-${i}`);
}

interface MerkleBlake3Record {
	desc:          string;
	treeSize:      number;
	rootHex:       string;
	leavesUtf8:    string[];
	inclusionHex:  string[][];          // one proof per leaf index
	consistency:   { fromSize: number; fromRootHex: string; proofHex: string[] }[];
}

function buildTree(n: number): Blake3Tree {
	const t = new Blake3Tree(new MemoryStorage());
	for (let i = 0; i < n; i++) t.append(leafBytes(i));
	return t;
}

function isPowerOfTwo(n: number): boolean {
	return n >= 1 && (n & (n - 1)) === 0;
}

const records: MerkleBlake3Record[] = [];

for (const n of TREE_SIZES) {
	const tree = new Blake3Tree(new MemoryStorage());
	const leavesUtf8: string[] = [];
	for (let i = 0; i < n; i++) {
		leavesUtf8.push(`leaf-${i}`);
		tree.append(leafBytes(i));
	}
	const root = tree.rootHash();
	const inclusionHex: string[][] = [];
	for (let i = 0; i < n; i++) {
		const proof = tree.getInclusionProof(i);
		inclusionHex.push(proof.map(bytesToHex));
	}
	// Consistency proofs to every prior power-of-2 size strictly less than n.
	// RFC 9162 §2.1.4 admits oldSize in [1, newSize]; power-of-2 mirrors real-log STH checkpoints.
	const consistency: { fromSize: number; fromRootHex: string; proofHex: string[] }[] = [];
	for (let prior = 1; prior < n; prior *= 2) {
		if (!isPowerOfTwo(prior)) continue;
		const proof = tree.getConsistencyProof(prior, n);
		const priorRoot = buildTree(prior).rootHash();
		consistency.push({
			fromSize: prior,
			fromRootHex: bytesToHex(priorRoot),
			proofHex: proof.map(bytesToHex),
		});
	}
	records.push({
		desc: `BLAKE3 Merkle tree, size ${n} (leaves utf8("leaf-i") for i in [0, ${n}))`,
		treeSize: n,
		rootHex: bytesToHex(root),
		leavesUtf8,
		inclusionHex,
		consistency,
	});
	console.log(`size ${n}: root ${bytesToHex(root).slice(0, 16)}…  incl=${inclusionHex.length}  cons=${consistency.length}`);
}

// Round-trip every record through the verifier surface before emit;
// generator / verifier disagreement surfaces here.
import { verifyInclusionProof, verifyConsistencyProof } from '../src/ts/index.js';

for (const rec of records) {
	const root = Uint8Array.from(Buffer.from(rec.rootHex, 'hex'));
	for (let i = 0; i < rec.treeSize; i++) {
		const leafHash = Blake3Hasher.hashLeaf(leafBytes(i));
		const proof = rec.inclusionHex[i].map(h => Uint8Array.from(Buffer.from(h, 'hex')));
		const ok = verifyInclusionProof({
			hasher: Blake3Hasher,
			leafHash,
			leafIndex: i,
			treeSize: rec.treeSize,
			proof,
			rootHash: root,
		});
		if (!ok) throw new Error(`size ${rec.treeSize} leaf ${i}: in-line inclusion check failed`);
	}
	for (const cons of rec.consistency) {
		const oldRoot = Uint8Array.from(Buffer.from(cons.fromRootHex, 'hex'));
		const proof = cons.proofHex.map(h => Uint8Array.from(Buffer.from(h, 'hex')));
		const ok = verifyConsistencyProof({
			hasher: Blake3Hasher,
			oldSize: cons.fromSize,
			newSize: rec.treeSize,
			oldRoot,
			newRoot: root,
			proof,
		});
		if (!ok) throw new Error(`size ${rec.treeSize} cons from ${cons.fromSize}: in-line check failed`);
	}
}
console.log('all records in-line round-trip verified');

const asciiHeader = `//                  ▄▄▄▄▄▄▄▄▄▄
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
// test/vectors/merkle_blake3.ts
//
// BLAKE3-native Merkle-tree KAT corpus for leviathan-crypto's
// \`Blake3Hasher\` / \`Blake3Tree\` pair.
//
// Composition (BLAKE3 §2.4 / §2.5):
//   hashEmpty()                = BLAKE3()
//   hashLeaf(leaf)             = BLAKE3(leaf)
//   hashInternal(left, right)  = parent compress with PARENT flag,
//                                IV as starting CV, modeFlags=0, isRoot=0
//
// Leaves are deterministic utf8("leaf-i"). Tree sizes 0, 1, 2, 4, 7,
// 1024 exercise empty, single-leaf, power-of-2, non-power-of-2, and a
// size that drives \`compress4\` parallelism at the internal-node layer
// (BLAKE3 §5.3 SIMD).
//
// Cross-check:
//   Independently verified against the RustCrypto \`blake3\` crate
//   (version ${RUSTCRYPTO_BLAKE3_PIN}, separate implementation lineage)
//   by \`scripts/verify-vectors/src/merkle_blake3.rs\`. Vector values
//   are spec-anchored via the agreement between the two stacks.
//
// Generator: \`scripts/gen-merkle-blake3-vectors.ts\`. Re-run only if
// the corpus shape itself changes; the file is immutable thereafter.

`;

let body = '';
body += 'export interface MerkleBlake3ConsistencyProof {\n';
body += '\tfromSize:    number;\n';
body += '\tfromRootHex: string;\n';
body += '\tproofHex:    string[];\n';
body += '}\n\n';
body += 'export interface MerkleBlake3Record {\n';
body += '\tdesc:         string;\n';
body += '\ttreeSize:     number;\n';
body += '\trootHex:      string;\n';
body += '\tleavesUtf8:   string[];\n';
body += '\tinclusionHex: string[][];\n';
body += '\tconsistency:  MerkleBlake3ConsistencyProof[];\n';
body += '}\n\n';
body += 'export const merkleBlake3Records: MerkleBlake3Record[] = [\n';
for (const rec of records) {
	body += '\t{\n';
	body += `\t\tdesc:     ${JSON.stringify(rec.desc)},\n`;
	body += `\t\ttreeSize: ${rec.treeSize},\n`;
	body += `\t\trootHex:  ${JSON.stringify(rec.rootHex)},\n`;
	body += `\t\tleavesUtf8: ${JSON.stringify(rec.leavesUtf8)},\n`;
	body += `\t\tinclusionHex: [\n`;
	for (const proof of rec.inclusionHex) {
		body += `\t\t\t${JSON.stringify(proof)},\n`;
	}
	body += `\t\t],\n`;
	body += `\t\tconsistency: [\n`;
	for (const c of rec.consistency) {
		body += `\t\t\t{ fromSize: ${c.fromSize}, fromRootHex: ${JSON.stringify(c.fromRootHex)}, proofHex: ${JSON.stringify(c.proofHex)} },\n`;
	}
	body += `\t\t],\n`;
	body += '\t},\n';
}
body += '];\n';

writeFileSync(OUT_PATH, asciiHeader + body, 'utf8');
console.log(`wrote ${records.length} records to ${OUT_PATH}`);
