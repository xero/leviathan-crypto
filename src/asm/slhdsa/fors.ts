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
// src/asm/slhdsa/fors.ts
//
// FIPS 205 §8 Forest of Random Subsets (FORS).
//
// Algorithms implemented (FIPS 205 numbering):
//   Algorithm 14 fors_skGen:       derive a single FORS secret value
//   Algorithm 15 fors_node:        Merkle node within one FORS tree
//   Algorithm 16 fors_sign:        produce a k-path FORS signature
//   Algorithm 17 fors_pkFromSig:   recover FORS public key from signature
//
// Digest split for fors_sign and fors_pkFromSig: this WASM layer accepts a
// ⌈k·a/8⌉-byte md buffer and consumes the *lower* k·a bits. The exact
// bit-extraction that produces md from the SLH-DSA message digest lives in
// FIPS 205 §10.1 Algorithm 19 lines 13-18 (slh_sign_internal) and §10.1
// Algorithm 20 lines 7-12 (slh_verify_internal), implemented in slh.ts.
// This file documents the contract; callers supply the prepared md as input.
//
// ADRS types used here:
//   ADRS_FORS_TREE:  internal nodes within a FORS tree
//   ADRS_FORS_ROOTS: final compression over the k tree roots
//   ADRS_FORS_PRF:   secret-key derivation via PRF
//
// Working-buffer layout: this module shares the STATE region with WOTS+.
// Within a single WASM entry call, WOTS+ algorithms and FORS algorithms
// are never both in flight, so aliasing the working buffers is safe.
//
//   +64 .. +1183   FORS_ROOTS_OFFSET:   k tree roots (max 1120 B = 35·n at 256f)
//                    Aliases WOTS_TMP_OFFSET; WOTS+ uses up to 2144 B here.
//   +2208 .. +2239 FORS_LEAF_OFFSET:    n-byte sk / leaf hash scratch
//                    Aliases WOTS_SK_OFFSET.
//   +2336 .. +2367 FORS_SK_ADRS_OFFSET: scratch ADRS (FORS_PRF type)
//                    Aliases SK_ADRS_OFFSET.
//   +2368 .. +2399 FORS_PK_ADRS_OFFSET: scratch ADRS (FORS_ROOTS type)
//                    Aliases WOTSPK_ADRS_OFFSET.
//   +2432 .. +3071 FORS_PAIR_BASE:      per-recursion-level lnode‖rnode
//                                       buffers, 2·n bytes per level z,
//                                       z ∈ [1..a]; max a = 9, 2·n = 64
//                                       → 9·64 = 576 B.
//
// fors_node recursion: caller's outPtr holds the result; child pairs
// land at FORS_PAIR_BASE + z*2n (per-depth stride, so descending into
// z-1 does not clobber z's slot). H runs over pair[0..2n].

import {
	STATE_OFFSET,
	getParamN, getParamSet,
	PARAMSET_128F, PARAMSET_192F,
} from './buffers';
import {
	ADRS_FORS_PRF, ADRS_FORS_ROOTS,
	adrsCopy,
	adrsSetType,
	adrsSetKeyPairAddress, adrsGetKeyPairAddress,
	adrsSetTreeHeight, adrsGetTreeIndex, adrsSetTreeIndex,
} from './address';
import {
	slhHashF, slhHashH, slhHashTl, slhPRF,
} from './hashes';

// ── Working-buffer offsets (STATE region; alias of wots.ts buffers) ────────

export const FORS_ROOTS_OFFSET:   i32 = STATE_OFFSET + 64;
export const FORS_LEAF_OFFSET:    i32 = STATE_OFFSET + 2208;
export const FORS_SK_ADRS_OFFSET: i32 = STATE_OFFSET + 2336;
export const FORS_PK_ADRS_OFFSET: i32 = STATE_OFFSET + 2368;
export const FORS_PAIR_BASE:      i32 = STATE_OFFSET + 2432;

// ── Parameter-set dispatch (FIPS 205 §11.1 Table 2) ────────────────────────
// k = trees, a = tree height (bits per FORS index). The PARAMS slot in
// buffers.ts only carries (n, m, paramSet); k and a are derived by per-set
// lookup rather than added as PARAMS fields.

@inline function forsK(): i32 {
	const ps = getParamSet();
	// FIPS 205 §11.1 Table 2: 128f/192f → k=33, 256f → k=35.
	if (ps === PARAMSET_128F || ps === PARAMSET_192F) return 33;
	return 35;
}

@inline function forsA(): i32 {
	const ps = getParamSet();
	// FIPS 205 §11.1 Table 2: 128f → a=6, 192f → a=8, 256f → a=9.
	if (ps === PARAMSET_128F) return 6;
	if (ps === PARAMSET_192F) return 8;
	return 9;
}

// ── base_2b for FORS message-digest unpacking ──────────────────────────────
// Same algorithm as WOTS+ (FIPS 205 §4 Algorithm 4). For FORS, b = a so
// digits range over [0, 2^a − 1]. With a ≤ 9, each digit still fits in
// 16 bits, so we store digits as a 2-byte little-endian pair to give a
// uniform stride; the caller indexes into FORS_INDICES_OFFSET below.
//
// Layout: indices[i] occupies 2 bytes at FORS_INDICES_OFFSET + i·2. The
// buffer aliases WOTS_MSG_OFFSET (+2240..+2335) because FORS never uses
// the WOTS+ msg||csum scratch, so the 96 B WOTS+ window safely hosts the
// 70 B (max, k=35) FORS-indices array. Aliasing-safe with SK_ADRS_OFFSET
// at +2336 (no overlap, separated by 26 B of WOTS_MSG slack).

const FORS_INDICES_OFFSET: i32 = STATE_OFFSET + 2240;   // 70-byte usage,
                                                        // 96-byte slot

function forsBase2b(outPtr: i32, xPtr: i32, b: i32, outLen: i32): void {
	let inIdx: i32 = 0;     // FIPS 205 §4 Algorithm 4 line 1
	let bits:  i32 = 0;     // FIPS 205 §4 Algorithm 4 line 2
	let total: u32 = 0;     // FIPS 205 §4 Algorithm 4 line 3
	const mask: u32 = (<u32>1 << b) - 1;

	for (let out = 0; out < outLen; out++) {                            // line 4
		while (bits < b) {                                              // line 5
			total = (total << 8) | (<u32>load<u8>(xPtr + inIdx));       // line 6
			inIdx++;                                                    // line 7
			bits += 8;                                                  // line 8
		}
		bits -= b;                                                      // line 10
		const digit: u32 = (total >>> bits) & mask;                     // line 11
		store<u16>(outPtr + out * 2, <u16>digit);
	}
}

@inline function forsIdx(i: i32): u32 {
	return <u32>load<u16>(FORS_INDICES_OFFSET + i * 2);
}

// ── FIPS 205 §8 Algorithm 14, fors_skGen ──────────────────────────────────
// Derives a single n-byte FORS private-key value. Internal helper used by
// fors_node (z = 0 leaf branch) and fors_sign.

function forsSkGenInternal(
	outPtr:    i32,
	skSeedPtr: i32,
	idx:       u32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	// FIPS 205 line 1: skADRS ← ADRS
	adrsCopy(FORS_SK_ADRS_OFFSET, adrsPtr);
	// FIPS 205 line 2: skADRS.setTypeAndClear(FORS_PRF)
	adrsSetType(FORS_SK_ADRS_OFFSET, ADRS_FORS_PRF);
	// FIPS 205 line 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	adrsSetKeyPairAddress(FORS_SK_ADRS_OFFSET, adrsGetKeyPairAddress(adrsPtr));
	// FIPS 205 line 4: skADRS.setTreeIndex(idx)
	adrsSetTreeIndex(FORS_SK_ADRS_OFFSET, idx);
	// FIPS 205 line 5: return PRF(PK.seed, SK.seed, skADRS)
	slhPRF(outPtr, pkSeedPtr, skSeedPtr, FORS_SK_ADRS_OFFSET);
}

export function forsSkGen(
	outPtr:    i32,
	skSeedPtr: i32,
	idx:       u32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	forsSkGenInternal(outPtr, skSeedPtr, idx, pkSeedPtr, adrsPtr);
}

// ── FIPS 205 §8 Algorithm 15, fors_node ────────────────────────────────────
// Recursively computes a node at height z, index i, within the FORS tree
// reachable from ADRS. Output lands at outPtr (n bytes). The recursion
// depth is bounded by a (≤ 9 for FIPS 205 approved sets) so a fixed
// per-depth scratch pool suffices.

export function forsNode(
	outPtr:    i32,
	skSeedPtr: i32,
	i:         u32,
	z:         i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n = getParamN();

	if (z === 0) {
		// FIPS 205 line 2: sk ← fors_skGen(SK.seed, PK.seed, ADRS, i)
		forsSkGenInternal(outPtr, skSeedPtr, i, pkSeedPtr, adrsPtr);
		// FIPS 205 line 3: ADRS.setTreeHeight(0)
		adrsSetTreeHeight(adrsPtr, 0);
		// FIPS 205 line 4: ADRS.setTreeIndex(i)
		adrsSetTreeIndex(adrsPtr, i);
		// FIPS 205 line 5: node ← F(PK.seed, ADRS, sk). sk currently lives
		// at outPtr (forsSkGenInternal wrote it there); F aliases-safe per
		// hashes.ts contract (full absorb before squeeze).
		slhHashF(outPtr, pkSeedPtr, adrsPtr, outPtr);
		return;
	}

	// FIPS 205 lines 7-8: recurse on left + right children. Each child's
	// result lives in its half of the per-z pair buffer.
	const pair = FORS_PAIR_BASE + z * 2 * n;
	forsNode(pair,     skSeedPtr, i * 2,     z - 1, pkSeedPtr, adrsPtr);
	forsNode(pair + n, skSeedPtr, i * 2 + 1, z - 1, pkSeedPtr, adrsPtr);

	// FIPS 205 lines 9-11: ADRS.setTreeHeight(z); ADRS.setTreeIndex(i);
	// node ← H(PK.seed, ADRS, lnode ‖ rnode)
	adrsSetTreeHeight(adrsPtr, <u32>z);
	adrsSetTreeIndex(adrsPtr, i);
	slhHashH(outPtr, pkSeedPtr, adrsPtr, pair);
}

// ── FIPS 205 §8 Algorithm 16, fors_sign ────────────────────────────────────
// Signs a ⌈k·a/8⌉-byte digest. Signature layout (k·(a+1)·n bytes):
//   per tree i ∈ [0, k):
//     n bytes: secret value at index i·2^a + indices[i]
//     a·n bytes: authentication path bottom-up
// Total: k·(a+1)·n bytes; matches FIPS 205 §11.1 Table 2 / §9 sigEncode.

export function forsSign(
	outSigPtr: i32,
	mdPtr:     i32,
	skSeedPtr: i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n = getParamN();
	const k = forsK();
	const a = forsA();

	// FIPS 205 line 2: indices ← base_2b(md, a, k)
	forsBase2b(FORS_INDICES_OFFSET, mdPtr, a, k);

	const pow2a: u32 = <u32>1 << a;
	const perTree = (a + 1) * n;

	// FIPS 205 lines 3-10: per tree i, write sk and a-element auth path.
	for (let i = 0; i < k; i++) {
		const idx_i = forsIdx(i);
		const base  = outSigPtr + i * perTree;

		// FIPS 205 line 4: SIG ← SIG ‖ fors_skGen(..., i·2^a + indices[i])
		forsSkGenInternal(base, skSeedPtr, <u32>i * pow2a + idx_i, pkSeedPtr, adrsPtr);

		// FIPS 205 lines 5-8: AUTH[j] ← fors_node(SK.seed,
		// i·2^(a−j) + (⌊indices[i]/2^j⌋ ⊕ 1), j, PK.seed, ADRS)
		for (let j = 0; j < a; j++) {
			const s: u32 = (idx_i >>> j) ^ 1;
			const childIdx: u32 = <u32>i * (pow2a >>> j) + s;
			forsNode(base + n + j * n, skSeedPtr, childIdx, j, pkSeedPtr, adrsPtr);
		}
	}
}

// ── FIPS 205 §8 Algorithm 17, fors_pkFromSig ──────────────────────────────
// Recovers the n-byte FORS public key from a k·(a+1)·n-byte signature and
// the same ⌈k·a/8⌉-byte digest used at signing time.

export function forsPkFromSig(
	outPkPtr:  i32,
	sigPtr:    i32,
	mdPtr:     i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n = getParamN();
	const k = forsK();
	const a = forsA();

	// FIPS 205 line 1: indices ← base_2b(md, a, k)
	forsBase2b(FORS_INDICES_OFFSET, mdPtr, a, k);

	const pow2a: u32 = <u32>1 << a;
	const perTree = (a + 1) * n;

	// FIPS 205 lines 2-20: rebuild each tree's root in FORS_ROOTS_OFFSET.
	for (let i = 0; i < k; i++) {
		const idx_i = forsIdx(i);
		const base  = sigPtr + i * perTree;

		// FIPS 205 line 3: sk ← SIG.getSK(i) → SIG[i·(a+1)·n : (i·(a+1)+1)·n]
		// FIPS 205 line 4: ADRS.setTreeHeight(0)
		adrsSetTreeHeight(adrsPtr, 0);
		// FIPS 205 line 5: ADRS.setTreeIndex(i·2^a + indices[i])
		adrsSetTreeIndex(adrsPtr, <u32>i * pow2a + idx_i);
		// FIPS 205 line 6: node[0] ← F(PK.seed, ADRS, sk). Stage the leaf
		// hash in FORS_LEAF_OFFSET so the auth-path loop can rebuild upward.
		slhHashF(FORS_LEAF_OFFSET, pkSeedPtr, adrsPtr, base);

		// FIPS 205 lines 7-18: combine with auth[j] for j ∈ [0, a).
		// auth = SIG[(i·(a+1)+1)·n : (i+1)·(a+1)·n], stride n per element.
		for (let j = 0; j < a; j++) {
			const authJ = base + n + j * n;
			adrsSetTreeHeight(adrsPtr, <u32>(j + 1));

			// FIPS 205 lines 10-15: branch on parity of ⌊indices[i]/2^j⌋.
			//   even → node[1] ← H(PK.seed, ADRS_idx/2, node[0] ‖ auth[j])
			//   odd  → node[1] ← H(PK.seed, ADRS_(idx-1)/2, auth[j] ‖ node[0])
			const treeIdx = adrsGetTreeIndex(adrsPtr);
			if (((idx_i >>> j) & 1) === 0) {
				adrsSetTreeIndex(adrsPtr, treeIdx >>> 1);
				// Compose node[0] ‖ auth[j] into the level-(j+1) pair slot
				// so H absorbs 2n contiguous bytes. Reuse FORS_PAIR_BASE
				// since forsNode is not active here.
				const pair = FORS_PAIR_BASE + (j + 1) * 2 * n;
				memory.copy(pair,     FORS_LEAF_OFFSET, n);
				memory.copy(pair + n, authJ,            n);
				slhHashH(FORS_LEAF_OFFSET, pkSeedPtr, adrsPtr, pair);
			} else {
				adrsSetTreeIndex(adrsPtr, (treeIdx - 1) >>> 1);
				const pair = FORS_PAIR_BASE + (j + 1) * 2 * n;
				memory.copy(pair,     authJ,            n);
				memory.copy(pair + n, FORS_LEAF_OFFSET, n);
				slhHashH(FORS_LEAF_OFFSET, pkSeedPtr, adrsPtr, pair);
			}
		}

		// FIPS 205 line 19: root[i] ← node[0]
		memory.copy(FORS_ROOTS_OFFSET + i * n, FORS_LEAF_OFFSET, n);
	}

	// FIPS 205 lines 21-24: forspkADRS ← ADRS; setTypeAndClear(FORS_ROOTS);
	// setKeyPairAddress(...); pk ← T_k(PK.seed, forspkADRS, root)
	adrsCopy(FORS_PK_ADRS_OFFSET, adrsPtr);
	adrsSetType(FORS_PK_ADRS_OFFSET, ADRS_FORS_ROOTS);
	adrsSetKeyPairAddress(FORS_PK_ADRS_OFFSET, adrsGetKeyPairAddress(adrsPtr));
	slhHashTl(outPkPtr, pkSeedPtr, FORS_PK_ADRS_OFFSET, FORS_ROOTS_OFFSET, k * n);
}

// ── Internal accessors for the unit test bridge ────────────────────────────

export function _testForsK(): i32 { return forsK(); }
export function _testForsA(): i32 { return forsA(); }
