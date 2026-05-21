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
// src/asm/slhdsa/xmss.ts
//
// FIPS 205 §6 XMSS (eXtended Merkle Signature Scheme), the per-subtree
// signing layer of SLH-DSA. An XMSS tree of height h' has 2^h' leaves; each
// leaf is a WOTS+ public key compressed via T_len. Inner nodes are the H
// tweakable hash over (left || right) child concatenation.
//
// Algorithms implemented (FIPS 205 numbering):
//   Algorithm  9  xmss_node:      node at height z, index i, in one subtree
//   Algorithm 10  xmss_sign:      WOTS+ sig + h' sibling auth path
//   Algorithm 11  xmss_pkFromSig: recover the subtree root from a signature
//
// Subtree heights per FIPS 205 §11.1 Table 2:
//
//   param-set  h'
//   128f       3
//   192f       3
//   256f       4
//
// XMSS leaf count per subtree = 2^h' (8 or 16). Per-subtree signature size
// = (len + h')·n bytes (len-element WOTS+ sig followed by the h'-element
// authentication path).
//
// Working-buffer layout extends fors.ts's STATE region:
//   +3072 .. +3391  XMSS_PAIR_BASE: per-recursion-level (lnode‖rnode)
//                                    pair slots for xmss_node, 2·n bytes
//                                    per level z ∈ [1..h']; max h'=4, n=32
//                                    so 5·64 = 320 B (slot 0 unused).
//
// Aliasing: xmss_node calls wots_pkGen at z=0, which reads/writes WOTS_TMP
// (+64..+2207) and WOTS_SK (+2208..+2239). Those buffers are reused on every
// leaf computation and never alias XMSS_PAIR_BASE. After wots_pkGen returns
// its n-byte result lives in the caller-supplied outPtr (the parent's pair
// slot), so WOTS_TMP being clobbered by the next leaf is irrelevant.
//
// ADRS mutation policy: xmssNode and xmssPkFromSig both mutate the caller's
// ADRS (type, keypair, treeHeight, treeIndex). layer + tree-address bytes
// are preserved across all mutations (FIPS 205 §4.2 setTypeAndClear preserves
// bytes 0..15). xmss_sign and xmss_pkFromSig reset the type explicitly so
// the caller does not need to restore ADRS between calls within ht_sign /
// ht_verify (hypertree.ts).

import {
	STATE_OFFSET,
	getParamN, getParamSet,
	PARAMSET_128F, PARAMSET_192F,
} from './buffers';
import {
	ADRS_WOTS_HASH, ADRS_TREE,
	adrsSetType,
	adrsSetKeyPairAddress,
	adrsSetTreeHeight,
	adrsSetTreeIndex, adrsGetTreeIndex,
} from './address';
import {
	slhHashH,
} from './hashes';
import {
	wotsPkGen, wotsSign, wotsPkFromSig,
} from './wots';

// ── Working-buffer offset (STATE region) ───────────────────────────────────

/** Per-level (lnode‖rnode) pair buffer for xmss_node recursion. Slot[z] =
 *  XMSS_PAIR_BASE + z·2n holds the two child nodes of a level-z parent.
 *  Slot 0 is unused (z=0 leaves go directly to the caller's outPtr via
 *  wots_pkGen). Sized for (h'_max + 1) · 2 · n_max = 5 · 64 = 320 B. */
export const XMSS_PAIR_BASE: i32 = STATE_OFFSET + 3072;

// ── h' subtree height (FIPS 205 §11.1 Table 2) ─────────────────────────────
// Hard-coded per approved parameter set so the PARAMS slot stays minimal
// (it carries only n / m / paramSet); h' falls out of paramSet directly.

@inline function xmssHPrime(): i32 {
	const ps = getParamSet();
	if (ps === PARAMSET_128F || ps === PARAMSET_192F) return 3;
	return 4;
}

// ── FIPS 205 §6.1 Algorithm 9, xmss_node ───────────────────────────────────
// Recursively compute the n-byte XMSS node at height z, index i, rooted in
// the subtree addressed by ADRS (layer + tree-address bytes pre-set by the
// caller). At z = 0 the node is a WOTS+ public key under ADRS_WOTS_HASH;
// at z > 0 the node is H over the concatenation of two child nodes from
// level z − 1.

export function xmssNode(
	outPtr:    i32,
	skSeedPtr: i32,
	i:         u32,
	z:         i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n = getParamN();

	if (z === 0) {
		// FIPS 205 line 2: ADRS.setTypeAndClear(WOTS_HASH)
		adrsSetType(adrsPtr, ADRS_WOTS_HASH);
		// FIPS 205 line 3: ADRS.setKeyPairAddress(i)
		adrsSetKeyPairAddress(adrsPtr, i);
		// FIPS 205 line 4: node ← wots_pkGen(SK.seed, PK.seed, ADRS)
		wotsPkGen(outPtr, skSeedPtr, pkSeedPtr, adrsPtr);
		return;
	}

	// FIPS 205 lines 6-7: recurse on left (2i) and right (2i+1) children at
	// level z − 1. Each child's result lands in its half of the per-z pair
	// slot. The two recursive calls reuse the same ADRS; descent paths
	// leave it in different intermediate states but the parent unwinds via
	// setTypeAndClear(TREE) on line 8 before any further read.
	const pair = XMSS_PAIR_BASE + z * 2 * n;
	xmssNode(pair,     skSeedPtr, i * 2,     z - 1, pkSeedPtr, adrsPtr);
	xmssNode(pair + n, skSeedPtr, i * 2 + 1, z - 1, pkSeedPtr, adrsPtr);

	// FIPS 205 line 8:  ADRS.setTypeAndClear(TREE)
	adrsSetType(adrsPtr, ADRS_TREE);
	// FIPS 205 line 9:  ADRS.setTreeHeight(z)
	adrsSetTreeHeight(adrsPtr, <u32>z);
	// FIPS 205 line 10: ADRS.setTreeIndex(i)
	adrsSetTreeIndex(adrsPtr, i);
	// FIPS 205 line 11: node ← H(PK.seed, ADRS, lnode‖rnode)
	slhHashH(outPtr, pkSeedPtr, adrsPtr, pair);
}

// ── FIPS 205 §6.2 Algorithm 10, xmss_sign ──────────────────────────────────
// Produce a signature on the n-byte message M within one XMSS subtree.
// Output layout: WOTS+ sig (len·n bytes) followed by the authentication path
// (h' nodes × n bytes, bottom-up). Total (len + h')·n bytes.
//
// idx is the h'-bit XMSS leaf index within this subtree. The caller's ADRS
// must carry the correct layer + tree-address bytes; xmss_sign mutates the
// remaining fields and leaves ADRS in WOTS_HASH state with keypair=idx on
// return (hypertree's caller does NOT depend on this and re-sets layer +
// tree-address explicitly before each iteration).

export function xmssSign(
	outSigPtr: i32,
	mPtr:      i32,
	skSeedPtr: i32,
	idx:       u32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n  = getParamN();
	const hp = xmssHPrime();
	// FIPS 205 §5 (lg_w = 4): len = 2·n + 3.
	const wotsLen = (n << 1) + 3;
	const authBase = outSigPtr + wotsLen * n;

	// FIPS 205 lines 1-4: for j ∈ [0, h'): k ← ⌊idx/2^j⌋ ⊕ 1;
	// AUTH[j] ← xmss_node(SK.seed, k, j, PK.seed, ADRS). Each xmss_node
	// mutates ADRS; the next iteration's xmss_node resets type/keypair/
	// height/index from scratch so leakage between iterations is harmless.
	for (let j = 0; j < hp; j++) {
		const k: u32 = (idx >>> <u32>j) ^ 1;
		xmssNode(authBase + j * n, skSeedPtr, k, j, pkSeedPtr, adrsPtr);
	}

	// FIPS 205 line 5: ADRS.setTypeAndClear(WOTS_HASH)
	adrsSetType(adrsPtr, ADRS_WOTS_HASH);
	// FIPS 205 line 6: ADRS.setKeyPairAddress(idx)
	adrsSetKeyPairAddress(adrsPtr, idx);
	// FIPS 205 line 7: sig_WOTS ← wots_sign(M, SK.seed, PK.seed, ADRS)
	// FIPS 205 line 8: SIG_XMSS ← sig_WOTS ‖ AUTH (AUTH already at authBase)
	wotsSign(outSigPtr, mPtr, skSeedPtr, pkSeedPtr, adrsPtr);
}

// ── FIPS 205 §6.3 Algorithm 11, xmss_pkFromSig ─────────────────────────────
// Recover the n-byte XMSS subtree root from a (len + h')·n-byte signature
// and the n-byte message M. Walks the authentication path bottom-up,
// combining each sibling with the running node[0] via H.
//
// Aliasing: outRootPtr and mPtr may alias (hypertree threads layer-(j-1)
// root in as both M for xmss_pkFromSig and as the destination for the
// recovered layer-j root). wots_pkFromSig reads M only at the start (into
// WOTS_MSG_OFFSET), then writes outRoot only at its final T_len step; the
// subsequent H loop reads outRoot and writes outRoot in place via the pair
// slot. Aliasing M = outRoot is safe.

export function xmssPkFromSig(
	outRootPtr: i32,
	idx:        u32,
	sigPtr:     i32,
	mPtr:       i32,
	pkSeedPtr:  i32,
	adrsPtr:    i32,
): void {
	const n  = getParamN();
	const hp = xmssHPrime();
	const wotsLen = (n << 1) + 3;
	const authBase = sigPtr + wotsLen * n;

	// FIPS 205 line 1: ADRS.setTypeAndClear(WOTS_HASH)
	adrsSetType(adrsPtr, ADRS_WOTS_HASH);
	// FIPS 205 line 2: ADRS.setKeyPairAddress(idx)
	adrsSetKeyPairAddress(adrsPtr, idx);
	// FIPS 205 line 5: node[0] ← wots_pkFromSig(sig, M, PK.seed, ADRS).
	// Stages node[0] directly at outRootPtr so the H loop can update it in
	// place via the pair slot.
	wotsPkFromSig(outRootPtr, sigPtr, mPtr, pkSeedPtr, adrsPtr);

	// FIPS 205 line 6: ADRS.setTypeAndClear(TREE)
	adrsSetType(adrsPtr, ADRS_TREE);
	// FIPS 205 line 7: ADRS.setTreeIndex(idx)
	adrsSetTreeIndex(adrsPtr, idx);

	// FIPS 205 lines 8-18: for k ∈ [0, h'): combine node[0] with AUTH[k]
	// under TreeHeight = k+1; branch on parity of ⌊idx/2^k⌋ for child
	// ordering and the TreeIndex update.
	for (let k = 0; k < hp; k++) {
		const authK = authBase + k * n;
		// FIPS 205 line 9: ADRS.setTreeHeight(k + 1)
		adrsSetTreeHeight(adrsPtr, <u32>(k + 1));

		const treeIdx = adrsGetTreeIndex(adrsPtr);
		const pair    = XMSS_PAIR_BASE + (k + 1) * 2 * n;

		if (((idx >>> <u32>k) & 1) === 0) {
			// FIPS 205 line 11: ADRS.setTreeIndex(treeIdx / 2)
			adrsSetTreeIndex(adrsPtr, treeIdx >>> 1);
			// FIPS 205 line 12: node[1] ← H(PK.seed, ADRS, node[0]‖AUTH[k])
			memory.copy(pair,     outRootPtr, n);
			memory.copy(pair + n, authK,      n);
		} else {
			// FIPS 205 line 14: ADRS.setTreeIndex((treeIdx − 1) / 2)
			adrsSetTreeIndex(adrsPtr, (treeIdx - 1) >>> 1);
			// FIPS 205 line 15: node[1] ← H(PK.seed, ADRS, AUTH[k]‖node[0])
			memory.copy(pair,     authK,      n);
			memory.copy(pair + n, outRootPtr, n);
		}
		// FIPS 205 line 17: node[0] ← node[1] (in-place write to outRoot)
		slhHashH(outRootPtr, pkSeedPtr, adrsPtr, pair);
	}
	// FIPS 205 line 19: return node[0] (already at outRootPtr).
}

// ── Internal accessors for the unit test bridge ────────────────────────────

export function _testXmssHPrime(): i32 { return xmssHPrime(); }
