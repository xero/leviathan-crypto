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
// src/asm/slhdsa/hypertree.ts
//
// FIPS 205 §7 Hypertree. The hypertree is a stack of d XMSS subtrees: the
// bottom-layer subtree signs an n-byte message (in SLH-DSA, the FORS public
// key derived from the message digest); each higher layer's subtree signs
// the previous layer's XMSS root via wots_sign, lifting the per-subtree
// authentication into a chain that terminates at PK.root.
//
// Algorithms implemented (FIPS 205 numbering):
//   Algorithm 12  ht_sign:   sign across all d hypertree layers
//   Algorithm 13  ht_verify: verify across all d layers
//
// Hypertree dimensions per FIPS 205 §11.1 Table 2:
//
//   param-set  h   d   h' = h/d
//   128f       66  22  3
//   192f       66  22  3
//   256f       68  17  4
//
// Total HT signature size = d · (len + h') · n bytes (d XMSS sigs).
//
// Index update (FIPS 205 §7 Algorithm 12 line 8): at each layer ascent,
// idx_leaf ← idx_tree mod 2^h'; idx_tree ← idx_tree ≫ h'. The lower h' bits
// of idx_tree pick the leaf in the next-up subtree; the remaining bits
// become the next-up subtree's idx_tree. For 256f the initial idx_tree is a
// 64-bit value (h − h' = 64); the WASM API splits it into two u32 limbs
// (hi/lo) so the host can call without BigInt.
//
// Working-buffer layout extends xmss.ts's STATE region:
//   +3392 .. +3423  HT_ROOT_OFFSET: XMSS root (n bytes) carried across
//                                    hypertree layers as input M to the
//                                    next layer's xmss_sign.
//
// ADRS contract: ht_sign / ht_verify clear the caller's ADRS at start (line
// 1 of both algorithms is ADRS ← toByte(0, 32)), then setLayerAddress and
// setTreeAddress per iteration. xmss_sign / xmss_pkFromSig manage type /
// keypair / height / index internally.

import {
	STATE_OFFSET,
	getParamN, getParamSet,
	PARAMSET_128F, PARAMSET_192F,
} from './buffers';
import {
	ADRS_BYTES,
	adrsSetLayerAddress, adrsSetTreeAddr,
} from './address';
import {
	xmssSign, xmssPkFromSig,
} from './xmss';
import { ctEqual } from '../cte/shared';

// ── Working-buffer offset (STATE region) ───────────────────────────────────

/** XMSS root (n bytes) carried across hypertree layers. Layer j writes the
 *  recovered subtree root here so layer j+1's xmss_sign / xmss_pkFromSig
 *  can consume it as input M. Sized for n_max = 32 B. */
export const HT_ROOT_OFFSET: i32 = STATE_OFFSET + 3392;

// ── Per-parameter constants ────────────────────────────────────────────────
// h' and d derived per FIPS 205 §11.1 Table 2, parallel to xmss.ts and
// fors.ts. The PARAMS slot only carries (n, m, paramSet); k/a/d/h' are
// derived by per-set lookup rather than added as PARAMS fields.

@inline function htHPrime(): i32 {
	const ps = getParamSet();
	if (ps === PARAMSET_128F || ps === PARAMSET_192F) return 3;
	return 4;
}

@inline function htD(): i32 {
	const ps = getParamSet();
	if (ps === PARAMSET_128F || ps === PARAMSET_192F) return 22;
	return 17;
}

// ── FIPS 205 §7.1 Algorithm 12, ht_sign ────────────────────────────────────
// Produce a d-layer hypertree signature on the n-byte message M. Output
// layout: SIG_XMSS[0] ‖ SIG_XMSS[1] ‖ ... ‖ SIG_XMSS[d-1], each subtree sig
// being (len + h')·n bytes for a total of d · (len + h')·n bytes.
//
// idx_tree is the (h − h')-bit hypertree-subtree index passed as two u32
// halves (hi || lo, big-endian semantics on the host side, low-bit-first
// shift semantics here). idx_leaf is the h'-bit leaf index inside the
// bottom-layer subtree.

export function htSign(
	outSigPtr:  i32,
	mPtr:       i32,
	skSeedPtr:  i32,
	pkSeedPtr:  i32,
	idxTreeHi:  u32,
	idxTreeLo:  u32,
	idxLeaf:    u32,
	adrsPtr:    i32,
): void {
	const n  = getParamN();
	const hp = htHPrime();
	const d  = htD();
	const wotsLen = (n << 1) + 3;
	const xmssSigSize = (wotsLen + hp) * n;

	let idxTree: u64 = (<u64>idxTreeHi << <u64>32) | <u64>idxTreeLo;
	let leaf:    u32 = idxLeaf;

	// FIPS 205 line 1: ADRS ← toByte(0, 32)
	memory.fill(adrsPtr, 0, ADRS_BYTES);
	// FIPS 205 line 2: ADRS.setTreeAddress(idx_tree)
	adrsSetTreeAddr(adrsPtr, 0, <u32>(idxTree >>> <u64>32), <u32>idxTree);

	// FIPS 205 line 3: SIG_TMP ← xmss_sign(M, SK.seed, idx_leaf, PK.seed, ADRS)
	// FIPS 205 line 4: SIG_HT ← SIG_TMP (layer 0 sig written at outSigPtr).
	let sigOff = outSigPtr;
	xmssSign(sigOff, mPtr, skSeedPtr, leaf, pkSeedPtr, adrsPtr);

	// FIPS 205 line 5: root ← xmss_pkFromSig(idx_leaf, SIG_TMP, M, PK.seed, ADRS)
	xmssPkFromSig(HT_ROOT_OFFSET, leaf, sigOff, mPtr, pkSeedPtr, adrsPtr);

	// FIPS 205 lines 6-16: for j ∈ [1, d): ascend one layer.
	for (let j = 1; j < d; j++) {
		// FIPS 205 line 7: idx_leaf ← idx_tree mod 2^h'
		leaf = <u32>(idxTree & ((<u64>1 << <u64>hp) - <u64>1));
		// FIPS 205 line 8: idx_tree ← idx_tree ≫ h'
		idxTree = idxTree >>> <u64>hp;

		// FIPS 205 line 9:  ADRS.setLayerAddress(j)
		adrsSetLayerAddress(adrsPtr, j);
		// FIPS 205 line 10: ADRS.setTreeAddress(idx_tree)
		adrsSetTreeAddr(adrsPtr, 0, <u32>(idxTree >>> <u64>32), <u32>idxTree);

		// FIPS 205 line 11: SIG_TMP ← xmss_sign(root, SK.seed, idx_leaf, PK.seed, ADRS)
		// FIPS 205 line 12: SIG_HT ← SIG_HT ‖ SIG_TMP
		sigOff += xmssSigSize;
		xmssSign(sigOff, HT_ROOT_OFFSET, skSeedPtr, leaf, pkSeedPtr, adrsPtr);

		// FIPS 205 lines 13-15: if j < d − 1: root ← xmss_pkFromSig(...).
		// Top-layer root is unused (verify compares against PK.root).
		// Aliasing M = HT_ROOT_OFFSET = outRoot is safe: wots_pkFromSig
		// (inside xmss_pkFromSig) reads M once into WOTS_MSG_OFFSET before
		// the final T_len write to outRoot.
		if (j < d - 1) {
			xmssPkFromSig(HT_ROOT_OFFSET, leaf, sigOff, HT_ROOT_OFFSET, pkSeedPtr, adrsPtr);
		}
	}
}

// ── FIPS 205 §7.2 Algorithm 13, ht_verify ──────────────────────────────────
// Verify a d-layer hypertree signature. Returns 1 on success, 0 on failure.
// The walk reproduces ht_sign's layer ascent in reverse-cost order: each
// layer's xmss_pkFromSig lifts the prior-layer root into the next-up
// subtree root, which feeds the layer above. The final root is compared
// against PK.root byte-wise (the comparison is intentionally constant-time
// even though both sides are public material, to keep the discipline
// uniform across the slhdsa module).

export function htVerify(
	mPtr:       i32,
	sigPtr:     i32,
	pkSeedPtr:  i32,
	idxTreeHi:  u32,
	idxTreeLo:  u32,
	idxLeaf:    u32,
	pkRootPtr:  i32,
	adrsPtr:    i32,
): i32 {
	const n  = getParamN();
	const hp = htHPrime();
	const d  = htD();
	const wotsLen = (n << 1) + 3;
	const xmssSigSize = (wotsLen + hp) * n;

	let idxTree: u64 = (<u64>idxTreeHi << <u64>32) | <u64>idxTreeLo;
	let leaf:    u32 = idxLeaf;

	// FIPS 205 line 1: ADRS ← toByte(0, 32)
	memory.fill(adrsPtr, 0, ADRS_BYTES);
	// FIPS 205 line 2: ADRS.setTreeAddress(idx_tree)
	adrsSetTreeAddr(adrsPtr, 0, <u32>(idxTree >>> <u64>32), <u32>idxTree);

	// FIPS 205 lines 3-4: layer-0 root via xmss_pkFromSig(idx_leaf, SIG_TMP[0], M, ...).
	let sigOff = sigPtr;
	xmssPkFromSig(HT_ROOT_OFFSET, leaf, sigOff, mPtr, pkSeedPtr, adrsPtr);

	// FIPS 205 lines 5-12: ascend the remaining d − 1 layers.
	for (let j = 1; j < d; j++) {
		// FIPS 205 line 6: idx_leaf ← idx_tree mod 2^h'
		leaf = <u32>(idxTree & ((<u64>1 << <u64>hp) - <u64>1));
		// FIPS 205 line 7: idx_tree ← idx_tree ≫ h'
		idxTree = idxTree >>> <u64>hp;
		// FIPS 205 line 8: SIG_TMP ← SIG_HT.layer(j)
		sigOff += xmssSigSize;
		// FIPS 205 line 9:  ADRS.setLayerAddress(j)
		adrsSetLayerAddress(adrsPtr, j);
		// FIPS 205 line 10: ADRS.setTreeAddress(idx_tree)
		adrsSetTreeAddr(adrsPtr, 0, <u32>(idxTree >>> <u64>32), <u32>idxTree);
		// FIPS 205 line 11: node ← xmss_pkFromSig(idx_leaf, SIG_TMP, node, PK.seed, ADRS).
		// Aliasing M = HT_ROOT_OFFSET = outRoot is safe (see ht_sign comment).
		xmssPkFromSig(HT_ROOT_OFFSET, leaf, sigOff, HT_ROOT_OFFSET, pkSeedPtr, adrsPtr);
	}

	// FIPS 205 lines 13-14: return node = PK.root. Constant-time compare
	// via cte/shared ctEqual (inlined; returns 1 if equal, 0 if differ,
	// matching this function's caller contract).
	return ctEqual(HT_ROOT_OFFSET, pkRootPtr, n);
}

// ── Internal accessors for the unit test bridge ────────────────────────────

export function _testHtD():       i32 { return htD();       }
export function _testHtHPrime():  i32 { return htHPrime();  }
