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
// src/asm/slhdsa/slh.ts
//
// FIPS 205 §9 SLH-DSA Internal Functions. Composes WOTS+, FORS, XMSS, and
// hypertree from this module's primitives into the three exported entry
// points: keygen_internal (Algorithm 18), sign_internal (Algorithm 19),
// verify_internal (Algorithm 20).
//
// I/O byte layouts (INPUT_OFFSET / OUT_OFFSET):
//
//   slhKeygenInternal():
//     INPUT  = SK.seed (n) ‖ SK.prf (n) ‖ PK.seed (n)        (3·n bytes)
//     OUT    = SK (4·n) ‖ PK (2·n)                           (6·n bytes)
//     SK     = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root          (FIPS 205 §9.1 fig 15)
//     PK     = PK.seed ‖ PK.root                             (FIPS 205 §9.1 fig 16)
//
//   slhSignInternal(msgLen):
//     INPUT  = SK (4·n) ‖ M (msgLen) ‖ opt_rand (n)
//     OUT    = SIG (sigBytes)
//     SIG    = R (n) ‖ SIG_FORS (k·(a+1)·n) ‖ SIG_HT ((h + d·len)·n)
//     opt_rand is whatever the caller wrote: random n bytes for hedged,
//     PK.seed for deterministic, caller-chosen for derand (FIPS 205 §9.2).
//
//   slhVerifyInternal(msgLen):
//     INPUT  = PK (2·n) ‖ M (msgLen) ‖ SIG (sigBytes)
//     return 1 if verify ok, else 0
//
// Working-state offsets (STATE region, base = STATE_OFFSET):
//   +0   .. +31    ADRS canonical scratch (set up by buffers.ts)
//   +32  .. +47    PARAMS slot
//   +64  .. +3071  WOTS+ / FORS working buffers (wots.ts, fors.ts)
//   +3072.. +3391  XMSS pair-stack buffer (xmss.ts)
//   +3392.. +3423  HT_ROOT_OFFSET, layer-to-layer XMSS root (hypertree.ts)
//   +3424.. +3471  SLH_DIGEST_OFFSET, m-byte H_msg output (this file)
//                  max m = 49 (256f); allocate 48-byte buffer with slack
//   +3472.. +3503  SLH_PK_FORS_OFFSET, n-byte FORS public key (this file)
//                  max n = 32; carried from fors_pkFromSig to ht_sign / ht_verify

import {
	INPUT_OFFSET, OUT_OFFSET, STATE_OFFSET,
	ADRS_OFFSET, ADRS_SIZE,
	getParamN, getParamSet,
	PARAMSET_128F, PARAMSET_192F,
} from './buffers';
import {
	ADRS_FORS_TREE,
	adrsSetLayerAddress, adrsSetTreeAddr,
	adrsSetType, adrsSetKeyPairAddress,
} from './address';
import {
	slhPRFmsg, slhHmsg,
} from './hashes';
import {
	xmssNode,
} from './xmss';
import {
	forsSign, forsPkFromSig,
} from './fors';
import {
	htSign, htVerify,
} from './hypertree';

// ── Working-buffer offsets (STATE region, this file's slice) ───────────────

/** H_msg output: m bytes, max 49 (256f). Slot is 48 B with slack. */
const SLH_DIGEST_OFFSET:  i32 = STATE_OFFSET + 3424;

/** FORS public-key carrier: n bytes, max 32 (256f). Lives between
 *  fors_pkFromSig (consumer) and ht_sign / ht_verify (consumer). */
const SLH_PK_FORS_OFFSET: i32 = STATE_OFFSET + 3472;

// ── Per-parameter-set dimension lookups ────────────────────────────────────
// k / a / h / d / h' fall out of param-set tag; the PARAMS slot in buffers.ts
// only carries (n, m, paramSet) so wots.ts / fors.ts / xmss.ts / hypertree.ts
// each hardcode the same lookups. SLH-level dimensions follow the same shape.
//
// FIPS 205 §11.1 Table 2.

@inline function slhK(): i32 {
	const ps = getParamSet();
	if (ps === PARAMSET_128F || ps === PARAMSET_192F) return 33;
	return 35;
}

@inline function slhA(): i32 {
	const ps = getParamSet();
	if (ps === PARAMSET_128F) return 6;
	if (ps === PARAMSET_192F) return 8;
	return 9;
}

@inline function slhD(): i32 {
	const ps = getParamSet();
	if (ps === PARAMSET_128F || ps === PARAMSET_192F) return 22;
	return 17;
}

@inline function slhHPrime(): i32 {
	const ps = getParamSet();
	if (ps === PARAMSET_128F || ps === PARAMSET_192F) return 3;
	return 4;
}

// ── Digest split (FIPS 205 §9.2 Algorithm 19 lines 6-10) ───────────────────
// digest layout: md (⌈k·a/8⌉) ‖ tmp_idx_tree (⌈(h-h/d)/8⌉) ‖
//                tmp_idx_leaf (⌈h/(8·d)⌉).
//
// Per-set splits (h = d·h' so h - h/d = (d−1)·h'):
//                       md_bytes   tree_bytes   leaf_bytes   tree_bits   leaf_bits
//   128f (n=16)         25         8            1            63          3
//   192f (n=24)         33         8            1            63          3
//   256f (n=32)         40         8            1            64          4
//
// idx_tree is u64-wide for all sets, masked to the relevant bit count.
// idx_leaf is u32-wide for all sets, masked to h'.

@inline function mdBytes(): i32 {
	// ⌈k·a/8⌉
	const ka = slhK() * slhA();
	return (ka + 7) >> 3;
}

@inline function treeBytes(): i32 {
	// ⌈(h - h/d)/8⌉ = ⌈(d-1)·h'/8⌉. 128f/192f → 8; 256f → 8 (64/8).
	const hhd = (slhD() - 1) * slhHPrime();
	return (hhd + 7) >> 3;
}

// ⌈h/(8·d)⌉ = ⌈h'/8⌉ ≡ 1 for all FIPS 205 fast variants. tmp_idx_leaf is
// therefore a single byte; the digest split loads it directly via load<u8>
// and the dedicated helper is inlined into the algorithm body.

/** Big-endian load of `len` ≤ 8 bytes into a u64. Used for idx_tree extraction
 *  from the message digest (FIPS 205 line 9 toInt(tmp_idx_tree, ⌈(h-h/d)/8⌉)). */
@inline function loadBE(ptr: i32, len: i32): u64 {
	let v: u64 = 0;
	for (let i = 0; i < len; i++) {
		v = (v << <u64>8) | <u64>load<u8>(ptr + i);
	}
	return v;
}

// ── FIPS 205 §9.1 Algorithm 18, slh_keygen_internal ────────────────────────
// Drives the top-layer (layer d-1) XMSS subtree root computation. The 3·n
// seed material (SK.seed ‖ SK.prf ‖ PK.seed) at INPUT becomes
// SK (4·n) ‖ PK (2·n) at OUT.

export function slhKeygenInternal(): void {
	const n  = getParamN();
	const hp = slhHPrime();
	const d  = slhD();

	const skSeedIn = INPUT_OFFSET + 0;
	const skPrfIn  = INPUT_OFFSET + n;
	const pkSeedIn = INPUT_OFFSET + n * 2;

	const skOut    = OUT_OFFSET;
	const pkOut    = OUT_OFFSET + n * 4;

	// Build SK frame: SK.seed ‖ SK.prf ‖ PK.seed already in INPUT layout
	// in the same order as SK[0..3n]. PK.root is written by the xmss_node
	// call below into SK[3n..4n]. PK = (PK.seed, PK.root) is then a memmove
	// of SK[2n..4n] to OUT+4n.
	memory.copy(skOut + 0,     skSeedIn, n);             // SK.seed
	memory.copy(skOut + n,     skPrfIn,  n);             // SK.prf
	memory.copy(skOut + n * 2, pkSeedIn, n);             // PK.seed

	// FIPS 205 §9.1 Algorithm 18 line 1: ADRS ← toByte(0, 32)
	memory.fill(ADRS_OFFSET, 0, ADRS_SIZE);
	// FIPS 205 §9.1 Algorithm 18 line 2: ADRS.setLayerAddress(d − 1)
	adrsSetLayerAddress(ADRS_OFFSET, d - 1);
	// FIPS 205 §9.1 Algorithm 18 line 3: PK.root ← xmss_node(SK.seed, 0, h', PK.seed, ADRS)
	// xmss_node writes its n-byte result to outPtr; we point it directly at
	// SK[3n..4n] which is the PK.root slot in the SK encoding.
	xmssNode(skOut + n * 3, skSeedIn, 0, hp, pkSeedIn, ADRS_OFFSET);

	// FIPS 205 §9.1 Algorithm 18 line 4 + Figure 16: PK = (PK.seed, PK.root).
	memory.copy(pkOut,     pkSeedIn,      n);            // PK.seed
	memory.copy(pkOut + n, skOut + n * 3, n);            // PK.root
}

// ── FIPS 205 §9.2 Algorithm 19, slh_sign_internal ──────────────────────────
// Generates an SLH-DSA signature on M with sk = (SK.seed, SK.prf, PK.seed,
// PK.root) using opt_rand as the randomizer.
//
// The caller picks opt_rand semantics: random n bytes for hedged signing
// (FIPS 205 §9.2 "addrnd"), PK.seed for the deterministic variant (line 2),
// or caller-supplied for derand (CAVP / ACVP). The WASM does not inspect
// opt_rand contents; it just reads n bytes from INPUT + 4n + msgLen.

export function slhSignInternal(msgLen: i32): void {
	const n  = getParamN();
	const k  = slhK();
	const a  = slhA();
	const hp = slhHPrime();
	const md = mdBytes();
	const tb = treeBytes();

	const skSeed  = INPUT_OFFSET + 0;
	const skPrf   = INPUT_OFFSET + n;
	const pkSeed  = INPUT_OFFSET + n * 2;
	const pkRoot  = INPUT_OFFSET + n * 3;
	const mPtr    = INPUT_OFFSET + n * 4;
	const optRand = INPUT_OFFSET + n * 4 + msgLen;

	const rOut       = OUT_OFFSET;
	const sigForsOut = OUT_OFFSET + n;
	const sigHtOut   = OUT_OFFSET + n + k * (a + 1) * n;

	// FIPS 205 §9.2 Algorithm 19 line 1: ADRS ← toByte(0, 32)
	memory.fill(ADRS_OFFSET, 0, ADRS_SIZE);

	// FIPS 205 §9.2 Algorithm 19 lines 2-4: R ← PRF_msg(SK.prf, opt_rand, M);
	// SIG ← R. The opt_rand substitution for the deterministic variant is the
	// caller's responsibility (TS layer writes opt_rand = PK.seed); the WASM
	// reads whatever is in INPUT + 4n + msgLen unconditionally.
	slhPRFmsg(rOut, skPrf, optRand, mPtr, msgLen);

	// FIPS 205 §9.2 Algorithm 19 line 5: digest ← H_msg(R, PK.seed, PK.root, M).
	// H_msg output length is m bytes (PARAMS_M_OFF), not n; SLH_DIGEST_OFFSET
	// holds it for the bit-extraction lines that follow.
	slhHmsg(SLH_DIGEST_OFFSET, rOut, pkSeed, pkRoot, mPtr, msgLen);

	// FIPS 205 §9.2 Algorithm 19 lines 6-10: split digest into md / tmp_idx_tree /
	// tmp_idx_leaf, then idx_tree ← toInt(tmp_idx_tree, tb) mod 2^(h-h/d) and
	// idx_leaf ← toInt(tmp_idx_leaf, lb) mod 2^(h/d).
	//
	// md is consumed as-is by fors_sign (a k·a-bit message); the bit-extraction
	// here only touches idx_tree / idx_leaf.
	const tmpIdxTree = SLH_DIGEST_OFFSET + md;
	const tmpIdxLeaf = SLH_DIGEST_OFFSET + md + tb;
	let idxTree: u64 = loadBE(tmpIdxTree, tb);
	let idxLeaf: u32 = <u32>load<u8>(tmpIdxLeaf);     // leafBytes ≡ 1 for all fast sets

	// Mask to the bit widths from FIPS 205 §11.1 Table 2.
	// tree_bits = h - h/d ∈ {63, 64}; leaf_bits = h/d = h' ∈ {3, 4}.
	const treeBits: i32 = (slhD() - 1) * hp;
	const leafBits: i32 = hp;
	if (treeBits < 64) {
		idxTree &= ((<u64>1 << <u64>treeBits) - <u64>1);
	}
	idxLeaf &= ((<u32>1 << <u32>leafBits) - <u32>1);

	// FIPS 205 §9.2 Algorithm 19 lines 11-13: ADRS.setTreeAddress(idx_tree);
	// ADRS.setTypeAndClear(FORS_TREE); ADRS.setKeyPairAddress(idx_leaf).
	adrsSetTreeAddr(ADRS_OFFSET, 0, <u32>(idxTree >>> <u64>32), <u32>idxTree);
	adrsSetType(ADRS_OFFSET, ADRS_FORS_TREE);
	adrsSetKeyPairAddress(ADRS_OFFSET, idxLeaf);

	// FIPS 205 §9.2 Algorithm 19 lines 14-15: SIG_FORS ← fors_sign(md, SK.seed,
	// PK.seed, ADRS); SIG ← SIG ‖ SIG_FORS.
	forsSign(sigForsOut, SLH_DIGEST_OFFSET, skSeed, pkSeed, ADRS_OFFSET);

	// FIPS 205 §9.2 Algorithm 19 line 16: PK_FORS ← fors_pkFromSig(SIG_FORS,
	// md, PK.seed, ADRS). PK_FORS is the message that the hypertree will sign.
	forsPkFromSig(SLH_PK_FORS_OFFSET, sigForsOut, SLH_DIGEST_OFFSET, pkSeed, ADRS_OFFSET);

	// FIPS 205 §9.2 Algorithm 19 lines 17-18: SIG_HT ← ht_sign(PK_FORS, SK.seed,
	// PK.seed, idx_tree, idx_leaf); SIG ← SIG ‖ SIG_HT. ht_sign re-clears ADRS
	// internally, so the FORS_TREE residue does not survive into the hypertree
	// layer.
	htSign(
		sigHtOut, SLH_PK_FORS_OFFSET, skSeed, pkSeed,
		<u32>(idxTree >>> <u64>32), <u32>idxTree, idxLeaf,
		ADRS_OFFSET,
	);
}

// ── FIPS 205 §9.3 Algorithm 20, slh_verify_internal ────────────────────────
// Verifies an SLH-DSA signature. Returns 1 on success, 0 on failure.
//
// The length-check on line 1 of Algorithm 20 is the caller's responsibility:
// the TS layer presents sig as a Uint8Array of length sigBytes; the WASM
// layout assumes that contract holds. ht_verify already runs the constant-
// time PK.root comparison so the verifier surface is branch-free on the
// secret-equivalence path.

export function slhVerifyInternal(msgLen: i32): i32 {
	const n  = getParamN();
	const k  = slhK();
	const a  = slhA();
	const hp = slhHPrime();
	const md = mdBytes();
	const tb = treeBytes();

	const pkSeed = INPUT_OFFSET + 0;
	const pkRoot = INPUT_OFFSET + n;
	const mPtr   = INPUT_OFFSET + n * 2;
	const sigPtr = INPUT_OFFSET + n * 2 + msgLen;

	const r        = sigPtr;
	const sigFors  = sigPtr + n;
	const sigHt    = sigPtr + n + k * (a + 1) * n;

	// FIPS 205 §9.3 Algorithm 20 lines 4-7: ADRS ← toByte(0, 32);
	// R, SIG_FORS, SIG_HT are slices of SIG.
	memory.fill(ADRS_OFFSET, 0, ADRS_SIZE);

	// FIPS 205 §9.3 Algorithm 20 line 8: digest ← H_msg(R, PK.seed, PK.root, M)
	slhHmsg(SLH_DIGEST_OFFSET, r, pkSeed, pkRoot, mPtr, msgLen);

	// FIPS 205 §9.3 Algorithm 20 lines 9-13: split digest, mask idx_tree /
	// idx_leaf to the per-set bit widths.
	const tmpIdxTree = SLH_DIGEST_OFFSET + md;
	const tmpIdxLeaf = SLH_DIGEST_OFFSET + md + tb;
	let idxTree: u64 = loadBE(tmpIdxTree, tb);
	let idxLeaf: u32 = <u32>load<u8>(tmpIdxLeaf);

	const treeBits: i32 = (slhD() - 1) * hp;
	const leafBits: i32 = hp;
	if (treeBits < 64) {
		idxTree &= ((<u64>1 << <u64>treeBits) - <u64>1);
	}
	idxLeaf &= ((<u32>1 << <u32>leafBits) - <u32>1);

	// FIPS 205 §9.3 Algorithm 20 lines 14-16: ADRS.setTreeAddress(idx_tree);
	// ADRS.setTypeAndClear(FORS_TREE); ADRS.setKeyPairAddress(idx_leaf).
	adrsSetTreeAddr(ADRS_OFFSET, 0, <u32>(idxTree >>> <u64>32), <u32>idxTree);
	adrsSetType(ADRS_OFFSET, ADRS_FORS_TREE);
	adrsSetKeyPairAddress(ADRS_OFFSET, idxLeaf);

	// FIPS 205 §9.3 Algorithm 20 line 17: PK_FORS ← fors_pkFromSig(SIG_FORS,
	// md, PK.seed, ADRS).
	forsPkFromSig(SLH_PK_FORS_OFFSET, sigFors, SLH_DIGEST_OFFSET, pkSeed, ADRS_OFFSET);

	// FIPS 205 §9.3 Algorithm 20 line 18: return ht_verify(PK_FORS, SIG_HT,
	// PK.seed, idx_tree, idx_leaf, PK.root). ht_verify runs the final
	// constant-time PK.root compare.
	return htVerify(
		SLH_PK_FORS_OFFSET, sigHt, pkSeed,
		<u32>(idxTree >>> <u64>32), <u32>idxTree, idxLeaf,
		pkRoot, ADRS_OFFSET,
	);
}
