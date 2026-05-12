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
// src/asm/slhdsa/wots.ts
//
// FIPS 205 §5 Winternitz One-Time Signature Plus (WOTS+).
//
// Algorithms implemented (FIPS 205 numbering):
//   Algorithm 4  base_2b           — byte-string → base-2^b digit array
//   Algorithm 5  chain             — iterative F hash chain
//   Algorithm 6  wots_pkGen        — derive public key from SK.seed
//   Algorithm 7  wots_sign         — sign an n-byte message
//   Algorithm 8  wots_pkFromSig    — recover public key from signature
//
// Lock-step structure with the spec: every helper / branch carries a
// `// FIPS 205 §5 Algorithm X line Y` comment so reviewers can trace
// each line back to the standard. Implementation is independent
// derivation per AGENTS.md §4; the slhdsa-c reference (slh_wots.c) is
// consulted only after the round-trip gates pass.
//
// Parameter derivations (FIPS 205 §5 lines 5.1-5.4, with lg_w = 4 fixed
// across the FIPS 205 approved sets):
//   w     = 2^lg_w = 16
//   len_1 = ⌈8·n / lg_w⌉ = 2·n
//   len_2 = ⌊log2(len_1 · (w-1)) / lg_w⌋ + 1 = 3 for n ∈ {16, 24, 32}
//   len   = len_1 + len_2 = 2·n + 3
//
// Working-buffer layout (STATE region, base = STATE_OFFSET; bytes 0..63
// hold ADRS + PARAMS, leaving 4032 free for the WOTS+ scratch below):
//   +64 .. +2207   WOTS_TMP_OFFSET — len·n public values (max 2144 B at 256f)
//   +2208 .. +2239 WOTS_SK_OFFSET  — n-byte PRF output scratch
//   +2240 .. +2335 WOTS_MSG_OFFSET — base-w encoded msg||csum array (max 67 B)
//   +2336 .. +2367 SK_ADRS_OFFSET  — scratch copy of ADRS (WOTS_PRF type)
//   +2368 .. +2399 WOTSPK_ADRS_OFFSET — scratch copy of ADRS (WOTS_PK type)
//
// FORS layers reuse +64..+2207 / +2336..+2399 (algorithms are mutually
// exclusive within a single WASM call); see src/asm/slhdsa/fors.ts.

import {
	STATE_OFFSET,
	getParamN,
} from './buffers';
import {
	ADRS_WOTS_PRF, ADRS_WOTS_PK,
	adrsCopy,
	adrsSetType,
	adrsSetKeyPairAddress, adrsGetKeyPairAddress,
	adrsSetChainAddress,
	adrsSetHashAddress,
} from './address';
import {
	slhHashF, slhHashTl, slhPRF,
} from './hashes';

// ── Working-buffer offsets (STATE region) ──────────────────────────────────

export const WOTS_TMP_OFFSET:        i32 = STATE_OFFSET + 64;
export const WOTS_SK_OFFSET:         i32 = STATE_OFFSET + 2208;
export const WOTS_MSG_OFFSET:        i32 = STATE_OFFSET + 2240;
export const SK_ADRS_OFFSET:         i32 = STATE_OFFSET + 2336;
export const WOTSPK_ADRS_OFFSET:     i32 = STATE_OFFSET + 2368;

// ── Derived constants (FIPS 205 §5 lines 5.1-5.4) ──────────────────────────

/** w − 1 = 15. End index of every WOTS+ hash chain (length-w chain runs
 *  through indices 0..w−1, with index 0 = secret value, index w−1 = public
 *  value). */
const W_MINUS_1: i32 = 15;
/** lg(w) = 4 for all FIPS 205 approved parameter sets (§11.1 Table 2). */
const LG_W:      i32 = 4;
/** len_2 = 3 for all FIPS 205 approved parameter sets. Re-derive:
 *  log2(2n·15)/4 + 1 = 3 for n ∈ {16, 24, 32}. */
const LEN2:      i32 = 3;

@inline function len1(): i32 { return getParamN() << 1; }                 // 2·n
@inline function len(): i32  { return (getParamN() << 1) + LEN2; }        // 2·n + 3

// ── FIPS 205 §4 Algorithm 4, base_2b ───────────────────────────────────────
// Computes the base-2^b representation of X. X is read MSB-first within
// each byte; outputs `outLen` base-2^b digits packed one per byte in `out`
// (each digit fits in 8 bits since b ≤ 9 in this standard).

function base2b(outPtr: i32, xPtr: i32, b: i32, outLen: i32): void {
	let inIdx: i32 = 0;     // FIPS 205 line 1: in   ← 0
	let bits:  i32 = 0;     // FIPS 205 line 2: bits ← 0
	let total: u32 = 0;     // FIPS 205 line 3: total ← 0
	const mask: u32 = (<u32>1 << b) - 1;

	// FIPS 205 lines 4-12
	for (let out = 0; out < outLen; out++) {
		// FIPS 205 lines 5-9: pull more bytes until `bits ≥ b`
		while (bits < b) {
			total = (total << 8) | (<u32>load<u8>(xPtr + inIdx));
			inIdx++;
			bits += 8;
		}
		// FIPS 205 line 10: bits ← bits − b
		bits -= b;
		// FIPS 205 line 11: base_b[out] ← (total ≫ bits) mod 2^b
		store<u8>(outPtr + out, <u8>((total >>> bits) & mask));
	}
}

// ── FIPS 205 §5 Algorithm 5, chain ─────────────────────────────────────────
// Iterates F `s` times on X starting at chain step `i`. Mutates the ADRS
// HashAddress field at each step; the caller's ADRS is left at HashAddress
// = i+s−1 on return when s > 0, unchanged when s = 0.
//
// Aliasing: F absorbs M1 fully before squeezing the output, so calling
// slhHashF with m1Ptr = outPtr is safe (see src/asm/slhdsa/hashes.ts —
// keccakAbsorbAt reads input bytes into the sponge before keccakSqueezeTo
// writes output back).

export function wotsChain(
	outPtr:    i32,
	xPtr:      i32,
	i:         i32,
	s:         i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n = getParamN();

	// FIPS 205 line 1: tmp ← X (copy X into the output slot so subsequent F
	// calls can iterate in place). Skip the copy if out and X are already
	// the same address.
	if (outPtr !== xPtr) memory.copy(outPtr, xPtr, n);

	// FIPS 205 lines 2-5: for j from i to i+s−1: ADRS.setHashAddress(j);
	// tmp ← F(PK.seed, ADRS, tmp). Loop is empty when s = 0 (line 1's copy
	// is the entire result, F(...)^0(X) = X).
	const end = i + s;
	for (let j = i; j < end; j++) {
		adrsSetHashAddress(adrsPtr, <u32>j);
		slhHashF(outPtr, pkSeedPtr, adrsPtr, outPtr);
	}
}

// ── FIPS 205 §5 Algorithm 6, wots_pkGen ────────────────────────────────────
// Derives the n-byte WOTS+ public key from SK.seed under the given ADRS.
// Mutates the caller's ADRS (chain address slot) during chain expansion;
// the caller is expected to reset / discard ADRS afterward.

export function wotsPkGen(
	outPkPtr:  i32,
	skSeedPtr: i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n      = getParamN();
	const lenAll = len();
	const kp     = adrsGetKeyPairAddress(adrsPtr);

	// FIPS 205 lines 1-3: skADRS ← ADRS; setTypeAndClear(WOTS_PRF);
	// setKeyPairAddress(ADRS.getKeyPairAddress())
	adrsCopy(SK_ADRS_OFFSET, adrsPtr);
	adrsSetType(SK_ADRS_OFFSET, ADRS_WOTS_PRF);
	adrsSetKeyPairAddress(SK_ADRS_OFFSET, kp);

	// FIPS 205 lines 4-9: for each chain, derive sk via PRF then run chain
	// from sk over w−1 F applications. Output slot tmp[i] = WOTS_TMP + i·n.
	for (let i = 0; i < lenAll; i++) {
		adrsSetChainAddress(SK_ADRS_OFFSET, <u32>i);
		slhPRF(WOTS_SK_OFFSET, pkSeedPtr, skSeedPtr, SK_ADRS_OFFSET);
		adrsSetChainAddress(adrsPtr, <u32>i);
		wotsChain(WOTS_TMP_OFFSET + i * n, WOTS_SK_OFFSET, 0, W_MINUS_1, pkSeedPtr, adrsPtr);
	}

	// FIPS 205 lines 10-13: wotspkADRS ← ADRS; setTypeAndClear(WOTS_PK);
	// setKeyPairAddress(ADRS.getKeyPairAddress()); pk ← T_len(PK.seed,
	// wotspkADRS, tmp). T_len is the tweakable hash T_ℓ with tail length
	// len·n (FIPS 205 §11.2 Table 4, ℓ = len here).
	adrsCopy(WOTSPK_ADRS_OFFSET, adrsPtr);
	adrsSetType(WOTSPK_ADRS_OFFSET, ADRS_WOTS_PK);
	adrsSetKeyPairAddress(WOTSPK_ADRS_OFFSET, kp);
	slhHashTl(outPkPtr, pkSeedPtr, WOTSPK_ADRS_OFFSET, WOTS_TMP_OFFSET, lenAll * n);
}

// ── Helper: convert an n-byte message into the len-element base-w digit
// array used by both wots_sign (Algorithm 7) and wots_pkFromSig
// (Algorithm 8). Writes len digits into WOTS_MSG_OFFSET. ──────────────────
//
// FIPS 205 §5 Algorithm 7 lines 2-7 (= §5 Algorithm 8 lines 2-7, identical
// pre-amble):
//   2: msg  ← base_2b(M, lg_w, len_1)
//   3-5: csum ← Σ (w−1−msg[i])  for i ∈ [0, len_1)
//   6: csum ← csum ≪ ((8 − ((len_2·lg_w) mod 8)) mod 8)
//   7: msg ← msg ‖ base_2b(toByte(csum, ⌈len_2·lg_w/8⌉), lg_w, len_2)
//
// For lg_w = 4 across all approved sets:
//   shift = (8 − ((3·4) mod 8)) mod 8 = (8 − 4) mod 8 = 4
//   ⌈(3·4)/8⌉ = 2-byte csum encoding (big-endian)

function wotsMsgEncode(mPtr: i32): void {
	const l1   = len1();
	const lAll = len();

	// FIPS 205 line 2: msg ← base_2b(M, lg_w, len_1)
	base2b(WOTS_MSG_OFFSET, mPtr, LG_W, l1);

	// FIPS 205 lines 3-5: csum ← Σ (w−1 − msg[i])
	let csum: u32 = 0;
	for (let i = 0; i < l1; i++) {
		csum += <u32>(W_MINUS_1 - <i32>load<u8>(WOTS_MSG_OFFSET + i));
	}

	// FIPS 205 line 6: csum ≪ 4 (constant shift for lg_w = 4).
	csum <<= 4;

	// FIPS 205 line 7 inner toByte(csum, 2): big-endian 2-byte encoding,
	// then unpack into len_2 = 3 nibbles via base_2b.
	store<u8>(WOTS_MSG_OFFSET + lAll,     <u8>((csum >>> 8) & 0xff));
	store<u8>(WOTS_MSG_OFFSET + lAll + 1, <u8>( csum        & 0xff));
	base2b(WOTS_MSG_OFFSET + l1, WOTS_MSG_OFFSET + lAll, LG_W, LEN2);
}

// ── FIPS 205 §5 Algorithm 7, wots_sign ─────────────────────────────────────
// Produces a len·n-byte WOTS+ signature on the n-byte message M.

export function wotsSign(
	outSigPtr: i32,
	mPtr:      i32,
	skSeedPtr: i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n      = getParamN();
	const lenAll = len();
	const kp     = adrsGetKeyPairAddress(adrsPtr);

	// FIPS 205 lines 1-7: build the len-element base-w msg||csum digit array
	wotsMsgEncode(mPtr);

	// FIPS 205 lines 8-10: skADRS ← ADRS; setTypeAndClear(WOTS_PRF);
	// setKeyPairAddress(ADRS.getKeyPairAddress())
	adrsCopy(SK_ADRS_OFFSET, adrsPtr);
	adrsSetType(SK_ADRS_OFFSET, ADRS_WOTS_PRF);
	adrsSetKeyPairAddress(SK_ADRS_OFFSET, kp);

	// FIPS 205 lines 11-16: per chain, sk ← PRF(...); sig[i] ← chain(sk, 0,
	// msg[i], PK.seed, ADRS). Each sig[i] occupies n bytes at outSigPtr+i·n.
	for (let i = 0; i < lenAll; i++) {
		const m = <i32>load<u8>(WOTS_MSG_OFFSET + i);
		adrsSetChainAddress(SK_ADRS_OFFSET, <u32>i);
		slhPRF(WOTS_SK_OFFSET, pkSeedPtr, skSeedPtr, SK_ADRS_OFFSET);
		adrsSetChainAddress(adrsPtr, <u32>i);
		wotsChain(outSigPtr + i * n, WOTS_SK_OFFSET, 0, m, pkSeedPtr, adrsPtr);
	}
}

// ── FIPS 205 §5 Algorithm 8, wots_pkFromSig ───────────────────────────────
// Recovers a candidate n-byte WOTS+ public key from a len·n-byte signature
// and an n-byte message. Result lands at outPkPtr; verifiers compare it
// against the expected wots_pkGen value.

export function wotsPkFromSig(
	outPkPtr:  i32,
	sigPtr:    i32,
	mPtr:      i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
): void {
	const n      = getParamN();
	const lenAll = len();
	const kp     = adrsGetKeyPairAddress(adrsPtr);

	// FIPS 205 lines 1-7: identical msg||csum preamble as wots_sign
	wotsMsgEncode(mPtr);

	// FIPS 205 lines 8-11: per chain, tmp[i] ← chain(sig[i], msg[i],
	// w−1−msg[i], PK.seed, ADRS). Reuses WOTS_TMP as the tmp[] buffer.
	for (let i = 0; i < lenAll; i++) {
		const m = <i32>load<u8>(WOTS_MSG_OFFSET + i);
		adrsSetChainAddress(adrsPtr, <u32>i);
		wotsChain(
			WOTS_TMP_OFFSET + i * n,
			sigPtr + i * n,
			m, W_MINUS_1 - m,
			pkSeedPtr, adrsPtr,
		);
	}

	// FIPS 205 lines 12-15: wotspkADRS ← ADRS; setTypeAndClear(WOTS_PK);
	// setKeyPairAddress(...); pk_sig ← T_len(PK.seed, wotspkADRS, tmp)
	adrsCopy(WOTSPK_ADRS_OFFSET, adrsPtr);
	adrsSetType(WOTSPK_ADRS_OFFSET, ADRS_WOTS_PK);
	adrsSetKeyPairAddress(WOTSPK_ADRS_OFFSET, kp);
	slhHashTl(outPkPtr, pkSeedPtr, WOTSPK_ADRS_OFFSET, WOTS_TMP_OFFSET, lenAll * n);
}

// ── Internal exports for the unit test bridge ──────────────────────────────
// These wrap the algorithms above 1:1 and are re-exported under `_test*`
// names in src/asm/slhdsa/index.ts. Consumers of the slhdsa surface have
// no use for them; they exist solely so test/unit/slhdsa/slhdsa-wots.test.ts
// can drive the algorithm-level functions in isolation.

export function _testBase2b(outPtr: i32, xPtr: i32, b: i32, outLen: i32): void {
	base2b(outPtr, xPtr, b, outLen);
}

export function _testWotsLen():  i32 { return len();  }
export function _testWotsLen1(): i32 { return len1(); }
