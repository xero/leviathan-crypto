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
// src/asm/slhdsa/index.ts
//
// SLH-DSA WASM module, public exports.
// FIPS 205, Stateless Hash-Based Digital Signature Standard.
//
// Substrate surface: buffer offsets, parameter-set selectors, embedded SHAKE
// gateway (slhShake256), tweakable hash family (F/H/T_ℓ/PRF/PRFmsg/Hmsg),
// and ADRS encode/decode helpers.
//
// Primitive layers (test-export-only): WOTS+ (§5), FORS (§8), XMSS (§6), and
// hypertree (§7) are re-exported under `_test*` prefixes for the unit suite
// to drive each layer in isolation.
//
// Top-level entry points: slhKeygenInternal / slhSignInternal /
// slhVerifyInternal (FIPS 205 §9 Algorithms 18/19/20) compose the §5-§8
// primitives into the keygen / sign / verify operations consumed by the
// TS surface in `src/ts/slhdsa/`.

// ── Buffer layout + param-set selectors (buffers.ts) ───────────────────────

export {
	getModuleId, getMemoryPages,
	getInputOffset, getOutOffset, getStateOffset, getScratchOffset,
	getAdrsOffset, getParamsOffset,
	getParamN, getParamM, getParamSet,
	slhSetParams128f, slhSetParams192f, slhSetParams256f,
	wipeBuffers,
} from './buffers';

// ── ADRS struct (address.ts) ───────────────────────────────────────────────

export {
	ADRS_WOTS_HASH, ADRS_WOTS_PK, ADRS_TREE,
	ADRS_FORS_TREE, ADRS_FORS_ROOTS, ADRS_WOTS_PRF, ADRS_FORS_PRF,
	ADRS_BYTES,
	adrsClear, adrsCopy,
	adrsSetLayerAddress,   adrsGetLayerAddress,
	adrsSetTreeAddr,       adrsGetTreeHi, adrsGetTreeMid, adrsGetTreeLo,
	adrsSetType,           adrsGetType,
	adrsSetKeyPairAddress, adrsGetKeyPairAddress,
	adrsSetChainAddress,   adrsGetChainAddress,
	adrsSetHashAddress,    adrsGetHashAddress,
	adrsSetTreeHeight,     adrsGetTreeHeight,
	adrsSetTreeIndex,      adrsGetTreeIndex,
} from './address';

// ── Hash family (hashes.ts) ────────────────────────────────────────────────

export {
	slhHashF, slhHashH, slhHashTl,
	slhPRF, slhPRFmsg, slhHmsg,
	slhShake256,
} from './hashes';

// ── Raw Keccak / SHAKE primitives (keccak.ts) ──────────────────────────────
// Exposed for parity with sha3.wasm so substrate gate tests can drive SHAKE
// directly. Higher-level callers prefer the §11.2 hash family above.

export {
	shake128Init, shake256Init,
	keccakAbsorb, keccakAbsorbAt,
	keccakSqueezeTo, shakeFinal,
} from './keccak';

// ── Internal test-only WASM exports ────────────────────────────────────────
// `_test*` are unit-test fixtures, not consumer ABI.

import {
	wotsChain, wotsPkGen, wotsSign, wotsPkFromSig,
	WOTS_TMP_OFFSET, WOTS_SK_OFFSET, WOTS_MSG_OFFSET,
	_testBase2b, _testWotsLen, _testWotsLen1,
} from './wots';
import {
	forsSkGen, forsNode, forsSign, forsPkFromSig,
	FORS_ROOTS_OFFSET, FORS_LEAF_OFFSET, FORS_PAIR_BASE,
	_testForsK, _testForsA,
} from './fors';
import {
	xmssNode, xmssSign, xmssPkFromSig,
	XMSS_PAIR_BASE,
	_testXmssHPrime,
} from './xmss';
import {
	htSign, htVerify,
	HT_ROOT_OFFSET,
	_testHtD, _testHtHPrime,
} from './hypertree';

export function _testWotsChain(
	outPtr: i32, xPtr: i32, i: i32, s: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { wotsChain(outPtr, xPtr, i, s, pkSeedPtr, adrsPtr); }

export function _testWotsPkGen(
	outPkPtr: i32, skSeedPtr: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { wotsPkGen(outPkPtr, skSeedPtr, pkSeedPtr, adrsPtr); }

export function _testWotsSign(
	outSigPtr: i32, mPtr: i32, skSeedPtr: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { wotsSign(outSigPtr, mPtr, skSeedPtr, pkSeedPtr, adrsPtr); }

export function _testWotsPkFromSig(
	outPkPtr: i32, sigPtr: i32, mPtr: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { wotsPkFromSig(outPkPtr, sigPtr, mPtr, pkSeedPtr, adrsPtr); }

export function _testForsSkGen(
	outPtr: i32, skSeedPtr: i32, idx: u32, pkSeedPtr: i32, adrsPtr: i32,
): void { forsSkGen(outPtr, skSeedPtr, idx, pkSeedPtr, adrsPtr); }

export function _testForsNode(
	outPtr: i32, skSeedPtr: i32, i: u32, z: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { forsNode(outPtr, skSeedPtr, i, z, pkSeedPtr, adrsPtr); }

export function _testForsSign(
	outSigPtr: i32, mdPtr: i32, skSeedPtr: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { forsSign(outSigPtr, mdPtr, skSeedPtr, pkSeedPtr, adrsPtr); }

export function _testForsPkFromSig(
	outPkPtr: i32, sigPtr: i32, mdPtr: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { forsPkFromSig(outPkPtr, sigPtr, mdPtr, pkSeedPtr, adrsPtr); }

// Test fixture re-exports for base_2b and parameter-set dispatch lookups.
export {
	_testBase2b, _testWotsLen, _testWotsLen1,
	_testForsK, _testForsA,
	_testXmssHPrime,
	_testHtD, _testHtHPrime,
};

// Working-buffer offset getters so tests can introspect / scratch-poke.
export function _testWotsTmpOffset():  i32 { return WOTS_TMP_OFFSET;   }
export function _testWotsSkOffset():   i32 { return WOTS_SK_OFFSET;    }
export function _testWotsMsgOffset():  i32 { return WOTS_MSG_OFFSET;   }
export function _testForsRootsOffset(): i32 { return FORS_ROOTS_OFFSET; }
export function _testForsLeafOffset():  i32 { return FORS_LEAF_OFFSET;  }
export function _testForsPairBase():    i32 { return FORS_PAIR_BASE;    }
export function _testXmssPairBase():    i32 { return XMSS_PAIR_BASE;    }
export function _testHtRootOffset():    i32 { return HT_ROOT_OFFSET;    }

// ── XMSS (FIPS 205 §6 Algorithms 9-11) ─────────────────────────────────────

export function _testXmssNode(
	outPtr: i32, skSeedPtr: i32, i: u32, z: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { xmssNode(outPtr, skSeedPtr, i, z, pkSeedPtr, adrsPtr); }

export function _testXmssSign(
	outSigPtr: i32, mPtr: i32, skSeedPtr: i32, idx: u32, pkSeedPtr: i32, adrsPtr: i32,
): void { xmssSign(outSigPtr, mPtr, skSeedPtr, idx, pkSeedPtr, adrsPtr); }

export function _testXmssPkFromSig(
	outRootPtr: i32, idx: u32, sigPtr: i32, mPtr: i32, pkSeedPtr: i32, adrsPtr: i32,
): void { xmssPkFromSig(outRootPtr, idx, sigPtr, mPtr, pkSeedPtr, adrsPtr); }

// ── Hypertree (FIPS 205 §7 Algorithms 12-13) ───────────────────────────────

export function _testHtSign(
	outSigPtr: i32, mPtr: i32, skSeedPtr: i32, pkSeedPtr: i32,
	idxTreeHi: u32, idxTreeLo: u32, idxLeaf: u32, adrsPtr: i32,
): void {
	htSign(outSigPtr, mPtr, skSeedPtr, pkSeedPtr,
		idxTreeHi, idxTreeLo, idxLeaf, adrsPtr);
}

export function _testHtVerify(
	mPtr: i32, sigPtr: i32, pkSeedPtr: i32,
	idxTreeHi: u32, idxTreeLo: u32, idxLeaf: u32,
	pkRootPtr: i32, adrsPtr: i32,
): i32 {
	return htVerify(mPtr, sigPtr, pkSeedPtr,
		idxTreeHi, idxTreeLo, idxLeaf, pkRootPtr, adrsPtr);
}

// ── Top-level §9 internal functions (slh.ts) ───────────────────────────────
// Algorithms 18 / 19 / 20 from FIPS 205 §9. These are the consumer-facing
// algorithm entry points, called from the TS layer with INPUT bytes set up
// per the layout documented in slh.ts.

export {
	slhKeygenInternal,
	slhSignInternal,
	slhVerifyInternal,
} from './slh';
