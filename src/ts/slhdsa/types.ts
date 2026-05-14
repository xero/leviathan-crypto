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
// src/ts/slhdsa/types.ts
//
// SLH-DSA type definitions: WASM export interface (substrate surface), the
// top-level keygen/sign/verify entry points, and the public TS types
// (SlhDsaKeyPair, SlhDsaTestExports).

/** SLH-DSA WASM exports. Mirrors the AssemblyScript surface in
 *  `src/asm/slhdsa/index.ts`. The consumer-facing TS surface (SlhDsaBase and
 *  its subclasses) calls slhKeygenInternal / slhSignInternal /
 *  slhVerifyInternal directly; the lower-level hash family + ADRS helpers
 *  are exported so the unit suite can drive each primitive layer in
 *  isolation. */
export interface SlhDsaExports {
	memory: WebAssembly.Memory

	// Buffer layout
	getModuleId:       () => number
	getMemoryPages:    () => number
	getInputOffset:    () => number
	getOutOffset:      () => number
	getStateOffset:    () => number
	getScratchOffset:  () => number
	getAdrsOffset:     () => number
	getParamsOffset:   () => number
	getParamN:         () => number
	getParamM:         () => number
	getParamSet:       () => number

	// Parameter-set selectors (FIPS 205 §11.1 Table 2)
	slhSetParams128f:  () => void
	slhSetParams192f:  () => void
	slhSetParams256f:  () => void

	// Buffer hygiene
	wipeBuffers:       () => void

	// ADRS (FIPS 205 §4.2)
	adrsClear:              (adrs: number) => void
	adrsCopy:               (dst: number, src: number) => void
	adrsSetLayerAddress:    (adrs: number, layer: number) => void
	adrsGetLayerAddress:    (adrs: number) => number
	adrsSetTreeAddr:        (adrs: number, hi: number, mid: number, lo: number) => void
	adrsGetTreeHi:          (adrs: number) => number
	adrsGetTreeMid:         (adrs: number) => number
	adrsGetTreeLo:          (adrs: number) => number
	adrsSetType:            (adrs: number, typ: number) => void
	adrsGetType:            (adrs: number) => number
	adrsSetKeyPairAddress:  (adrs: number, kp: number) => void
	adrsGetKeyPairAddress:  (adrs: number) => number
	adrsSetChainAddress:    (adrs: number, chain: number) => void
	adrsGetChainAddress:    (adrs: number) => number
	adrsSetHashAddress:     (adrs: number, h: number) => void
	adrsGetHashAddress:     (adrs: number) => number
	adrsSetTreeHeight:      (adrs: number, height: number) => void
	adrsGetTreeHeight:      (adrs: number) => number
	adrsSetTreeIndex:       (adrs: number, index: number) => void
	adrsGetTreeIndex:       (adrs: number) => number

	// ADRS type constants
	ADRS_WOTS_HASH:    { value: number }
	ADRS_WOTS_PK:      { value: number }
	ADRS_TREE:         { value: number }
	ADRS_FORS_TREE:    { value: number }
	ADRS_FORS_ROOTS:   { value: number }
	ADRS_WOTS_PRF:     { value: number }
	ADRS_FORS_PRF:     { value: number }
	ADRS_BYTES:        { value: number }

	// Hash family (FIPS 205 §11.2)
	slhHashF:    (out: number, pkSeed: number, adrs: number, m1: number) => void
	slhHashH:    (out: number, pkSeed: number, adrs: number, m2: number) => void
	slhHashTl:   (out: number, pkSeed: number, adrs: number, m: number, mLen: number) => void
	slhPRF:      (out: number, pkSeed: number, skSeed: number, adrs: number) => void
	slhPRFmsg:   (out: number, prf: number, optRand: number, m: number, mLen: number) => void
	slhHmsg:     (out: number, r: number, pkSeed: number, pkRoot: number, m: number, mLen: number) => void
	slhShake256: (out: number, outLen: number, in_: number, inLen: number) => void

	// Raw Keccak/SHAKE (parity with sha3.wasm; gate-test entry points)
	shake128Init:     () => void
	shake256Init:     () => void
	keccakAbsorb:     (len: number) => void
	keccakAbsorbAt:   (src: number, len: number) => void
	keccakSqueezeTo:  (dst: number, outLen: number) => void
	shakeFinal:       (outLen: number) => void

	// Top-level §9 internal functions (FIPS 205 Algorithms 18 / 19 / 20).
	// I/O byte layouts are documented in src/asm/slhdsa/slh.ts.
	slhKeygenInternal: () => void
	slhSignInternal:   (msgLen: number) => void
	slhVerifyInternal: (msgLen: number) => number
}

/** SLH-DSA key pair returned by keygen / keygenDerand. */
export interface SlhDsaKeyPair {
	verificationKey: Uint8Array  // pk, FIPS 205 §9 Algorithm 17 (pkEncode)
	signingKey:      Uint8Array  // sk, FIPS 205 §9 Algorithm 17 (skEncode)
}

/** SLH-DSA WASM internal test exports. NOT part of the consumer surface,
 *  NOT re-exported from src/ts/slhdsa/index.ts. Wired exclusively for the
 *  unit suite (slhdsa-wots / slhdsa-fors / slhdsa-xmss / slhdsa-hypertree
 *  tests) to drive each primitive layer in isolation.
 *
 *  Tests obtain these via test/unit/slhdsa/helpers.ts which casts the
 *  public SlhDsaExports to (SlhDsaExports & SlhDsaTestExports). The cast
 *  is contained inside the test helpers, so consumer code never sees
 *  the _test* surface. */
export interface SlhDsaTestExports {
	// WOTS+ (FIPS 205 §5 Algorithms 4-8)
	_testBase2b:        (out: number, x: number, b: number, outLen: number) => void
	_testWotsLen:       () => number
	_testWotsLen1:      () => number
	_testWotsTmpOffset: () => number
	_testWotsSkOffset:  () => number
	_testWotsMsgOffset: () => number
	_testWotsChain:     (out: number, x: number, i: number, s: number, pkSeed: number, adrs: number) => void
	_testWotsPkGen:     (outPk: number, skSeed: number, pkSeed: number, adrs: number) => void
	_testWotsSign:      (outSig: number, m: number, skSeed: number, pkSeed: number, adrs: number) => void
	_testWotsPkFromSig: (outPk: number, sig: number, m: number, pkSeed: number, adrs: number) => void

	// FORS (FIPS 205 §8 Algorithms 14-17)
	_testForsK:           () => number
	_testForsA:           () => number
	_testForsRootsOffset: () => number
	_testForsLeafOffset:  () => number
	_testForsPairBase:    () => number
	_testForsSkGen:       (out: number, skSeed: number, idx: number, pkSeed: number, adrs: number) => void
	_testForsNode:        (out: number, skSeed: number, i: number, z: number, pkSeed: number, adrs: number) => void
	_testForsSign:        (outSig: number, md: number, skSeed: number, pkSeed: number, adrs: number) => void
	_testForsPkFromSig:   (outPk: number, sig: number, md: number, pkSeed: number, adrs: number) => void

	// XMSS (FIPS 205 §6 Algorithms 9-11)
	_testXmssHPrime:    () => number
	_testXmssPairBase:  () => number
	_testXmssNode:      (out: number, skSeed: number, i: number, z: number, pkSeed: number, adrs: number) => void
	_testXmssSign:      (outSig: number, m: number, skSeed: number, idx: number, pkSeed: number, adrs: number) => void
	_testXmssPkFromSig: (outRoot: number, idx: number, sig: number, m: number, pkSeed: number, adrs: number) => void

	// Hypertree (FIPS 205 §7 Algorithms 12-13)
	_testHtD:          () => number
	_testHtHPrime:     () => number
	_testHtRootOffset: () => number
	_testHtSign:       (outSig: number, m: number, skSeed: number, pkSeed: number,
	                    idxTreeHi: number, idxTreeLo: number, idxLeaf: number, adrs: number) => void
	_testHtVerify:     (m: number, sig: number, pkSeed: number,
	                    idxTreeHi: number, idxTreeLo: number, idxLeaf: number,
	                    pkRoot: number, adrs: number) => number
}
