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
// src/ts/mldsa/types.ts
//
// ML-DSA type definitions: WASM export interfaces and signature API types.

export interface MlDsaExports {
	memory: WebAssembly.Memory
	// Buffer layout
	getModuleId:        () => number
	getMemoryPages:     () => number
	getPolySlotBase:    () => number
	getPolySlotSize:    () => number
	getPolySlot0:       () => number
	getPolySlot1:       () => number
	getPolySlot2:       () => number
	getPolySlot3:       () => number
	getPolySlot4:       () => number
	getPolySlot5:       () => number
	getPolySlot6:       () => number
	getPolySlot7:       () => number
	getMatrixSlot:      () => number
	getMatrixSlotSize:  () => number
	getPolyvecSlotBase: () => number
	getPolyvecSlotSize: () => number
	getPolyvecSlot0:    () => number
	getPolyvecSlot1:    () => number
	getPolyvecSlot2:    () => number
	getPolyvecSlot3:    () => number
	getPolyvecSlot4:    () => number
	getPolyvecSlot5:    () => number
	getPolyvecSlot6:    () => number
	getPolyvecSlot7:    () => number
	getSeedOffset:      () => number
	getTrOffset:        () => number
	getMsgRepOffset:    () => number
	getCTildeOffset:    () => number
	getPkOffset:        () => number
	getSkOffset:        () => number
	getSigOffset:       () => number
	getXofPrfOffset:    () => number
	wipeBuffers:        () => void
	// Reduction
	montgomery_reduce: (a: bigint) => number
	barrett_reduce:    (a: number) => number
	fqmul:             (a: number, b: number) => number
	// NTT
	getZetasOffset: () => number
	getZeta:        (i: number) => number
	BitRev8:        (m: number) => number
	ntt:            (polyOff: number) => void
	invntt:         (polyOff: number) => void
	// Polynomial arithmetic
	poly_add:                  (rOff: number, aOff: number, bOff: number) => void
	poly_sub:                  (rOff: number, aOff: number, bOff: number) => void
	poly_reduce:               (polyOff: number) => void
	poly_caddq:                (polyOff: number) => void
	poly_pointwise_montgomery: (rOff: number, aOff: number, bOff: number) => void
	poly_freeze:               (polyOff: number) => void
	poly_chknorm:              (polyOff: number, bound: number) => number
	poly_tomont:               (polyOff: number) => void
	// Encoding
	simple_bit_pack:    (rByteOff: number, polyOff: number, bitlen: number) => void
	bit_pack:           (rByteOff: number, polyOff: number, a: number, b: number) => void
	simple_bit_unpack:  (polyOff: number, vByteOff: number, bitlen: number) => void
	bit_unpack:         (polyOff: number, vByteOff: number, a: number, b: number) => void
	hint_bit_pack:      (rByteOff: number, hPvOff: number, k: number, omega: number) => void
	hint_bit_unpack:    (hPvOff: number, vByteOff: number, k: number, omega: number) => number
	// Rounding
	power2round:  (r1Off: number, r0Off: number, aOff: number) => void
	decompose:    (r1Off: number, r0Off: number, aOff: number, gamma2: number) => void
	highbits:     (rOff: number, aOff: number, gamma2: number) => void
	lowbits:      (rOff: number, aOff: number, gamma2: number) => void
	make_hint:    (hOff: number, zOff: number, rOff: number, gamma2: number) => void
	use_hint:     (rOff: number, hOff: number, aOff: number, gamma2: number) => void
	// Polyvec
	polyvec_add:                          (rOff: number, aOff: number, bOff: number, len: number) => void
	polyvec_sub:                          (rOff: number, aOff: number, bOff: number, len: number) => void
	polyvec_reduce:                       (pvOff: number, len: number) => void
	polyvec_caddq:                        (pvOff: number, len: number) => void
	polyvec_freeze:                       (pvOff: number, len: number) => void
	polyvec_tomont:                       (pvOff: number, len: number) => void
	polyvec_ntt:                          (pvOff: number, len: number) => void
	polyvec_invntt:                       (pvOff: number, len: number) => void
	polyvec_pointwise_montgomery:         (rOff: number, aOff: number, bOff: number, len: number) => void
	polyvec_pointwise_acc_montgomery:     (rPolyOff: number, aPvOff: number, bPvOff: number, len: number) => void
	polyvec_matrix_pointwise_montgomery:  (rPvOff: number, matOff: number, vPvOff: number, k: number, l: number) => void
	polyvec_chknorm:                      (pvOff: number, bound: number, len: number) => number
	polyvec_power2round:                  (r1pvOff: number, r0pvOff: number, aPvOff: number, len: number) => void
	polyvec_decompose:                    (r1pvOff: number, r0pvOff: number, aPvOff: number, len: number, gamma2: number) => void
	polyvec_highbits:                     (rPvOff: number, aPvOff: number, len: number, gamma2: number) => void
	polyvec_lowbits:                      (rPvOff: number, aPvOff: number, len: number, gamma2: number) => void
	polyvec_make_hint:                    (hPvOff: number, zPvOff: number, rPvOff: number, len: number, gamma2: number) => number
	polyvec_use_hint:                     (rPvOff: number, hPvOff: number, aPvOff: number, len: number, gamma2: number) => void
	// Sampling
	rej_ntt_poly:      (polyOff: number, ctrStart: number, bufOff: number, bufLen: number) => number
	rej_bounded_poly:  (polyOff: number, ctrStart: number, bufOff: number, bufLen: number, eta: number) => number
	sample_in_ball:    (polyOff: number, signsOff: number, posBytesOff: number, posBytesLen: number, tau: number, startI: number) => number
}

// Sha3Exports, re-exported from kyber/types.ts. Both modules consume the
// same SHA3 WASM ABI; duplication of the interface declaration would let the
// two drift independently.
export type { Sha3Exports } from '../kyber/types.js';

/** ML-DSA key pair returned by keygen / keygenDerand. */
export interface MlDsaKeyPair {
	verificationKey: Uint8Array  // pk, FIPS 204 Algorithm 22 (pkEncode)
	signingKey:      Uint8Array  // sk, FIPS 204 Algorithm 24 (skEncode)
}
