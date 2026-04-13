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
// src/ts/kyber/types.ts
//
// ML-KEM type definitions: WASM export interfaces and KEM API types.

// ── Kyber WASM exports ──────────────────────────────────────────────────────

export interface KyberExports {
	memory: WebAssembly.Memory
	// Buffer layout
	getModuleId: () => number
	getMemoryPages: () => number
	getPolySlotBase: () => number
	getPolySlotSize: () => number
	getPolySlot0: () => number
	getPolySlot1: () => number
	getPolySlot2: () => number
	getPolySlot3: () => number
	getPolySlot4: () => number
	getPolySlot5: () => number
	getPolySlot6: () => number
	getPolySlot7: () => number
	getPolySlot8: () => number
	getPolySlot9: () => number
	getPolyvecSlotBase: () => number
	getPolyvecSlotSize: () => number
	getPolyvecSlot0: () => number
	getPolyvecSlot1: () => number
	getPolyvecSlot2: () => number
	getPolyvecSlot3: () => number
	getPolyvecSlot4: () => number
	getPolyvecSlot5: () => number
	getPolyvecSlot6: () => number
	getPolyvecSlot7: () => number
	getSeedOffset: () => number
	getMsgOffset: () => number
	getPkOffset: () => number
	getSkOffset: () => number
	getCtOffset: () => number
	getCtPrimeOffset: () => number
	getXofPrfOffset: () => number
	wipeBuffers: () => void
	// Arithmetic
	montgomery_reduce: (a: number) => number
	barrett_reduce: (a: number) => number
	fqmul: (a: number, b: number) => number
	// NTT
	getZetasOffset: () => number
	getZeta: (i: number) => number
	ntt: (polyOffset: number) => void
	invntt: (polyOffset: number) => void
	basemul: (rOffset: number, aOffset: number, bOffset: number, zetaIdx: number) => void
	// Polynomial
	poly_tobytes: (rOffset: number, polyOffset: number) => void
	poly_frombytes: (polyOffset: number, aOffset: number) => void
	poly_compress: (rOffset: number, polyOffset: number, dv: number) => void
	poly_decompress: (polyOffset: number, aOffset: number, dv: number) => void
	poly_frommsg: (polyOffset: number, msgOffset: number) => void
	poly_tomsg: (msgOffset: number, polyOffset: number) => void
	poly_add: (rOffset: number, aOffset: number, bOffset: number) => void
	poly_sub: (rOffset: number, aOffset: number, bOffset: number) => void
	poly_reduce: (polyOffset: number) => void
	poly_tomont: (polyOffset: number) => void
	poly_ntt: (polyOffset: number) => void
	poly_invntt: (polyOffset: number) => void
	poly_basemul_montgomery: (rOffset: number, aOffset: number, bOffset: number) => void
	poly_getnoise: (polyOffset: number, bufOffset: number, eta: number) => void
	// Polyvec
	polyvec_tobytes: (rOffset: number, pvOffset: number, k: number) => void
	polyvec_frombytes: (pvOffset: number, aOffset: number, k: number) => void
	polyvec_compress: (rOffset: number, pvOffset: number, k: number, du: number) => void
	polyvec_decompress: (pvOffset: number, aOffset: number, k: number, du: number) => void
	polyvec_ntt: (pvOffset: number, k: number) => void
	polyvec_invntt: (pvOffset: number, k: number) => void
	polyvec_reduce: (pvOffset: number, k: number) => void
	polyvec_add: (rOffset: number, aOffset: number, bOffset: number, k: number) => void
	polyvec_basemul_acc_montgomery: (rOffset: number, aOffset: number, bOffset: number, k: number) => void
	polyvec_modulus_check: (pvOffset: number, k: number) => number
	// Sampling
	rej_uniform: (polyOffset: number, ctrStart: number, bufOffset: number, buflen: number) => number
	// Constant-time
	ct_verify: (aOffset: number, bOffset: number, len: number) => number
	ct_cmov: (rOffset: number, xOffset: number, len: number, b: number) => void
}

// ── SHA3 WASM exports ───────────────────────────────────────────────────────

export interface Sha3Exports {
	memory:            WebAssembly.Memory
	getInputOffset:    () => number
	getOutOffset:      () => number
	getStateOffset:    () => number
	sha3_224Init:      () => void
	sha3_256Init:      () => void
	sha3_384Init:      () => void
	sha3_512Init:      () => void
	shake128Init:      () => void
	shake256Init:      () => void
	keccakAbsorb:      (len: number) => void
	sha3_224Final:     () => void
	sha3_256Final:     () => void
	sha3_384Final:     () => void
	sha3_512Final:     () => void
	shakeFinal:        (outLen: number) => void
	shakePad:          () => void
	shakeSqueezeBlock: () => void
	wipeBuffers:       () => void
}

// ── KEM API types ───────────────────────────────────────────────────────────

export interface KyberKeyPair {
	encapsulationKey: Uint8Array // ek
	decapsulationKey: Uint8Array // dk
}

export interface KyberEncapsulation {
	ciphertext:   Uint8Array // c
	sharedSecret: Uint8Array // K (32 bytes)
}
