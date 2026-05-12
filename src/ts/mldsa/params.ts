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
// src/ts/mldsa/params.ts
//
// ML-DSA (FIPS 204) parameter sets, values from §4 Table 1 and Table 2.
//
// Sizes are derived per parameter set:
//   pk  = 32 + k · 32 · (bitlen(q-1) - d)       , Alg 22 pkEncode
//   sk  = 32 + 32 + 64 + 32·((ℓ+k)·bitlen(2η) + d·k) , Alg 24 skEncode
//   sig = λ/4 + ℓ·32·(1 + bitlen(γ₁ - 1)) + ω + k   , Alg 26 sigEncode
//
// β = τ · η is precomputed; it bounds ‖cs1‖∞ and ‖cs2‖∞.

export interface MlDsaParams {
	paramSet: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87'
	k:        number   // matrix rows
	l:        number   // matrix cols (ℓ)
	eta:      number   // noise parameter (η)
	tau:      number   // # of ±1 in challenge polynomial (τ)
	lambda:   number   // collision strength in bits (λ)
	gamma1:   number   // y coefficient range (mask)
	gamma2:   number   // low-order rounding modulus
	omega:    number   // max # of 1s in hint
	beta:     number   // = τ · η  (precomputed)
	pkBytes:  number
	skBytes:  number
	sigBytes: number
}

/** ML-DSA-44, FIPS 204 §4 Table 1 (NIST security category 2). */
export const MLDSA44: MlDsaParams = {
	paramSet: 'ML-DSA-44',
	k: 4, l: 4, eta: 2, tau: 39, lambda: 128,
	gamma1: 1 << 17, gamma2: ((8380417 - 1) / 88) | 0,
	omega: 80, beta: 39 * 2,
	pkBytes: 1312, skBytes: 2560, sigBytes: 2420,
};

/** ML-DSA-65, FIPS 204 §4 Table 1 (NIST security category 3). */
export const MLDSA65: MlDsaParams = {
	paramSet: 'ML-DSA-65',
	k: 6, l: 5, eta: 4, tau: 49, lambda: 192,
	gamma1: 1 << 19, gamma2: ((8380417 - 1) / 32) | 0,
	omega: 55, beta: 49 * 4,
	pkBytes: 1952, skBytes: 4032, sigBytes: 3309,
};

/** ML-DSA-87, FIPS 204 §4 Table 1 (NIST security category 5). */
export const MLDSA87: MlDsaParams = {
	paramSet: 'ML-DSA-87',
	k: 8, l: 7, eta: 2, tau: 60, lambda: 256,
	gamma1: 1 << 19, gamma2: ((8380417 - 1) / 32) | 0,
	omega: 75, beta: 60 * 2,
	pkBytes: 2592, skBytes: 4896, sigBytes: 4627,
};
