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
// src/ts/kyber/params.ts
//
// ML-KEM (FIPS 203) parameter set configurations.
// FIPS 203 Table 2 — Parameter sets for ML-KEM.

export interface KyberParams {
	k: number          // matrix dimension
	eta1: number       // noise parameter for keygen/encrypt r
	eta2: number       // noise parameter for encrypt e1/e2
	du: number         // polyvec compression bits
	dv: number         // poly compression bits
	ekBytes: number    // encapsulation key byte length
	dkBytes: number    // decapsulation key byte length
	ctBytes: number    // ciphertext byte length
	skCpaBytes: number // IND-CPA secret key bytes = k * 384
}

export const MLKEM512: KyberParams = {
	k: 2, eta1: 3, eta2: 2, du: 10, dv: 4,
	ekBytes: 800, dkBytes: 1632, ctBytes: 768, skCpaBytes: 768,
};

export const MLKEM768: KyberParams = {
	k: 3, eta1: 2, eta2: 2, du: 10, dv: 4,
	ekBytes: 1184, dkBytes: 2400, ctBytes: 1088, skCpaBytes: 1152,
};

export const MLKEM1024: KyberParams = {
	k: 4, eta1: 2, eta2: 2, du: 11, dv: 5,
	ekBytes: 1568, dkBytes: 3168, ctBytes: 1568, skCpaBytes: 1536,
};
