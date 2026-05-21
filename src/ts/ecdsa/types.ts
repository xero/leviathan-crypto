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
// src/ts/ecdsa/types.ts
//
// ECDSA-P256 type surface: the WASM export interface for the p256
// module and the public key-pair shape returned by keygen /
// keygenDerand. FIPS 186-5 §6, ECDSA and SP 800-186 §3.2.1.3, P-256
// parameters.

export interface EcdsaP256KeyPair {
	/** 33-byte compressed public key per SEC 1 §2.3.3, 0x02 / 0x03 || x. */
	publicKey: Uint8Array
	/** 32-byte secret scalar d ∈ [1, n-1] per FIPS 186-5 §6.2.1, private-key generation. */
	secretKey: Uint8Array
}

/**
 * The ECDSA-P256-relevant subset of the p256 WASM exports.
 *
 * The p256 module hosts the full elliptic-curve substrate (field,
 * scalar, point, RFC 6979 K derivation, embedded SHA-256 + HMAC) and
 * the four high-level ECDSA entry points (keygen, sign, signInternalPk,
 * verify). The wrapper additionally drives `pointDecompress` + `feToBytes`
 * for the SEC 1 §2.3.4 uncompressed-pk emission path; those two
 * substrate exports are public because no high-level ABI covers
 * "given a compressed pk, return its uncompressed form" without
 * round-tripping through verify. Substrate test hooks live outside
 * the consumer-facing ABI.
 */
export interface EcdsaP256Exports {
	memory:              WebAssembly.Memory
	getModuleId:         () => number
	getMemoryPages:      () => number
	feToBytes:           (outOff: number, feOff: number) => void
	pointDecompress:     (outOff: number, srcOff: number) => number
	ecdsaKeygen:         (seedOff: number, pkOff: number) => void
	ecdsaSign:           (skOff: number, pkOff: number, msgHashOff: number, rndOff: number, sigOff: number) => void
	ecdsaSignInternalPk: (skOff: number, msgHashOff: number, rndOff: number, sigOff: number) => void
	ecdsaVerify:         (pkOff: number, msgHashOff: number, sigOff: number) => number
	wipeBuffers:         () => void
}
