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
// src/ts/ed25519/types.ts
//
// Ed25519 type surface: the WASM export interface for the curve25519
// module (Ed25519-relevant subset) and the public key-pair shape returned
// by keygen / keygenDerand. RFC 8032 §5.1.

export interface Ed25519KeyPair {
	/** 32-byte verifying key, encoded per RFC 8032 §5.1.2 (compressed y || x sign). */
	publicKey: Uint8Array
	/** 32-byte secret seed, the RFC 8032 §5.1.5 input. */
	secretKey: Uint8Array
}

/**
 * The Ed25519-relevant subset of the curve25519 WASM exports.
 *
 * The curve25519 module is shared between Ed25519 and X25519; this
 * interface deliberately surfaces only the Ed25519 high-level entry
 * points plus the layout / wipe primitives. The X25519 wrapper consumes
 * a separate `X25519Exports` view over the same instance.
 */
export interface Ed25519Exports {
	memory:                          WebAssembly.Memory
	getModuleId:                     () => number
	getMemoryPages:                  () => number
	ed25519Keygen:                   (seedOff: number, pkOff: number) => void
	ed25519Sign:                     (seedOff: number, pkOff: number, msgOff: number, msgLen: number, sigOff: number) => void
	ed25519Verify:                   (pkOff: number, msgOff: number, msgLen: number, sigOff: number) => number
	ed25519SignPrehashed:            (seedOff: number, pkOff: number, digestOff: number, ctxOff: number, ctxLen: number, sigOff: number) => void
	ed25519VerifyPrehashed:          (pkOff: number, digestOff: number, ctxOff: number, ctxLen: number, sigOff: number) => number
	ed25519SignInternalPk:           (seedOff: number, msgOff: number, msgLen: number, sigOff: number) => void
	ed25519SignPrehashedInternalPk:  (seedOff: number, digestOff: number, ctxOff: number, ctxLen: number, sigOff: number) => void
	wipeBuffers:                     () => void
}
