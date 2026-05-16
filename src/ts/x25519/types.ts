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
// src/ts/x25519/types.ts
//
// X25519 type surface: the WASM export interface for the curve25519
// module (X25519-relevant subset) and the public key-pair shape returned
// by keygen / keygenDerand. RFC 7748 §5 / §6.

export interface X25519KeyPair {
	/** 32-byte public u-coordinate. */
	publicKey: Uint8Array
	/**
	 * 32-byte secret. Per RFC 7748 §5 / §6 this is "any 32 random bytes";
	 * clamping is applied internally on every WASM call. The stored
	 * secretKey is the unclamped form so that round-tripping through
	 * keygen / external storage preserves byte-equality.
	 */
	secretKey: Uint8Array
}

/**
 * The X25519-relevant subset of the curve25519 WASM exports. The
 * curve25519 module is shared between Ed25519 and X25519; this interface
 * deliberately surfaces only the X25519 high-level entry points plus the
 * layout / wipe primitives.
 */
export interface X25519Exports {
	memory:          WebAssembly.Memory
	getModuleId:     () => number
	getMemoryPages:  () => number
	x25519Keygen:    (skOff: number, pkOff: number) => void
	x25519DH:        (skOff: number, peerPkOff: number, sharedOff: number) => void
	wipeBuffers:     () => void
}
