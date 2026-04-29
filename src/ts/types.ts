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
// src/ts/types.ts
//
// Primitive interfaces for leviathan-crypto.
// No init() dependency — available at import time.

export interface Hash {
	hash(msg: Uint8Array): Uint8Array;
	dispose(): void;
}

export interface KeyedHash {
	hash(key: Uint8Array, msg: Uint8Array): Uint8Array;
	dispose(): void;
}

export interface Blockcipher {
	encrypt(block: Uint8Array): Uint8Array;
	decrypt(block: Uint8Array): Uint8Array;
	dispose(): void;
}

export interface Streamcipher {
	encrypt(msg: Uint8Array): Uint8Array;
	decrypt(msg: Uint8Array): Uint8Array;
	dispose(): void;
}

export interface AEAD {
	encrypt(msg: Uint8Array, aad?: Uint8Array): Uint8Array;
	/** Decrypt and authenticate. Throws `Error` on authentication failure — never returns null. */
	decrypt(ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array;
	dispose(): void;
}

/**
 * Stateless cipher PRF for Fortuna's generator slot. Produces `n` bytes of
 * keystream from `(key, counter)` without mutating either input. Implementations
 * are plain const objects, not classes.
 */
export interface Generator {
	readonly keySize: number;       // bytes
	readonly blockSize: number;     // bytes per cipher block
	readonly counterSize: number;   // bytes — Fortuna allocates genCnt of this size
	readonly wasmModules: readonly string[];
	generate(key: Uint8Array, counter: Uint8Array, n: number): Uint8Array;
}

/**
 * Stateless hash function for Fortuna's accumulator and reseed slots. Output
 * size must match the generator's key size when paired in Fortuna.
 */
export interface HashFn {
	readonly outputSize: number;    // bytes
	readonly wasmModules: readonly string[];
	digest(msg: Uint8Array): Uint8Array;
}
