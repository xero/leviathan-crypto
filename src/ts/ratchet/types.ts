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
// src/ts/ratchet/types.ts
//
// Shared types for the ratchet KDF construction.
// Re-exports MlKemLike so consumers import from one place.

// Re-export MlKemLike so consumers import from one place.
// MlKemLike is the structural interface already used in suite.ts.
export type { MlKemLike } from '../kyber/suite.js';

export interface RatchetInitResult {
	readonly nextRootKey:  Uint8Array  // 32 bytes
	readonly sendChainKey: Uint8Array  // 32 bytes
	readonly recvChainKey: Uint8Array  // 32 bytes
}

export interface KemEncapResult {
	readonly nextRootKey:  Uint8Array  // 32 bytes
	readonly sendChainKey: Uint8Array  // 32 bytes
	readonly recvChainKey: Uint8Array  // 32 bytes
	readonly kemCt:        Uint8Array  // ML-KEM ciphertext — transmit in-band
}

export interface KemDecapResult {
	readonly nextRootKey:  Uint8Array  // 32 bytes
	readonly sendChainKey: Uint8Array  // 32 bytes
	readonly recvChainKey: Uint8Array  // 32 bytes
}

export interface RatchetMessageHeader {
	readonly epoch:   number        // sender's epoch at seal time; starts 0, increments on ratchet step
	readonly counter: number        // KDFChain.n at seal time (post-step value, first message = 1)
	readonly pn?:     number        // previous chain length — present only on the first message of a new epoch
	readonly kemCt?:  Uint8Array    // ML-KEM ciphertext — present only on the first message of a new epoch (encap side)
}

// Transactional handle returned by SkippedKeyStore.resolve. Caller reads
// `key` to decrypt, then settles once via `commit()` on success or
// `rollback()` on auth failure. Double-settle throws. Accessing `key` after
// settling throws. A FinalizationRegistry wipes the key (best-effort) if
// the handle is GC'd without settling.
export interface ResolveHandle {
	readonly key: Uint8Array;
	commit(): void;
	rollback(): void;
}

export interface SkippedKeyStoreOpts {
	/** Max keys held in cache. Default 100. Must be >= maxSkipPerResolve. */
	maxCacheSize?: number;
	/** Max skip-ahead derivations per resolve() call. Default 50. */
	maxSkipPerResolve?: number;
	/** @deprecated use maxCacheSize + maxSkipPerResolve. If provided, sets both. */
	ceiling?: number;
}
