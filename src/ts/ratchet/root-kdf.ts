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
// src/ts/ratchet/root-kdf.ts
//
// Root KDF functions for the Sparse Post-Quantum Ratchet (spec §7.2).
// Implements KDF_SCKA_INIT (ratchetInit) and KDF_SCKA_RK (kemRatchetEncap/Decap).

import { HKDF_SHA256 } from '../sha2/index.js';
import { isInitialized } from '../init.js';
import { wipe, concat, utf8ToBytes } from '../utils.js';
import type { MlKemLike, RatchetInitResult, KemEncapResult, KemDecapResult } from './types.js';

// Signal Double Ratchet §7.2 — info strings
const INFO_INIT = utf8ToBytes('leviathan-ratchet-v1 Chain Start');
const INFO_ROOT = utf8ToBytes('leviathan-ratchet-v1 Chain Add Epoch');
// INFO_CHAIN ('leviathan-ratchet-v1 Chain Step') is used in kdf-chain.ts

const ZERO_SALT = new Uint8Array(32);

// HKDF-SHA-256 root step (KDF_SCKA_INIT and KDF_SCKA_RK share this shape).
// ikm    = 32-byte secret (shared secret or sk)
// salt   = 32-byte salt (zero bytes for init, rk for KEM ratchet)
// info   = protocol info bytes
// length = 96
// → { nextRootKey: [0:32], sendChainKey: [32:64], recvChainKey: [64:96] }
// Wipes okm after slicing.
function kdfRoot(
	secret: Uint8Array,
	salt:   Uint8Array,
	info:   Uint8Array,
): { nextRootKey: Uint8Array; sendChainKey: Uint8Array; recvChainKey: Uint8Array } {
	const h = new HKDF_SHA256();
	try {
		const okm          = h.derive(secret, salt, info, 96);
		const nextRootKey  = okm.slice(0, 32);
		const sendChainKey = okm.slice(32, 64);
		const recvChainKey = okm.slice(64, 96);
		wipe(okm);
		return { nextRootKey, sendChainKey, recvChainKey };
	} finally {
		h.dispose();
	}
}

// u32 big-endian length prefix — same convention as serpent/cipher-suite.ts AAD encoding.
function u32be(n: number): Uint8Array {
	if (!Number.isInteger(n) || n < 0 || n > 0xFFFFFFFF)
		throw new RangeError(`u32be: n must be an integer in [0, 0xFFFFFFFF] (got ${n})`);
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n, false);
	return b;
}

// KEM ratchet info — binds peerEk, kemCt, and context with u32be length prefixes.
// Defense-in-depth: the HKDF output is tied to the exact (peerEk, kemCt, context)
// tuple used, not just the KEM shared secret. An attacker who substitutes any of
// these inputs derives a different chain key trio, regardless of the KEM transcript.
function buildRootInfo(peerEk: Uint8Array, kemCt: Uint8Array, context?: Uint8Array): Uint8Array {
	const ctxBytes = context ?? new Uint8Array(0);
	return concat(
		INFO_ROOT,
		u32be(peerEk.length), peerEk,
		u32be(kemCt.length),  kemCt,
		u32be(ctxBytes.length), ctxBytes,
	);
}

// KDF_SCKA_INIT — spec §7.2
// Derives initial root key, send chain key, and receive chain key from a
// shared secret sk. Optional context bytes are appended to the info string.
export function ratchetInit(sk: Uint8Array, context?: Uint8Array): RatchetInitResult {
	if (!isInitialized('sha2'))
		throw new Error('leviathan-crypto: call init({ sha2: ... }) before using ratchetInit');
	if (sk.length !== 32)
		throw new RangeError('ratchetInit: sk must be 32 bytes');

	const info = context != null && context.length > 0 ? concat(INFO_INIT, context) : INFO_INIT;
	const { nextRootKey, sendChainKey, recvChainKey } = kdfRoot(sk, ZERO_SALT, info);

	return { nextRootKey, sendChainKey, recvChainKey };
}

// KDF_SCKA_RK — encapsulation side (spec §7.2)
// Generates a fresh KEM ciphertext, derives next epoch keys from the shared secret.
// `peerEk` and `kemCt` are bound into the HKDF info string (defense-in-depth).
export function kemRatchetEncap(
	kem:      MlKemLike,
	rk:       Uint8Array,
	peerEk:   Uint8Array,
	context?: Uint8Array,
): KemEncapResult {
	if (!isInitialized('sha2'))
		throw new Error('leviathan-crypto: call init({ sha2: ... }) before using kemRatchetEncap');
	if (rk.length !== 32)
		throw new RangeError('kemRatchetEncap: rk must be 32 bytes');

	const { ciphertext: kemCt, sharedSecret } = kem.encapsulate(peerEk);
	const info = buildRootInfo(peerEk, kemCt, context);
	try {
		const { nextRootKey, sendChainKey, recvChainKey } = kdfRoot(sharedSecret, rk, info);
		return { nextRootKey, sendChainKey, recvChainKey, kemCt };
	} finally {
		wipe(sharedSecret);
	}
}

// KDF_SCKA_RK — decapsulation side (spec §7.2)
// Recovers the shared secret from the KEM ciphertext, derives next epoch keys.
// The chain key slots are swapped relative to the encap side: what the KDF
// labels 'sendChainKey' (A→B direction) becomes the decap side's recvChainKey,
// and vice versa — Alice's send IS Bob's receive.
//
// `ownEk` is the local party's encapsulation key (the same public key the
// encap side targeted as `peerEk`). It must be passed explicitly so both
// sides bind the identical (peerEk, kemCt) pair into the HKDF info string.
export function kemRatchetDecap(
	kem:      MlKemLike,
	rk:       Uint8Array,
	dk:       Uint8Array,
	kemCt:    Uint8Array,
	ownEk:    Uint8Array,
	context?: Uint8Array,
): KemDecapResult {
	if (!isInitialized('sha2'))
		throw new Error('leviathan-crypto: call init({ sha2: ... }) before using kemRatchetDecap');
	if (rk.length !== 32)
		throw new RangeError('kemRatchetDecap: rk must be 32 bytes');

	const sharedSecret = kem.decapsulate(dk, kemCt);
	const info = buildRootInfo(ownEk, kemCt, context);
	try {
		const { nextRootKey, sendChainKey: recvChainKey, recvChainKey: sendChainKey } = kdfRoot(sharedSecret, rk, info);
		return { nextRootKey, sendChainKey, recvChainKey };
	} finally {
		wipe(sharedSecret);
	}
}
