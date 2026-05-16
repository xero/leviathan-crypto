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
// src/ts/x25519/index.ts
//
// X25519 public API. RFC 7748 §5 (algorithm), §6 (keygen + DH), §7
// (security considerations and the small-order peer-pk rejection that
// motivates the TS-layer all-zero shared-secret check).
//
// Both Ed25519 and X25519 share the curve25519 WASM module;
// `ed25519Init(source)` and `x25519Init(source)` both target it and the
// init() layer de-dupes when given identical sources.
//
// Per-call lifecycle mirrors the Ed25519 wrapper: stage caller inputs
// at fixed offsets above the WASM mutable buffer region, call the
// underlying export, copy outputs to fresh `Uint8Array`s, wipe both
// the WASM-internal scratch and the TS-side I/O staging region.

import { getInstance, initModule, isInitialized, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import { randomBytes, wipe } from '../utils.js';
import { KeyAgreementError } from '../errors.js';
import type { X25519Exports, X25519KeyPair } from './types.js';
import { validateSecretKey, validatePublicKey } from './validate.js';

/**
 * Initialise the curve25519 WASM module under the `x25519` alias.
 * Equivalent to `ed25519Init(source)`; both target the same WASM module
 * and the init layer de-dupes when given identical sources.
 */
export async function x25519Init(source: WasmSource): Promise<void> {
	return initModule('curve25519', source);
}

export type { WasmSource };
export type { X25519KeyPair, X25519Exports } from './types.js';
export { isInitialized };

// ── I/O staging layout ─────────────────────────────────────────────────────
//
// Same base as the ed25519 wrapper, fixed offsets above the WASM mutable
// buffer region (BUFFER_END = 7836). Two 32-byte input slots plus one
// 32-byte output slot, no large variable region.

const IO_BASE       = 8192;
const SK_STAGE      = IO_BASE;         // 32 bytes
const PK_STAGE      = IO_BASE + 32;    // 32 bytes
const PEER_STAGE    = IO_BASE + 64;    // 32 bytes
const SHARED_STAGE  = IO_BASE + 96;    // 32 bytes

function ioWipe(mx: X25519Exports): void {
	// Zero the entire TS-managed staging region. wipeBuffers covers
	// MUTABLE_START..BUFFER_END only; the I/O slots above must be
	// scrubbed at the wrapper layer.
	new Uint8Array(mx.memory.buffer).fill(0, IO_BASE, mx.memory.buffer.byteLength);
}

export class X25519 {
	constructor() {
		if (!isInitialized('curve25519'))
			throw new Error('leviathan-crypto: call init({ x25519: ... }) before using X25519');
	}

	private get mx(): X25519Exports {
		return getInstance('curve25519').exports as unknown as X25519Exports;
	}

	/**
	 * Deterministic X25519 key generation from a 32-byte secret per
	 * RFC 7748 §6. Clamping is applied internally on every WASM call;
	 * the returned secretKey is a fresh copy of the supplied sk bytes
	 * (NOT pre-clamped).
	 */
	keygenDerand(sk: Uint8Array): X25519KeyPair {
		_assertNotOwned('curve25519');
		validateSecretKey(sk);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(sk, SK_STAGE);
		try {
			mx.x25519Keygen(SK_STAGE, PK_STAGE);
			const publicKey = mem.slice(PK_STAGE, PK_STAGE + 32);
			const secretKey = new Uint8Array(32);
			secretKey.set(sk);
			return { publicKey, secretKey };
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	/** Random X25519 key generation, wraps `keygenDerand` with `randomBytes(32)`. */
	keygen(): X25519KeyPair {
		const sk = randomBytes(32);
		try {
			return this.keygenDerand(sk);
		} finally {
			wipe(sk);
		}
	}

	/**
	 * X25519 Diffie-Hellman, RFC 7748 §6.
	 *
	 * Computes the shared u-coordinate from the local secret and the
	 * peer's public key. If the resulting shared secret is all-zero
	 * (peer public key is a small-order point per RFC 7748 §7), throws
	 * `KeyAgreementError` rather than returning the degenerate value.
	 * The all-zero scan accumulates via OR across all 32 output bytes
	 * before comparing to zero, so the success path is constant-time;
	 * the throw branches off only after a known-bad outcome is observed.
	 *
	 * @param sk     32-byte local secret (NOT pre-clamped, clamped internally)
	 * @param peerPk 32-byte peer public key (u-coordinate)
	 * @returns 32-byte shared u-coordinate
	 * @throws KeyAgreementError on all-zero shared secret
	 */
	dh(sk: Uint8Array, peerPk: Uint8Array): Uint8Array {
		_assertNotOwned('curve25519');
		validateSecretKey(sk);
		validatePublicKey(peerPk);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(sk,     SK_STAGE);
		mem.set(peerPk, PEER_STAGE);
		try {
			mx.x25519DH(SK_STAGE, PEER_STAGE, SHARED_STAGE);
			const shared = mem.slice(SHARED_STAGE, SHARED_STAGE + 32);
			// Constant-time OR-accumulate scan, RFC 7748 §6.1
			// contributory-behaviour requirement. No early exit on the
			// first non-zero byte.
			let acc = 0;
			for (let i = 0; i < 32; i++) acc |= shared[i];
			if (acc === 0) {
				wipe(shared);
				throw new KeyAgreementError(
					'leviathan-crypto: X25519 shared secret is all-zero '
					+ '(peer public key is a small-order point)',
				);
			}
			return shared;
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	dispose(): void {
		try {
			this.mx.wipeBuffers();
			ioWipe(this.mx);
		} catch { /* idempotent */ }
	}
}
