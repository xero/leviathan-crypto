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
// src/ts/ratchet/ratchet-keypair.ts
//
// RatchetKeypair — single-use ek/dk lifecycle for one KEM ratchet step.
// Enforces the DR spec requirement that both parties rotate encapsulation
// keys after each KEM ratchet step.

import { wipe } from '../utils.js';
import { kemRatchetDecap } from './root-kdf.js';
import type { MlKemLike, KemDecapResult } from './types.js';

export class RatchetKeypair {
	readonly ek: Uint8Array;
	private _dk:   Uint8Array;
	private _used: boolean;

	constructor(kem: MlKemLike) {
		const { encapsulationKey, decapsulationKey } = kem.keygen();
		this.ek   = encapsulationKey;
		this._dk  = decapsulationKey;
		this._used = false;
	}

	// Decapsulate using the stored dk. May only be called once per instance.
	// Wipes the dk immediately after decap — the dk never leaves this class.
	// The stored ek is passed as `ownEk` so both sides bind the identical
	// (peerEk, kemCt) pair into the HKDF info string.
	decap(kem: MlKemLike, rk: Uint8Array, kemCt: Uint8Array, context?: Uint8Array): KemDecapResult {
		if (this._used)
			throw new Error('RatchetKeypair: already consumed or disposed. generate a new keypair for the next ratchet step');
		this._used = true;
		try {
			return kemRatchetDecap(kem, rk, this._dk, kemCt, this.ek, context);
		} finally {
			wipe(this._dk);
		}
	}

	// Wipe the dk if not already wiped by decap. Idempotent.
	dispose(): void {
		if (!this._used) {
			wipe(this._dk);
			this._used = true;
		}
	}
}
