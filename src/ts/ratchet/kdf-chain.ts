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
// src/ts/ratchet/kdf-chain.ts
//
// KDFChain — stateful symmetric ratchet chain step (spec §5.2, KDF_SCKA_CK).
// Each step derives a message key and advances the chain key via HKDF-SHA-256.

import { HKDF_SHA256 } from '../sha2/index.js';
import { isInitialized } from '../init.js';
import { wipe, concat, utf8ToBytes } from '../utils.js';

// Signal Double Ratchet §7.2 — chain step info string
const INFO_CHAIN_BYTES = utf8ToBytes('leviathan-ratchet-v1 Chain Step');

const ZERO_SALT = new Uint8Array(32);

export class KDFChain {
	private _ck:       Uint8Array;
	private _n:        number;
	private _disposed: boolean;

	constructor(ck: Uint8Array) {
		if (!isInitialized('sha2'))
			throw new Error('leviathan-crypto: call init({ sha2: ... }) before using KDFChain');
		if (ck.length !== 32)
			throw new RangeError('KDFChain: ck must be 32 bytes');
		this._ck       = ck.slice();
		this._n        = 0;
		this._disposed = false;
	}

	step(): Uint8Array {
		if (this._disposed)
			throw new Error('KDFChain: instance has been disposed');
		if (this._n >= Number.MAX_SAFE_INTEGER)
			throw new RangeError('KDFChain: counter exceeds maximum safe integer');

		const nextN = this._n + 1;

		// Encode counter as big-endian uint64 — two u32 calls, no BigInt
		const ctrBuf = new Uint8Array(8);
		const dv     = new DataView(ctrBuf.buffer);
		dv.setUint32(0, Math.floor(nextN / 0x100000000), false);
		dv.setUint32(4, nextN >>> 0, false);

		const info = concat(INFO_CHAIN_BYTES, ctrBuf);
		const h    = new HKDF_SHA256();
		try {
			const okm    = h.derive(this._ck, ZERO_SALT, info, 64);
			const nextCk = okm.slice(0, 32);
			const msgKey = okm.slice(32, 64);
			wipe(this._ck);
			this._ck = nextCk;
			this._n  = nextN;
			wipe(okm);
			return msgKey;
		} finally {
			h.dispose();
		}
	}

	// Returns both the message key and the post-step counter atomically.
	// Eliminates the two-step step() + .n read pattern and the off-by-one risk.
	stepWithCounter(): { key: Uint8Array; counter: number } {
		const key = this.step();
		return { key, counter: this._n };
	}

	get n(): number {
		return this._n;
	}

	dispose(): void {
		wipe(this._ck);
		this._disposed = true;
	}
}
