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
// src/ts/serpent/seal.ts
//
// SerpentSeal — authenticated Serpent-256 encryption.
// Encrypt-then-MAC: SerpentCbc + HMAC-SHA256. Tier 2 pure-TS composition.

import { SerpentCbc, _serpentReady } from './index.js';
import { HMAC_SHA256, _sha2Ready } from '../sha2/index.js';
import { concat, constantTimeEqual } from '../utils.js';
import { AuthenticationError } from '../errors.js';
import { getInstance } from '../init.js';

function u32be(n: number): Uint8Array {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n, false);
	return b;
}

export class SerpentSeal {
	private readonly _cbc: SerpentCbc;
	private readonly _hmac: HMAC_SHA256;

	constructor() {
		if (!_serpentReady() || !_sha2Ready())
			throw new Error('leviathan-crypto: call init({ serpent: ..., sha2: ... }) before using SerpentSeal');
		this._cbc = new SerpentCbc({ dangerUnauthenticated: true });
		this._hmac = new HMAC_SHA256();
	}

	encrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
		if (key.length !== 64)
			throw new RangeError(`SerpentSeal key must be 64 bytes (got ${key.length})`);
		const aadBytes = aad ?? new Uint8Array(0);
		const encKey = key.subarray(0, 32);
		const macKey = key.subarray(32, 64);
		// eslint-disable-next-line prefer-rest-params
		const _iv = arguments[3] as Uint8Array | undefined;
		if (_iv !== undefined && _iv.length !== 16)
			throw new RangeError(`_iv must be 16 bytes (got ${_iv.length})`);
		const iv = _iv ?? new Uint8Array(16);
		if (!_iv) crypto.getRandomValues(iv);
		const ciphertext = this._cbc.encrypt(encKey, iv, plaintext);
		const tag = this._hmac.hash(macKey, concat(u32be(aadBytes.length), aadBytes, iv, ciphertext));
		return concat(iv, ciphertext, tag);
	}

	decrypt(key: Uint8Array, data: Uint8Array, aad?: Uint8Array): Uint8Array {
		if (key.length !== 64)
			throw new RangeError(`SerpentSeal key must be 64 bytes (got ${key.length})`);
		if (data.length < 64)
			throw new RangeError('SerpentSeal ciphertext too short');
		const aadBytes = aad ?? new Uint8Array(0);
		const encKey = key.subarray(0, 32);
		const macKey = key.subarray(32, 64);
		const iv = data.subarray(0, 16);
		const tag = data.subarray(data.length - 32);
		const ciphertext = data.subarray(16, data.length - 32);
		const expectedTag = this._hmac.hash(macKey, concat(u32be(aadBytes.length), aadBytes, iv, ciphertext));
		try {
			if (!constantTimeEqual(tag, expectedTag)) {
				(getInstance('serpent').exports as { wipeBuffers(): void }).wipeBuffers();
				throw new AuthenticationError('serpent');
			}
			return this._cbc.decrypt(encKey, iv, ciphertext);
		} finally {
			expectedTag.fill(0);
		}
	}

	dispose(): void {
		this._cbc.dispose();
		this._hmac.dispose();
	}
}
