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

export class SerpentSeal {
	private readonly _cbc: SerpentCbc;
	private readonly _hmac: HMAC_SHA256;

	constructor() {
		if (!_serpentReady() || !_sha2Ready())
			throw new Error('leviathan-crypto: call init([\'serpent\', \'sha2\']) before using SerpentSeal');
		this._cbc = new SerpentCbc({ dangerUnauthenticated: true });
		this._hmac = new HMAC_SHA256();
	}

	// _iv: test seam only — inject a fixed IV for deterministic KAT vectors
	encrypt(key: Uint8Array, plaintext: Uint8Array, _iv?: Uint8Array): Uint8Array {
		if (key.length !== 64)
			throw new RangeError(`SerpentSeal key must be 64 bytes (got ${key.length})`);
		const encKey = key.subarray(0, 32);
		const macKey = key.subarray(32, 64);
		const iv = (_iv && _iv.length === 16) ? _iv : new Uint8Array(16);
		if (!_iv || _iv.length !== 16) crypto.getRandomValues(iv);
		const ciphertext = this._cbc.encrypt(encKey, iv, plaintext);
		const tag = this._hmac.hash(macKey, concat(iv, ciphertext));
		return concat(concat(iv, ciphertext), tag);
	}

	decrypt(key: Uint8Array, data: Uint8Array): Uint8Array {
		if (key.length !== 64)
			throw new RangeError(`SerpentSeal key must be 64 bytes (got ${key.length})`);
		if (data.length < 64)
			throw new RangeError('SerpentSeal ciphertext too short');
		const encKey = key.subarray(0, 32);
		const macKey = key.subarray(32, 64);
		const iv = data.subarray(0, 16);
		const tag = data.subarray(data.length - 32);
		const ciphertext = data.subarray(16, data.length - 32);
		const expectedTag = this._hmac.hash(macKey, concat(iv, ciphertext));
		if (!constantTimeEqual(tag, expectedTag))
			throw new Error('SerpentSeal: authentication failed');
		return this._cbc.decrypt(encKey, iv, ciphertext);
	}

	dispose(): void {
		this._cbc.dispose();
		this._hmac.dispose();
	}
}
