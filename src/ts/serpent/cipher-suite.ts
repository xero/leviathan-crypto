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
// src/ts/serpent/cipher-suite.ts
//
// SerpentCipher — CipherSuite implementation for the STREAM construction.
// 3-key HKDF derivation, HMAC-derived CBC IV, Serpent-CBC + HMAC-SHA-256.
// Verify-then-decrypt ordering prevents padding oracle attacks (Vaudenay 2002).

import { SerpentCbc } from './serpent-cbc.js';
import { HKDF_SHA256, HMAC_SHA256 } from '../sha2/index.js';
import { constantTimeEqual, wipe, concat, randomBytes } from '../utils.js';
import { AuthenticationError } from '../errors.js';
import { getInstance } from '../init.js';
import type { CipherSuite, DerivedKeys } from '../stream/types.js';

const INFO = new TextEncoder().encode('serpent-sealstream-v2');

export const SerpentCipher: CipherSuite & { keygen(): Uint8Array } = {
	formatEnum: 0x02,
	formatName: 'serpent',
	hkdfInfo: 'serpent-sealstream-v2',
	keySize: 32,
	kemCtSize: 0,
	tagSize: 32,
	padded: true,
	wasmModules: ['serpent', 'sha2'],

	keygen(): Uint8Array {
		return randomBytes(32);
	},

	deriveKeys(masterKey: Uint8Array, nonce: Uint8Array, _kemCt?: Uint8Array): DerivedKeys {
		const hkdf = new HKDF_SHA256();
		const derived = hkdf.derive(masterKey, nonce, INFO, 96);
		hkdf.dispose();
		// bytes[0:32]=enc_key, bytes[32:64]=mac_key, bytes[64:96]=iv_key
		return { bytes: derived };
	},

	sealChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array {
		const encKey = keys.bytes.subarray(0, 32);
		const macKey = keys.bytes.subarray(32, 64);
		const ivKey  = keys.bytes.subarray(64, 96);
		const aadBytes = aad ?? new Uint8Array(0);

		const hmac = new HMAC_SHA256();

		// Derive IV from counter nonce
		const ivFull = hmac.hash(ivKey, counterNonce);
		const iv = ivFull.slice(0, 16);
		wipe(ivFull);

		// Encrypt: Serpent-CBC with PKCS7 padding
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		const ct = cbc.encrypt(encKey, iv, chunk);
		cbc.dispose();

		// Compute HMAC tag: HMAC-SHA-256(mac_key, counterNonce || u32be(aad_len) || aad || ct)
		const aadLenBuf = new Uint8Array(4);
		new DataView(aadLenBuf.buffer).setUint32(0, aadBytes.length, false);
		const tagInput = concat(counterNonce, aadLenBuf, aadBytes, ct);
		const tag = hmac.hash(macKey, tagInput);
		hmac.dispose();

		wipe(iv);
		wipe(tagInput);

		// Output: ct || tag (IV is NOT included)
		return concat(ct, tag);
	},

	openChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array {
		if (chunk.length < 32)
			throw new RangeError(`chunk too short for 32-byte tag (got ${chunk.length})`);
		const encKey = keys.bytes.subarray(0, 32);
		const macKey = keys.bytes.subarray(32, 64);
		const ivKey  = keys.bytes.subarray(64, 96);
		const aadBytes = aad ?? new Uint8Array(0);

		const ct          = chunk.subarray(0, chunk.length - 32);
		const receivedTag = chunk.subarray(chunk.length - 32);

		const hmac = new HMAC_SHA256();

		// Derive IV from counter nonce
		const ivFull = hmac.hash(ivKey, counterNonce);
		const iv = ivFull.slice(0, 16);
		wipe(ivFull);

		// Compute expected tag: HMAC-SHA-256(mac_key, counterNonce || u32be(aad_len) || aad || ct)
		const aadLenBuf = new Uint8Array(4);
		new DataView(aadLenBuf.buffer).setUint32(0, aadBytes.length, false);
		const tagInput = concat(counterNonce, aadLenBuf, aadBytes, ct);
		const expectedTag = hmac.hash(macKey, tagInput);
		hmac.dispose();

		// CRITICAL: Verify HMAC BEFORE decrypting.
		// Evaluating PKCS7 padding on unauthenticated data is a padding oracle (Vaudenay 2002).
		if (!constantTimeEqual(expectedTag, receivedTag)) {
			wipe(iv);
			wipe(tagInput);
			wipe(expectedTag);
			(getInstance('serpent').exports as { wipeBuffers(): void }).wipeBuffers();
			throw new AuthenticationError('serpent');
		}

		wipe(tagInput);
		wipe(expectedTag);

		// ONLY decrypt after authentication succeeds
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		const plaintext = cbc.decrypt(encKey, iv, ct);
		cbc.dispose();
		wipe(iv);

		return plaintext;
	},

	wipeKeys(keys: DerivedKeys): void {
		wipe(keys.bytes);
	},

	createPoolWorker(): Worker {
		return new Worker(
			new URL('./pool-worker.js', import.meta.url),
			{ type: 'module' },
		);
	},
};
