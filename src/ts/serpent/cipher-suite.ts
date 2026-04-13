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

import { HKDF_SHA256 } from '../sha2/index.js';
import { constantTimeEqual, wipe, concat, randomBytes } from '../utils.js';
import { AuthenticationError } from '../errors.js';
import { getInstance, _assertNotOwned } from '../init.js';
import {
	hmacSha256,
	cbcEncryptChunk,
	cbcDecryptChunk,
	type Sha2OpsExports,
	type SerpentOpsExports,
} from './shared-ops.js';
import { WORKER_SOURCE } from '../embedded/serpent-pool-worker.js';
import type { CipherSuite, DerivedKeys } from '../stream/types.js';

const INFO = new TextEncoder().encode('serpent-sealstream-v2');

/**
 * `CipherSuite` implementation for the stream construction using Serpent-256.
 *
 * Each chunk is encrypted with Serpent-CBC (PKCS7) and authenticated with
 * HMAC-SHA-256. Keys are derived via 3-way HKDF-SHA-256 (enc / mac / iv keys).
 * Verify-then-decrypt ordering prevents padding oracle attacks (Vaudenay 2002).
 *
 * Pass to `SealStream` / `OpenStream` / `SealStreamPool` instead of constructing
 * this object directly. Use `SerpentCipher.keygen()` to generate a 32-byte key.
 */
export const SerpentCipher: CipherSuite & { keygen(): Uint8Array } = {
	formatEnum: 0x02,
	formatName: 'serpent',
	hkdfInfo: 'serpent-sealstream-v2',
	keySize: 32,
	kemCtSize: 0,
	tagSize: 32,
	padded: true,
	wasmChunkSize: 65552,  // src/asm/serpent/buffers.ts CHUNK_SIZE (65536 + 16 PKCS7 max overhead)
	wasmModules: ['serpent', 'sha2'],

	/** Generate a random 32-byte master key suitable for use with `SerpentCipher`. @returns 32 cryptographically random bytes */
	keygen(): Uint8Array {
		return randomBytes(32);
	},

	/**
	 * Derive 96 bytes of keying material from `masterKey` and `nonce` via HKDF-SHA-256.
	 * Layout: bytes[0:32]=enc_key, bytes[32:64]=mac_key, bytes[64:96]=iv_key.
	 * @param masterKey  32-byte master key
	 * @param nonce      Stream nonce (16 bytes minimum)
	 * @returns          `DerivedKeys` holding the 96-byte material
	 */
	deriveKeys(masterKey: Uint8Array, nonce: Uint8Array, _kemCt?: Uint8Array): DerivedKeys {
		const hkdf = new HKDF_SHA256();
		const derived = hkdf.derive(masterKey, nonce, INFO, 96);
		hkdf.dispose();
		// bytes[0:32]=enc_key, bytes[32:64]=mac_key, bytes[64:96]=iv_key
		return { bytes: derived };
	},

	/**
	 * Encrypt and authenticate one stream chunk.
	 * IV is derived from `counterNonce` via HMAC-SHA-256 with the iv_key.
	 * Output: ciphertext (PKCS7-padded) || 32-byte HMAC tag.
	 * @param keys         Derived keys from `deriveKeys`
	 * @param counterNonce Per-chunk nonce (unique per chunk in the stream)
	 * @param chunk        Plaintext chunk
	 * @param aad          Optional additional authenticated data
	 * @returns            Authenticated ciphertext
	 */
	sealChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array {
		// shared-ops functions operate directly on the module exports without
		// going through `_acquireModule`. Assert no stateful instance owns
		// either module before touching WASM memory.
		_assertNotOwned('serpent');
		_assertNotOwned('sha2');

		const sx = getInstance('sha2').exports as unknown as Sha2OpsExports;
		const kx = getInstance('serpent').exports as unknown as SerpentOpsExports;

		const encKey = keys.bytes.subarray(0, 32);
		const macKey = keys.bytes.subarray(32, 64);
		const ivKey  = keys.bytes.subarray(64, 96);
		const aadBytes = aad ?? new Uint8Array(0);

		let iv: Uint8Array | undefined;
		let tagInput: Uint8Array | undefined;
		try {
			// Derive IV from counter nonce
			const ivFull = hmacSha256(sx, ivKey, counterNonce);
			iv = ivFull.slice(0, 16);
			wipe(ivFull);

			// Encrypt: Serpent-CBC with PKCS7 padding
			const ct = cbcEncryptChunk(kx, encKey, iv, chunk);

			// Compute HMAC tag: HMAC-SHA-256(mac_key, counterNonce || u32be(aad_len) || aad || ct)
			const aadLenBuf = new Uint8Array(4);
			new DataView(aadLenBuf.buffer).setUint32(0, aadBytes.length, false);
			tagInput = concat(counterNonce, aadLenBuf, aadBytes, ct);
			const tag = hmacSha256(sx, macKey, tagInput);

			// Output: ct || tag (IV is NOT included)
			return concat(ct, tag);
		} finally {
			if (iv)       wipe(iv);
			if (tagInput) wipe(tagInput);
			// No hmac/cbc instance to dispose — shared-ops functions are instance-free.
		}
	},

	/**
	 * Verify and decrypt one stream chunk. HMAC is verified before decryption
	 * to prevent padding oracle attacks (Vaudenay 2002). Throws
	 * `AuthenticationError` on tag mismatch.
	 * @param keys         Derived keys from `deriveKeys`
	 * @param counterNonce Per-chunk nonce — must match the value used by `sealChunk`
	 * @param chunk        Ciphertext || 32-byte HMAC tag
	 * @param aad          Optional additional authenticated data
	 * @returns            Plaintext with PKCS7 padding removed
	 */
	openChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array {
		if (chunk.length < 32)
			throw new RangeError(`chunk too short for 32-byte tag (got ${chunk.length})`);

		_assertNotOwned('serpent');
		_assertNotOwned('sha2');

		const sx = getInstance('sha2').exports as unknown as Sha2OpsExports;
		const kx = getInstance('serpent').exports as unknown as SerpentOpsExports;

		const encKey = keys.bytes.subarray(0, 32);
		const macKey = keys.bytes.subarray(32, 64);
		const ivKey  = keys.bytes.subarray(64, 96);
		const aadBytes = aad ?? new Uint8Array(0);

		const ct          = chunk.subarray(0, chunk.length - 32);
		const receivedTag = chunk.subarray(chunk.length - 32);

		let iv: Uint8Array | undefined;
		let tagInput: Uint8Array | undefined;
		let expectedTag: Uint8Array | undefined;
		try {
			// Derive IV from counter nonce
			const ivFull = hmacSha256(sx, ivKey, counterNonce);
			iv = ivFull.slice(0, 16);
			wipe(ivFull);

			// Compute expected tag: HMAC-SHA-256(mac_key, counterNonce || u32be(aad_len) || aad || ct)
			const aadLenBuf = new Uint8Array(4);
			new DataView(aadLenBuf.buffer).setUint32(0, aadBytes.length, false);
			tagInput = concat(counterNonce, aadLenBuf, aadBytes, ct);
			expectedTag = hmacSha256(sx, macKey, tagInput);

			// CRITICAL: Verify HMAC BEFORE decrypting.
			// Evaluating PKCS7 padding on unauthenticated data is a padding oracle (Vaudenay 2002).
			// Belt-and-suspenders: explicit wipes here cover the auth-fail path before
			// throwing; the finally block below covers every other path.
			if (!constantTimeEqual(expectedTag, receivedTag)) {
				wipe(iv);
				wipe(tagInput);
				wipe(expectedTag);
				(getInstance('serpent').exports as { wipeBuffers(): void }).wipeBuffers();
				throw new AuthenticationError('serpent');
			}

			// ONLY decrypt after authentication succeeds
			return cbcDecryptChunk(kx, encKey, iv, ct);
		} finally {
			if (iv)          wipe(iv);
			if (tagInput)    wipe(tagInput);
			if (expectedTag) wipe(expectedTag);
		}
	},

	/**
	 * Zero all derived key material in `keys`. Called by the stream layer on
	 * teardown and after auth failure.
	 * @param keys  Derived keys to wipe
	 */
	wipeKeys(keys: DerivedKeys): void {
		wipe(keys.bytes);
	},

	/**
	 * Spawn a Serpent pool worker from the embedded IIFE bundle.
	 * The worker holds its own serpent + sha2 WASM instances.
	 * @returns  Newly constructed `Worker` instance
	 */
	createPoolWorker(): Worker {
		// IIFE source is bundled at lib build time (scripts/embed-workers.ts).
		// Avoids the syntactic `new Worker(new URL(..., import.meta.url))`
		// pattern that triggers eager worker-chunk emission in Vite's
		// transform hook (issue.md). Classic worker via blob URL —
		// module workers fail on file:// in Chromium (issue2.md).
		const blob = new Blob([WORKER_SOURCE], { type: 'application/javascript' });
		const url  = URL.createObjectURL(blob);
		const w    = new Worker(url);
		// Worker spec fetches the URL synchronously at construction. Revoke
		// in a macrotask so the spawn completes first; releases the Blob
		// (~5 KB per spawn × N workers) instead of leaking it for the
		// document's lifetime.
		setTimeout(() => URL.revokeObjectURL(url), 0);
		return w;
	},
};
