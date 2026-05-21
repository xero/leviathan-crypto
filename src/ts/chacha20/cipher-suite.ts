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
// src/ts/chacha20/cipher-suite.ts
//
// XChaCha20Cipher, CipherSuite implementation for the STREAM construction.
// HKDF-SHA-256 key derivation → HChaCha20 subkey → ChaCha20-Poly1305 per chunk.

import { getInstance, _assertNotOwned } from '../init.js';
import { HKDF_SHA256 } from '../sha2/index.js';
import { aeadEncrypt, aeadDecrypt, deriveSubkey } from './ops.js';
import { wipe, randomBytes, concat } from '../utils.js';
import { HEADER_SIZE } from '../stream/constants.js';
import { WORKER_SOURCE } from '../embedded/chacha20-pool-worker.js';
import type { ChaChaExports } from './types.js';
import type { CipherSuite, DerivedKeys } from '../stream/types.js';

const INFO = new TextEncoder().encode('xchacha20-sealstream-v3');

/** Returns the raw chacha20 WASM export object. @internal */
function getExports(): ChaChaExports {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

/**
 * `CipherSuite` implementation for the stream construction using XChaCha20-Poly1305.
 *
 * Each chunk is encrypted with ChaCha20-Poly1305 using a HChaCha20 subkey
 * derived via HKDF-SHA-256 + HChaCha20. This is the recommended cipher suite
 * for `SealStream` / `OpenStream` / `SealStreamPool`.
 *
 * Pass to `SealStream` / `OpenStream` / `SealStreamPool` instead of constructing
 * this object directly. Use `XChaCha20Cipher.keygen()` to generate a 32-byte key.
 */
export const XChaCha20Cipher: CipherSuite & { keygen(): Uint8Array } = {
	formatEnum: 0x03,
	formatName: 'xchacha20',
	hkdfInfo: 'xchacha20-sealstream-v3',
	keySize: 32,
	kemCtSize: 0,
	commitmentSize: 32,
	tagSize: 16,
	padded: false,
	wasmChunkSize: 65536,  // src/asm/chacha20/buffers.ts CHUNK_SIZE
	wasmModules: ['chacha20'],

	/** Generate a random 32-byte master key suitable for use with `XChaCha20Cipher`. @returns 32 cryptographically random bytes */
	keygen(): Uint8Array {
		return randomBytes(32);
	},

	/**
	 * Derive a 32-byte HChaCha20 subkey and a 32-byte key commitment from
	 * `masterKey` and `nonce` via HKDF-SHA-256 followed by HChaCha20 subkey
	 * derivation. The full 20-byte preamble header is appended to the HKDF
	 * info string, binding `formatEnum`, framed flag, nonce, and chunkSize
	 * into the derived material, header tampering causes derived keys to
	 * differ and AEAD fails on the first chunk.
	 *
	 * The 64-byte HKDF output is split: bytes 0..32 feed HChaCha20 subkey
	 * derivation, bytes 32..64 are the key commitment that ends up in the
	 * preamble. Verifying the commitment before any chunk is processed
	 * closes the Invisible Salamanders attack surface, Poly1305 alone is
	 * not key-committing, so without this an adversary with control over
	 * two master keys could craft a single ciphertext + tag that decrypts
	 * validly under both.
	 *
	 * @param masterKey  32-byte master key
	 * @param nonce      Stream nonce (16 bytes, also used as HChaCha20 input)
	 * @param _kemCt     Unused for symmetric XChaCha20; KEM wrappers pass it through
	 * @param header     20-byte preamble header, required (throws otherwise)
	 * @returns          `DerivedKeys` holding the 32-byte HChaCha20 subkey and 32-byte commitment
	 */
	deriveKeys(masterKey: Uint8Array, nonce: Uint8Array, _kemCt?: Uint8Array, header?: Uint8Array): DerivedKeys {
		if (!header || header.length !== HEADER_SIZE)
			throw new Error(`XChaCha20Cipher.deriveKeys: header binding required (got ${header?.length ?? 'undefined'} bytes)`);

		_assertNotOwned('chacha20');
		const hkdf = new HKDF_SHA256();
		let okm: Uint8Array;
		try {
			// INFO || header, binds formatEnum, framed flag, nonce, chunkSize into the KDF.
			// Any header tampering produces different keys, AEAD fails on the first chunk.
			const info = concat(INFO, header);
			okm = hkdf.derive(masterKey, nonce, info, 64);
		} finally {
			hkdf.dispose();
		}

		// Bytes 0..32: streamKey for HChaCha20 subkey derivation.
		// Bytes 32..64: key commitment for the seal preamble.
		const streamKey  = okm.subarray(0, 32);
		const commitment = okm.slice(32, 64);          // independent backing, survives okm wipe

		const x = getExports();
		const subkey = deriveSubkey(x, streamKey, nonce);
		wipe(okm);                                     // wipe both halves of okm; commitment is safe (independent backing)
		return { bytes: subkey, commitment };
	},

	/**
	 * Encrypt and authenticate one stream chunk with ChaCha20-Poly1305.
	 * Output: ciphertext || 16-byte Poly1305 tag.
	 * @param keys         Derived keys from `deriveKeys`
	 * @param counterNonce 12-byte per-chunk nonce (unique per chunk in the stream)
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
		_assertNotOwned('chacha20');
		const x = getExports();
		const { ciphertext, tag } = aeadEncrypt(
			x, keys.bytes, counterNonce, chunk, aad ?? new Uint8Array(0),
		);
		const out = new Uint8Array(ciphertext.length + 16);
		out.set(ciphertext);
		out.set(tag, ciphertext.length);
		return out;
	},

	/**
	 * Verify and decrypt one stream chunk. Throws `AuthenticationError` on tag mismatch.
	 * @param keys         Derived keys from `deriveKeys`
	 * @param counterNonce 12-byte per-chunk nonce, must match the value used by `sealChunk`
	 * @param chunk        Ciphertext || 16-byte Poly1305 tag
	 * @param aad          Optional additional authenticated data
	 * @returns            Plaintext
	 */
	openChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array {
		_assertNotOwned('chacha20');
		if (chunk.length < 16)
			throw new RangeError(`chunk too short for 16-byte tag (got ${chunk.length})`);
		const x = getExports();
		const ct  = chunk.subarray(0, chunk.length - 16);
		const tag = chunk.subarray(chunk.length - 16);
		return aeadDecrypt(
			x, keys.bytes, counterNonce, ct, tag,
			aad ?? new Uint8Array(0), 'xchacha20-poly1305',
		);
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
	 * Spawn an XChaCha20 pool worker from the embedded IIFE bundle.
	 * The worker holds its own chacha20 WASM instance and derived subkey.
	 * @returns  Newly constructed `Worker` instance
	 */
	createPoolWorker(): Worker {
		// See docs/architecture.md#pool-worker-spawn-pattern.
		const blob = new Blob([WORKER_SOURCE], { type: 'application/javascript' });
		const url  = URL.createObjectURL(blob);
		const w    = new Worker(url);
		setTimeout(() => URL.revokeObjectURL(url), 0);
		return w;
	},
};
