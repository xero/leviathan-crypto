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
// src/ts/aes/cipher-suite.ts
//
// AESGCMSIVCipher, CipherSuite implementation for the STREAM construction.
// HKDF-SHA-256 key derivation → AES-256-GCM-SIV per chunk. Mirrors the
// XChaCha20Cipher HtE explicit-commitment construction byte-for-byte
// modulo the cipher backend, since AES-GCM-SIV's POLYVAL-based MAC is
// not key-committing on its own.

import { getInstance, _assertNotOwned } from '../init.js';
import { HKDF_SHA256 } from '../sha2/index.js';
import { sivAeadEncrypt, sivAeadDecrypt } from './ops.js';
import { wipe, randomBytes, concat } from '../utils.js';
import { HEADER_SIZE } from '../stream/constants.js';
import { WORKER_SOURCE } from '../embedded/aes-pool-worker.js';
import type { AesExports } from './types.js';
import type { CipherSuite, DerivedKeys } from '../stream/types.js';

const INFO = new TextEncoder().encode('aes-gcm-siv-sealstream-v3');

/** Returns the raw aes WASM export object. @internal */
function getExports(): AesExports {
	return getInstance('aes').exports as unknown as AesExports;
}

/**
 * `CipherSuite` implementation for the stream construction using
 * AES-256-GCM-SIV (RFC 8452).
 *
 * Each chunk is encrypted with AES-256-GCM-SIV using a per-stream
 * AES key derived via HKDF-SHA-256. Unlike `XChaCha20Cipher` there is
 * no intermediate subkey derivation step, AES-GCM-SIV uses a 12-byte
 * nonce natively, so the 32 bytes from HKDF feed straight into the
 * cipher.
 *
 * Pass to `Seal` / `SealStream` / `OpenStream` / `SealStreamPool`
 * instead of constructing this object directly. Use
 * `AESGCMSIVCipher.keygen()` to generate a 32-byte master key.
 *
 * The cipher suite is AES-256 only; the standalone `AESGCMSIV` primitive
 * class continues to support both AES-128 and AES-256 (RFC 8452 §6).
 */
export const AESGCMSIVCipher: CipherSuite & { keygen(): Uint8Array } = {
	formatEnum: 0x04,
	formatName: 'aes-gcm-siv',
	hkdfInfo: 'aes-gcm-siv-sealstream-v3',
	keySize: 32,
	kemCtSize: 0,
	commitmentSize: 32,
	tagSize: 16,
	padded: false,
	wasmChunkSize: 65536,  // src/asm/aes/buffers.ts AES_CHUNK_SIZE
	wasmModules: ['aes'],

	/** Generate a random 32-byte master key suitable for use with `AESGCMSIVCipher`. @returns 32 cryptographically random bytes */
	keygen(): Uint8Array {
		return randomBytes(32);
	},

	/**
	 * Derive a 32-byte AES-256-GCM-SIV key and a 32-byte key commitment
	 * from `masterKey` and `nonce` via HKDF-SHA-256. The full 20-byte
	 * preamble header is appended to the HKDF info string, binding
	 * `formatEnum`, framed flag, nonce, and chunkSize into the derived
	 * material, header tampering causes derived keys to differ and AEAD
	 * fails on the first chunk.
	 *
	 * The 64-byte HKDF output is split: bytes 0..32 are the per-stream
	 * AES-GCM-SIV key, bytes 32..64 are the key commitment that ends up
	 * in the preamble. Verifying the commitment before any chunk is
	 * processed closes the Invisible Salamanders attack surface,
	 * AES-GCM-SIV's POLYVAL-based MAC is not key-committing on its own,
	 * so without this an adversary with control over two master keys
	 * could craft a single ciphertext + tag that decrypts validly under
	 * both.
	 *
	 * Unlike `XChaCha20Cipher` there is no subkey-derivation step:
	 * AES-GCM-SIV's nonce is 12 bytes, used directly per chunk; there
	 * is no HChaCha20 analog.
	 *
	 * @param masterKey  32-byte master key
	 * @param nonce      Stream nonce (16 bytes)
	 * @param _kemCt     Unused for symmetric AES-GCM-SIV; KEM wrappers pass it through
	 * @param header     20-byte preamble header, required (throws otherwise)
	 * @returns          `DerivedKeys` holding the 32-byte AES-GCM-SIV key and 32-byte commitment
	 */
	deriveKeys(masterKey: Uint8Array, nonce: Uint8Array, _kemCt?: Uint8Array, header?: Uint8Array): DerivedKeys {
		if (!header || header.length !== HEADER_SIZE)
			throw new Error(`AESGCMSIVCipher.deriveKeys: header binding required (got ${header?.length ?? 'undefined'} bytes)`);

		_assertNotOwned('aes');
		_assertNotOwned('sha2');
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

		// Bytes 0..32: per-stream AES-GCM-SIV key (no subkey derivation step).
		// Bytes 32..64: key commitment for the seal preamble.
		const aesKey     = okm.slice(0,  32);   // independent backing, survives okm wipe
		const commitment = okm.slice(32, 64);   // independent backing, survives okm wipe
		wipe(okm);
		return { bytes: aesKey, commitment };
	},

	/**
	 * Encrypt and authenticate one stream chunk with AES-256-GCM-SIV.
	 * Output: ciphertext || 16-byte tag.
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
		_assertNotOwned('aes');
		const x = getExports();
		const { ciphertext, tag } = sivAeadEncrypt(
			x, keys.bytes, counterNonce, chunk, aad ?? new Uint8Array(0),
		);
		const out = new Uint8Array(ciphertext.length + 16);
		out.set(ciphertext);
		out.set(tag, ciphertext.length);
		return out;
	},

	/**
	 * Verify and decrypt one stream chunk. Throws `AuthenticationError('aes-gcm-siv')`
	 * on tag mismatch.
	 * @param keys         Derived keys from `deriveKeys`
	 * @param counterNonce 12-byte per-chunk nonce, must match the value used by `sealChunk`
	 * @param chunk        Ciphertext || 16-byte tag
	 * @param aad          Optional additional authenticated data
	 * @returns            Plaintext
	 */
	openChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array {
		_assertNotOwned('aes');
		if (chunk.length < 16)
			throw new RangeError(`chunk too short for 16-byte tag (got ${chunk.length})`);
		const x = getExports();
		const ct  = chunk.subarray(0, chunk.length - 16);
		const tag = chunk.subarray(chunk.length - 16);
		return sivAeadDecrypt(
			x, keys.bytes, counterNonce, ct, tag,
			aad ?? new Uint8Array(0), 'aes-gcm-siv',
		);
	},

	/**
	 * Zero all derived key material in `keys`. Called by the stream
	 * layer on teardown and after auth failure.
	 * @param keys  Derived keys to wipe
	 */
	wipeKeys(keys: DerivedKeys): void {
		wipe(keys.bytes);
	},

	/**
	 * Spawn an AES pool worker from the embedded IIFE bundle. The worker
	 * holds its own aes WASM instance and derived AES-GCM-SIV key.
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
