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
// src/ts/aes/ops.ts
//
// Raw AES-GCM-SIV operations — standalone functions that take AesExports
// explicitly. Used by both `AESGCMSIVCipher` (cipher-suite.ts) and the
// pool worker (pool-worker.ts), eliminating duplication.
//
// This file MUST NOT import from `../init.js`. Pool workers have their
// own WASM instances; importing init in shared ops would couple them.
// The cipher suite obtains exports via getInstance at the call site and
// passes them down.

import type { AesExports } from './types.js';
import { constantTimeEqual, wipe } from '../utils.js';
import { AuthenticationError } from '../errors.js';

const KEY_LEN_256 = 32;
const NONCE_LEN   = 12;
const TAG_LEN     = 16;
const MAX_AAD     = 65536;

/**
 * AES-256-GCM-SIV AEAD encrypt (RFC 8452). Single-shot per call; the
 * plaintext is bounded by the AES module's WASM CHUNK_SIZE.
 *
 * Stage: write KGK at KEY_OFFSET, expand round keys, write nonce/AAD/PT
 * into their slots, run `sivDeriveKeys(NONCE_OFFSET)`, then `sivSeal`.
 * `sivSeal` overwrites CHUNK_PT with the ciphertext in place; the tag
 * lands at TAG_OFFSET.
 *
 * @param x          AES WASM exports
 * @param key        32-byte AES-256 key (KGK in RFC 8452 terminology)
 * @param nonce      12-byte nonce — must be unique per `(key, message)`
 *                   under the standard nonce-respecting model; reuse is
 *                   tolerated by the SIV construction but reduces IND-CPA
 *                   to message-equality leakage
 * @param plaintext  Data to encrypt; must be ≤ `x.getChunkSize()`
 * @param aad        Additional authenticated data; must be ≤ 64 KiB
 * @returns          `{ ciphertext, tag }` — tag is 16 bytes
 */
export function sivAeadEncrypt(
	x:         AesExports,
	key:       Uint8Array,
	nonce:     Uint8Array,
	plaintext: Uint8Array,
	aad:       Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	if (key.length !== KEY_LEN_256)
		throw new RangeError(`AES-GCM-SIV: key must be ${KEY_LEN_256} bytes (got ${key.length})`);
	if (nonce.length !== NONCE_LEN)
		throw new RangeError(`AES-GCM-SIV: nonce must be ${NONCE_LEN} bytes (got ${nonce.length})`);
	const maxChunk = x.getChunkSize();
	if (plaintext.length > maxChunk)
		throw new RangeError(`AES-GCM-SIV: plaintext exceeds ${maxChunk} bytes — split into smaller chunks`);
	if (aad.length > MAX_AAD)
		throw new RangeError(`AES-GCM-SIV: AAD must be ≤ ${MAX_AAD} bytes (got ${aad.length})`);

	const mem = new Uint8Array(x.memory.buffer);

	mem.set(key, x.getKeyOffset());
	if (x.loadKey(KEY_LEN_256) !== 0) {
		x.wipeBuffers();
		throw new Error('AES-GCM-SIV: loadKey failed');
	}

	mem.set(nonce, x.getNonceOffset());
	if (aad.length > 0)
		mem.set(aad, x.getAadOffset());
	mem.set(plaintext, x.getChunkPtOffset());

	x.sivDeriveKeys(x.getNonceOffset());
	x.sivSeal(aad.length, plaintext.length);

	// sivSeal writes the ciphertext in place at CHUNK_PT_OFFSET.
	const ctOff  = x.getChunkPtOffset();
	const tagOff = x.getTagOffset();
	const memView = new Uint8Array(x.memory.buffer);
	const ciphertext = memView.slice(ctOff,  ctOff  + plaintext.length);
	const tag        = memView.slice(tagOff, tagOff + TAG_LEN);
	return { ciphertext, tag };
}

/**
 * AES-256-GCM-SIV AEAD decrypt (RFC 8452). Verify-after-decrypt — the
 * tag is a function of the plaintext, so SIV reconstructs the plaintext
 * before recomputing and comparing the tag in constant time.
 *
 * On mismatch, `sivWipeOnFail()` zeroes the unauthenticated plaintext at
 * CHUNK_PT_OFFSET before this function throws. Subsequent reads of
 * the WASM memory cannot recover plaintext from a forged ciphertext.
 *
 * @param x           AES WASM exports
 * @param key         32-byte AES-256 key
 * @param nonce       12-byte nonce — must match the value used to encrypt
 * @param ciphertext  Ciphertext bytes (must be ≤ `x.getChunkSize()`)
 * @param tag         16-byte SIV tag
 * @param aad         Additional authenticated data
 * @param cipherName  Error label for `AuthenticationError` (default 'aes-gcm-siv')
 * @returns           Plaintext
 */
export function sivAeadDecrypt(
	x:          AesExports,
	key:        Uint8Array,
	nonce:      Uint8Array,
	ciphertext: Uint8Array,
	tag:        Uint8Array,
	aad:        Uint8Array,
	cipherName  = 'aes-gcm-siv',
): Uint8Array {
	if (key.length !== KEY_LEN_256)
		throw new RangeError(`AES-GCM-SIV: key must be ${KEY_LEN_256} bytes (got ${key.length})`);
	if (nonce.length !== NONCE_LEN)
		throw new RangeError(`AES-GCM-SIV: nonce must be ${NONCE_LEN} bytes (got ${nonce.length})`);
	if (tag.length !== TAG_LEN)
		throw new RangeError(`AES-GCM-SIV: tag must be ${TAG_LEN} bytes (got ${tag.length})`);
	const maxChunk = x.getChunkSize();
	if (ciphertext.length > maxChunk)
		throw new RangeError(`AES-GCM-SIV: ciphertext exceeds ${maxChunk} bytes — split into smaller chunks`);
	if (aad.length > MAX_AAD)
		throw new RangeError(`AES-GCM-SIV: AAD must be ≤ ${MAX_AAD} bytes (got ${aad.length})`);

	const mem = new Uint8Array(x.memory.buffer);

	mem.set(key, x.getKeyOffset());
	if (x.loadKey(KEY_LEN_256) !== 0) {
		x.wipeBuffers();
		throw new Error('AES-GCM-SIV: loadKey failed');
	}

	mem.set(nonce, x.getNonceOffset());
	if (aad.length > 0)
		mem.set(aad, x.getAadOffset());
	mem.set(ciphertext, x.getChunkCtOffset());
	// sivOpen reads the provided tag from SIV_IC_OFFSET (the CTR initial
	// counter slot — RFC 8452 §4, where the tag drives the CTR start).
	mem.set(tag, x.getSivIcOffset());

	x.sivDeriveKeys(x.getNonceOffset());
	x.sivOpen(aad.length, ciphertext.length);

	// Read the recomputed expected tag from TAG_OFFSET. slice() so the
	// buffer survives any subsequent WASM memory growth.
	const memView = new Uint8Array(x.memory.buffer);
	const expectedTag = memView.slice(x.getTagOffset(), x.getTagOffset() + TAG_LEN);
	// Defensive copy of the provided tag for the constant-time compare —
	// callers may pass a view over a mutable buffer.
	const providedTagCopy = new Uint8Array(tag);

	if (!constantTimeEqual(expectedTag, providedTagCopy)) {
		x.sivWipeOnFail();
		wipe(expectedTag);
		wipe(providedTagCopy);
		throw new AuthenticationError(cipherName);
	}

	const ptOff = x.getChunkPtOffset();
	return memView.slice(ptOff, ptOff + ciphertext.length);
}
