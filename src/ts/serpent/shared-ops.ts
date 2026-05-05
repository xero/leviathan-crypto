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
// src/ts/serpent/shared-ops.ts
//
// Pure-function primitives shared between the main-thread `SerpentCipher`
// (cipher-suite.ts) and the `SealStreamPool` worker (pool-worker.ts). Both
// call sites hold their own WASM exports — pool workers instantiate modules
// locally, the main thread fetches via `getInstance()` — so every function
// here takes the sha2/serpent exports as parameters. No dependency on
// `init.ts`, no module-level state, no instance wrappers.
//
// These helpers are strictly single-chunk: the caller already divided the
// payload into chunks ≤ WASM CHUNK_SIZE. For multi-chunk use, see
// `SerpentCbc.encrypt`/`decrypt`, which loop over the same WASM exports.
//
// `pkcs7Pad` / `pkcs7Strip` / `PKCS7_INVALID` live in `../shared/pkcs7.js`
// and are re-exported here so existing serpent-side imports keep working.
// A single source of truth keeps the branch-free, Vaudenay-2002-closed
// padding check identical across all CBC paths.

export { pkcs7Pad, pkcs7Strip, PKCS7_INVALID } from '../shared/pkcs7.js';
import { pkcs7Pad, pkcs7Strip, PKCS7_INVALID } from '../shared/pkcs7.js';

// ── WASM export interfaces ──────────────────────────────────────────────────

/** Subset of the sha2 WASM exports used by `hmacSha256`. */
export interface Sha2OpsExports {
	memory:              WebAssembly.Memory;
	getSha256InputOffset:() => number;
	getSha256OutOffset:  () => number;
	sha256Init:          () => void;
	sha256Update:        (len: number) => void;
	sha256Final:         () => void;
	hmac256Init:         (keyLen: number) => void;
	hmac256Update:       (len: number) => void;
	hmac256Final:        () => void;
}

/** Subset of the serpent WASM exports used by `cbcEncryptChunk`/`cbcDecryptChunk`. */
export interface SerpentOpsExports {
	memory:               WebAssembly.Memory;
	getKeyOffset:         () => number;
	getChunkPtOffset:     () => number;
	getChunkCtOffset:     () => number;
	getChunkSize:         () => number;
	getCbcIvOffset:       () => number;
	loadKey:              (n: number) => number;
	cbcEncryptChunk:      (n: number) => number;
	cbcDecryptChunk_simd: (n: number) => number;
}

// ── HMAC-SHA-256 ────────────────────────────────────────────────────────────

/**
 * Compute HMAC-SHA-256 using raw WASM sha2 exports.
 *
 * Keys longer than 64 bytes are pre-hashed per RFC 2104 §3. The SHA-256
 * input buffer is fed in 64-byte chunks to match the WASM block size.
 * Does not call `_acquireModule` — callers must ensure no stateful instance
 * owns the sha2 module before calling.
 * @param sx   sha2 WASM exports
 * @param key  HMAC key of any length
 * @param msg  Message to authenticate
 * @returns    32-byte HMAC-SHA-256 tag
 */
export function hmacSha256(
	sx: Sha2OpsExports,
	key: Uint8Array,
	msg: Uint8Array,
): Uint8Array {
	const inOff  = sx.getSha256InputOffset();
	const outOff = sx.getSha256OutOffset();
	let k = key;
	if (k.length > 64) {
		sx.sha256Init();
		feedMemory(sx.memory, inOff, k, 64, sx.sha256Update);
		sx.sha256Final();
		k = new Uint8Array(sx.memory.buffer).slice(outOff, outOff + 32);
	}
	const mem = new Uint8Array(sx.memory.buffer);
	mem.set(k, inOff);
	sx.hmac256Init(k.length);
	feedMemory(sx.memory, inOff, msg, 64, sx.hmac256Update);
	sx.hmac256Final();
	return new Uint8Array(sx.memory.buffer).slice(outOff, outOff + 32);
}

/**
 * Copy `msg` into WASM linear memory at `inputOff` in `chunkSize`-byte
 * increments, calling `update(n)` after each write.
 * @param memory     WASM memory object
 * @param inputOff   Byte offset of the WASM input buffer
 * @param msg        Data to feed
 * @param chunkSize  Maximum bytes per write (must match WASM buffer size)
 * @param update     WASM update function to call after each write
 * @internal
 */
function feedMemory(
	memory: WebAssembly.Memory,
	inputOff: number,
	msg: Uint8Array,
	chunkSize: number,
	update: (n: number) => void,
): void {
	const mem = new Uint8Array(memory.buffer);
	let pos = 0;
	while (pos < msg.length) {
		const n = Math.min(msg.length - pos, chunkSize);
		mem.set(msg.subarray(pos, pos + n), inputOff);
		update(n);
		pos += n;
	}
}

// ── Serpent-CBC (single chunk) ──────────────────────────────────────────────

/**
 * Encrypt one plaintext chunk with Serpent-256 CBC + PKCS7 padding.
 *
 * The padded chunk must fit within the WASM CHUNK_SIZE. Callers are
 * responsible for splitting larger payloads before calling.
 * @param kx     Serpent WASM exports
 * @param key    16, 24, or 32-byte key
 * @param iv     16-byte CBC initialisation vector
 * @param chunk  Plaintext chunk (padded length must be ≤ WASM CHUNK_SIZE)
 * @returns      Ciphertext with PKCS7 padding applied
 */
export function cbcEncryptChunk(
	kx: SerpentOpsExports,
	key: Uint8Array,
	iv: Uint8Array,
	chunk: Uint8Array,
): Uint8Array {
	loadKeyAndIv(kx, key, iv);
	const padded = pkcs7Pad(chunk);
	const ptOff = kx.getChunkPtOffset();
	const ctOff = kx.getChunkCtOffset();
	const mem = new Uint8Array(kx.memory.buffer);
	mem.set(padded, ptOff);
	const ret = kx.cbcEncryptChunk(padded.length);
	if (ret < 0) throw new RangeError(
		`cbcEncryptChunk rejected len=${padded.length}` +
		` (WASM CHUNK_SIZE=${kx.getChunkSize()})`,
	);
	return new Uint8Array(kx.memory.buffer).slice(ctOff, ctOff + padded.length);
}

/**
 * Decrypt one Serpent-256 CBC chunk using the SIMD path and strip PKCS7 padding.
 *
 * Output matches `SerpentCbc.decrypt` byte-for-byte. Throws
 * `RangeError('invalid ciphertext')` on any length or padding failure.
 * @param kx   Serpent WASM exports
 * @param key  16, 24, or 32-byte key
 * @param iv   16-byte CBC initialisation vector
 * @param ct   Ciphertext (must be non-empty and a multiple of 16 bytes)
 * @returns    Plaintext with PKCS7 padding removed
 */
export function cbcDecryptChunk(
	kx: SerpentOpsExports,
	key: Uint8Array,
	iv: Uint8Array,
	ct: Uint8Array,
): Uint8Array {
	if (ct.length === 0 || ct.length % 16 !== 0)
		throw new RangeError(PKCS7_INVALID);
	loadKeyAndIv(kx, key, iv);
	const ctOff = kx.getChunkCtOffset();
	const ptOff = kx.getChunkPtOffset();
	const mem = new Uint8Array(kx.memory.buffer);
	mem.set(ct, ctOff);
	const ret = kx.cbcDecryptChunk_simd(ct.length);
	if (ret < 0) throw new RangeError(
		`cbcDecryptChunk_simd rejected len=${ct.length}` +
		` (WASM CHUNK_SIZE=${kx.getChunkSize()})`,
	);
	const raw = new Uint8Array(kx.memory.buffer).slice(ptOff, ptOff + ct.length);
	return pkcs7Strip(raw);
}

/**
 * Validate, then write `key` and `iv` into the WASM buffers and expand the key schedule.
 * @param kx   Serpent WASM exports
 * @param key  16, 24, or 32-byte Serpent key
 * @param iv   16-byte CBC initialisation vector
 * @internal
 */
function loadKeyAndIv(
	kx: SerpentOpsExports,
	key: Uint8Array,
	iv: Uint8Array,
): void {
	if (key.length !== 16 && key.length !== 24 && key.length !== 32)
		throw new RangeError(`Serpent key must be 16, 24, or 32 bytes (got ${key.length})`);
	if (iv.length !== 16)
		throw new RangeError(`CBC IV must be 16 bytes (got ${iv.length})`);
	const mem = new Uint8Array(kx.memory.buffer);
	mem.set(key, kx.getKeyOffset());
	kx.loadKey(key.length);
	mem.set(iv, kx.getCbcIvOffset());
}
