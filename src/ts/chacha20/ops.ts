// src/ts/chacha20/ops.ts
//
// Raw XChaCha20-Poly1305 operations — standalone functions that take
// ChaChaExports explicitly. Used by both the class wrappers (index.ts)
// and the pool worker (pool.worker.ts), eliminating duplication.

import type { ChaChaExports } from './types.js';
import { constantTimeEqual } from '../utils.js';
import { AuthenticationError } from '../errors.js';

// ── Module-private helpers ──────────────────────────────────────────────────

/**
 * Feed `data` into the active Poly1305 accumulator via the WASM message buffer.
 * No-op when `data` is empty.
 * @param x     ChaCha20 WASM exports
 * @param data  Bytes to absorb
 * @internal
 */
function polyFeed(x: ChaChaExports, data: Uint8Array): void {
	if (data.length === 0) return;
	const mem    = new Uint8Array(x.memory.buffer);
	const msgOff = x.getPolyMsgOffset();
	let pos = 0;
	while (pos < data.length) {
		const chunk = Math.min(64, data.length - pos);
		mem.set(data.subarray(pos, pos + chunk), msgOff);
		x.polyUpdate(chunk);
		pos += chunk;
	}
}

/**
 * Build the 16-byte Poly1305 length footer from AAD and ciphertext lengths.
 * Both lengths are encoded as 64-bit little-endian integers (RFC 8439 §2.8).
 * @param aadLen  AAD byte length
 * @param ctLen   Ciphertext byte length
 * @returns       16-byte length block
 * @internal
 */
function lenBlock(aadLen: number, ctLen: number): Uint8Array {
	const b = new Uint8Array(16);
	const dv = new DataView(b.buffer);
	// RFC 8439 §2.8 — 64-bit LE lengths.
	// JS numbers are f64 — write low 32 bits directly, high bits via
	// Math.floor(n / 2^32). Safe for n ≤ Number.MAX_SAFE_INTEGER.
	dv.setUint32(0, aadLen >>> 0, true);
	dv.setUint32(4, Math.floor(aadLen / 0x100000000) >>> 0, true);
	dv.setUint32(8, ctLen >>> 0, true);
	dv.setUint32(12, Math.floor(ctLen / 0x100000000) >>> 0, true);
	return b;
}

// ── Inner AEAD (12-byte nonce) ──────────────────────────────────────────────

/**
 * ChaCha20-Poly1305 AEAD encrypt (RFC 8439 §2.8).
 * @param x          ChaCha20 WASM exports
 * @param key        32-byte key
 * @param nonce      12-byte nonce — must be unique per (key, message)
 * @param plaintext  Data to encrypt (must be ≤ WASM CHUNK_SIZE)
 * @param aad        Additional authenticated data
 * @returns          `{ ciphertext, tag }` — tag is 16 bytes
 */
export function aeadEncrypt(
	x:         ChaChaExports,
	key:       Uint8Array,
	nonce:     Uint8Array,
	plaintext: Uint8Array,
	aad:       Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
	const maxChunk = x.getChunkSize();
	if (plaintext.length > maxChunk)
		throw new RangeError(`plaintext exceeds ${maxChunk} bytes — split into smaller chunks`);

	const mem = new Uint8Array(x.memory.buffer);

	// Step 1: Generate Poly1305 one-time key at counter=0 (RFC 8439 §2.6)
	mem.set(key,   x.getKeyOffset());
	mem.set(nonce, x.getChachaNonceOffset());
	x.chachaLoadKey();
	x.chachaGenPolyKey();

	// Step 2: Initialise Poly1305
	x.polyInit();

	// Step 3: MAC AAD + pad
	polyFeed(x, aad);
	const aadPad = (16 - aad.length % 16) % 16;
	if (aadPad > 0) polyFeed(x, new Uint8Array(aadPad));

	// Step 4: Re-init ChaCha20 at counter=1.
	// `chachaGenPolyKey` mutated CHACHA_STATE + 48 (the counter word) to 0 but
	// left every other state word intact (constants, key, nonce). Writing
	// counter=1 via `chachaSetCounter` restores the state for encryption —
	// no second `chachaLoadKey()` is needed (the key/nonce buffers and the
	// non-counter state words are already correct).
	x.chachaSetCounter(1);

	// Step 5: Encrypt
	mem.set(plaintext, x.getChunkPtOffset());
	x.chachaEncryptChunk_simd(plaintext.length);
	const ctOff     = x.getChunkCtOffset();
	const ciphertext = new Uint8Array(x.memory.buffer).slice(ctOff, ctOff + plaintext.length);

	// Step 6: MAC ciphertext + pad
	polyFeed(x, ciphertext);
	const ctPad = (16 - plaintext.length % 16) % 16;
	if (ctPad > 0) polyFeed(x, new Uint8Array(ctPad));

	// Step 7: MAC length footer
	polyFeed(x, lenBlock(aad.length, plaintext.length));

	// Step 8: Finalise
	x.polyFinal();
	const tagOff = x.getPolyTagOffset();
	const tag    = new Uint8Array(x.memory.buffer).slice(tagOff, tagOff + 16);

	return { ciphertext, tag };
}

/**
 * ChaCha20-Poly1305 AEAD decrypt with constant-time tag comparison (RFC 8439 §2.8).
 * Throws `AuthenticationError` on tag mismatch; never returns plaintext on failure.
 * @param x           ChaCha20 WASM exports
 * @param key         32-byte key
 * @param nonce       12-byte nonce — must match the value used to encrypt
 * @param ciphertext  Ciphertext bytes (must be ≤ WASM CHUNK_SIZE)
 * @param tag         16-byte Poly1305 tag
 * @param aad         Additional authenticated data
 * @param cipherName  Error label for `AuthenticationError` (default 'chacha20-poly1305')
 * @returns           Plaintext
 */
export function aeadDecrypt(
	x:          ChaChaExports,
	key:        Uint8Array,
	nonce:      Uint8Array,
	ciphertext: Uint8Array,
	tag:        Uint8Array,
	aad:        Uint8Array,
	cipherName  = 'chacha20-poly1305',
): Uint8Array {
	const maxChunk = x.getChunkSize();
	if (ciphertext.length > maxChunk)
		throw new RangeError(`ciphertext exceeds ${maxChunk} bytes — split into smaller chunks`);

	const mem = new Uint8Array(x.memory.buffer);

	// Compute expected tag
	mem.set(key,   x.getKeyOffset());
	mem.set(nonce, x.getChachaNonceOffset());
	x.chachaLoadKey();
	x.chachaGenPolyKey();

	x.polyInit();
	polyFeed(x, aad);
	const aadPad = (16 - aad.length % 16) % 16;
	if (aadPad > 0) polyFeed(x, new Uint8Array(aadPad));
	polyFeed(x, ciphertext);
	const ctPad = (16 - ciphertext.length % 16) % 16;
	if (ctPad > 0) polyFeed(x, new Uint8Array(ctPad));
	polyFeed(x, lenBlock(aad.length, ciphertext.length));
	x.polyFinal();

	// Constant-time tag comparison
	const tagOff      = x.getPolyTagOffset();
	const expectedTag = new Uint8Array(x.memory.buffer).slice(tagOff, tagOff + 16);
	if (!constantTimeEqual(expectedTag, tag)) {
		// Wipe the full chunk output buffer — defense-in-depth before throwing.
		const ctOff = x.getChunkCtOffset();
		mem.fill(0, ctOff, ctOff + maxChunk);
		// Also zero the 64-byte chacha block buffer — it holds keystream bytes
		// generated by chachaGenPolyKey() that would otherwise persist until
		// the next op or dispose().
		const blockOff = x.getChachaBlockOffset();
		mem.fill(0, blockOff, blockOff + 64);
		// And the 32-byte Poly1305 one-time subkey copy at POLY_KEY_OFFSET.
		// chachaGenPolyKey copies keystream[0..32] here; wiping CHACHA_BLOCK
		// zeroes the source but not this copy.
		const polyKeyOff = x.getPolyKeyOffset();
		mem.fill(0, polyKeyOff, polyKeyOff + 32);
		throw new AuthenticationError(cipherName);
	}

	// Decrypt only after authentication succeeds
	x.chachaSetCounter(1);
	x.chachaLoadKey();
	new Uint8Array(x.memory.buffer).set(ciphertext, x.getChunkPtOffset());
	x.chachaEncryptChunk_simd(ciphertext.length);
	const ptOff = x.getChunkCtOffset();
	return new Uint8Array(x.memory.buffer).slice(ptOff, ptOff + ciphertext.length);
}

// ── XChaCha20 helpers ───────────────────────────────────────────────────────

/**
 * Derive a 32-byte HChaCha20 subkey from `key` and the first 16 bytes of `nonce`.
 * Used as the inner key for XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha §2.3).
 * @param x      ChaCha20 WASM exports
 * @param key    32-byte master key
 * @param nonce  24-byte XChaCha20 nonce (only bytes 0–15 are used)
 * @returns      32-byte HChaCha20 subkey
 */
export function deriveSubkey(x: ChaChaExports, key: Uint8Array, nonce: Uint8Array): Uint8Array {
	const mem = new Uint8Array(x.memory.buffer);
	mem.set(key,                   x.getKeyOffset());
	mem.set(nonce.subarray(0, 16), x.getXChaChaNonceOffset());
	x.hchacha20();
	const off = x.getXChaChaSubkeyOffset();
	return new Uint8Array(x.memory.buffer).slice(off, off + 32);
}

/**
 * Build the inner 12-byte ChaCha20 nonce for XChaCha20 from bytes 16–23 of the
 * 24-byte XChaCha nonce (draft-irtf-cfrg-xchacha §2.3).
 * @param nonce  24-byte XChaCha20 nonce
 * @returns      12-byte inner nonce (bytes 0–3 are zero, bytes 4–11 are nonce[16:24])
 */
export function innerNonce(nonce: Uint8Array): Uint8Array {
	const n = new Uint8Array(12);
	n.set(nonce.subarray(16, 24), 4);
	return n;
}

// ── Full XChaCha20-Poly1305 ─────────────────────────────────────────────────

/**
 * XChaCha20-Poly1305 encrypt (draft-irtf-cfrg-xchacha).
 * Derives HChaCha20 subkey from `key` + nonce[0:16], then runs
 * ChaCha20-Poly1305 with a 12-byte inner nonce (nonce[16:24]).
 * @param x          ChaCha20 WASM exports
 * @param key        32-byte key
 * @param nonce      24-byte nonce
 * @param plaintext  Data to encrypt
 * @param aad        Additional authenticated data
 * @returns          Ciphertext || 16-byte Poly1305 tag
 */
export function xcEncrypt(
	x:         ChaChaExports,
	key:       Uint8Array,
	nonce:     Uint8Array,
	plaintext: Uint8Array,
	aad:       Uint8Array,
): Uint8Array {
	const subkey = deriveSubkey(x, key, nonce);
	const inner  = innerNonce(nonce);
	const { ciphertext, tag } = aeadEncrypt(x, subkey, inner, plaintext, aad);

	const result = new Uint8Array(ciphertext.length + 16);
	result.set(ciphertext);
	result.set(tag, ciphertext.length);
	return result;
}

/**
 * XChaCha20-Poly1305 decrypt (draft-irtf-cfrg-xchacha).
 * Derives HChaCha20 subkey, verifies the Poly1305 tag, then decrypts.
 * Throws `AuthenticationError` on tag mismatch.
 * @param x           ChaCha20 WASM exports
 * @param key         32-byte key
 * @param nonce       24-byte nonce — must match the value used to encrypt
 * @param ciphertext  Ciphertext || 16-byte tag (combined format from `xcEncrypt`)
 * @param aad         Additional authenticated data
 * @returns           Plaintext
 */
export function xcDecrypt(
	x:          ChaChaExports,
	key:        Uint8Array,
	nonce:      Uint8Array,
	ciphertext: Uint8Array,
	aad:        Uint8Array,
): Uint8Array {
	const ct     = ciphertext.subarray(0, ciphertext.length - 16);
	const tag    = ciphertext.subarray(ciphertext.length - 16);
	const subkey = deriveSubkey(x, key, nonce);
	const inner  = innerNonce(nonce);
	return aeadDecrypt(x, subkey, inner, ct, tag, aad, 'xchacha20-poly1305');
}
