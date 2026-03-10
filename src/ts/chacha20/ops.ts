// src/ts/chacha20/ops.ts
//
// Raw XChaCha20-Poly1305 operations — standalone functions that take
// ChaChaExports explicitly. Used by both the class wrappers (index.ts)
// and the pool worker (pool.worker.ts), eliminating duplication.

import type { ChaChaExports } from './types.js';
import { constantTimeEqual } from '../utils.js';

// ── Module-private helpers ───────────────────────────────────────────────────

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

function lenBlock(aadLen: number, ctLen: number): Uint8Array {
	const b = new Uint8Array(16);
	let n = aadLen;
	for (let i = 0; i < 4; i++) {
		b[i]     = n & 0xff; n >>>= 8;
	}
	n = ctLen;
	for (let i = 0; i < 4; i++) {
		b[8 + i] = n & 0xff; n >>>= 8;
	}
	return b;
}

// ── Inner AEAD (12-byte nonce) ───────────────────────────────────────────────

/** ChaCha20-Poly1305 AEAD encrypt (RFC 8439 §2.8). */
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
	x.chachaSetCounter(1);
	x.chachaLoadKey();
	x.chachaGenPolyKey();

	// Step 2: Initialise Poly1305
	x.polyInit();

	// Step 3: MAC AAD + pad
	polyFeed(x, aad);
	const aadPad = (16 - aad.length % 16) % 16;
	if (aadPad > 0) polyFeed(x, new Uint8Array(aadPad));

	// Step 4: Re-init ChaCha20 at counter=1
	x.chachaSetCounter(1);
	x.chachaLoadKey();

	// Step 5: Encrypt
	mem.set(plaintext, x.getChunkPtOffset());
	x.chachaEncryptChunk(plaintext.length);
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

/** ChaCha20-Poly1305 AEAD decrypt (RFC 8439 §2.8). Constant-time tag comparison. */
export function aeadDecrypt(
	x:          ChaChaExports,
	key:        Uint8Array,
	nonce:      Uint8Array,
	ciphertext: Uint8Array,
	tag:        Uint8Array,
	aad:        Uint8Array,
): Uint8Array {
	const maxChunk = x.getChunkSize();
	if (ciphertext.length > maxChunk)
		throw new RangeError(`ciphertext exceeds ${maxChunk} bytes — split into smaller chunks`);

	const mem = new Uint8Array(x.memory.buffer);

	// Compute expected tag
	mem.set(key,   x.getKeyOffset());
	mem.set(nonce, x.getChachaNonceOffset());
	x.chachaSetCounter(1);
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
	if (!constantTimeEqual(expectedTag, tag))
		throw new Error('ChaCha20Poly1305: authentication failed');

	// Decrypt only after authentication succeeds
	x.chachaSetCounter(1);
	x.chachaLoadKey();
	new Uint8Array(x.memory.buffer).set(ciphertext, x.getChunkPtOffset());
	x.chachaEncryptChunk(ciphertext.length);
	const ptOff = x.getChunkCtOffset();
	return new Uint8Array(x.memory.buffer).slice(ptOff, ptOff + ciphertext.length);
}

// ── XChaCha20 helpers ────────────────────────────────────────────────────────

/** HChaCha20 subkey derivation — first 16 bytes of nonce. */
export function deriveSubkey(x: ChaChaExports, key: Uint8Array, nonce: Uint8Array): Uint8Array {
	const mem = new Uint8Array(x.memory.buffer);
	mem.set(key,                   x.getKeyOffset());
	mem.set(nonce.subarray(0, 16), x.getXChaChaNonceOffset());
	x.hchacha20();
	const off = x.getXChaChaSubkeyOffset();
	return new Uint8Array(x.memory.buffer).slice(off, off + 32);
}

/** Build inner 12-byte nonce from bytes 16–23 of XChaCha nonce. */
export function innerNonce(nonce: Uint8Array): Uint8Array {
	const n = new Uint8Array(12);
	n.set(nonce.subarray(16, 24), 4);
	return n;
}

// ── Full XChaCha20-Poly1305 ──────────────────────────────────────────────────

/** XChaCha20-Poly1305 encrypt → ciphertext || tag. */
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

/** XChaCha20-Poly1305 decrypt → plaintext (throws on auth failure). */
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
	return aeadDecrypt(x, subkey, inner, ct, tag, aad);
}
