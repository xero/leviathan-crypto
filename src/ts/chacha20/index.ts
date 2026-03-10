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
// src/ts/chacha20/index.ts
//
// Public API classes for the ChaCha20 WASM module.
// Uses the init() module cache — call init('chacha20') before constructing.

import { getInstance, initModule } from '../init.js';
import type { Mode, InitOpts } from '../init.js';
import { constantTimeEqual } from '../utils.js';
import type { ChaChaExports } from './types.js';

const _embedded = () => import('../embedded/chacha.js').then(m => m.WASM_BASE64);

export async function init(
	mode: Mode = 'embedded',
	opts?: InitOpts,
): Promise<void> {
	return initModule('chacha20', _embedded, mode, opts);
}

function getExports(): ChaChaExports {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

// ── ChaCha20 ──────────────────────────────────────────────────────────────────

export class ChaCha20 {
	private readonly x: ChaChaExports;

	constructor() {
		this.x = getExports();
	}

	beginEncrypt(key: Uint8Array, nonce: Uint8Array): void {
		if (key.length !== 32)
			throw new RangeError(`ChaCha20 key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 12)
			throw new RangeError(`ChaCha20 nonce must be 12 bytes (got ${nonce.length})`);
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(key,   this.x.getKeyOffset());
		mem.set(nonce, this.x.getChachaNonceOffset());
		this.x.chachaSetCounter(1);
		this.x.chachaLoadKey();
	}

	encryptChunk(chunk: Uint8Array): Uint8Array {
		const maxChunk = this.x.getChunkSize();
		if (chunk.length > maxChunk)
			throw new RangeError(
				`chunk exceeds maximum size of ${maxChunk} bytes — split into smaller chunks`,
			);
		const mem   = new Uint8Array(this.x.memory.buffer);
		const ptOff = this.x.getChunkPtOffset();
		const ctOff = this.x.getChunkCtOffset();
		mem.set(chunk, ptOff);
		this.x.chachaEncryptChunk(chunk.length);
		return mem.slice(ctOff, ctOff + chunk.length);
	}

	beginDecrypt(key: Uint8Array, nonce: Uint8Array): void {
		this.beginEncrypt(key, nonce);
	}

	decryptChunk(chunk: Uint8Array): Uint8Array {
		return this.encryptChunk(chunk);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── Poly1305 ──────────────────────────────────────────────────────────────────

export class Poly1305 {
	private readonly x: ChaChaExports;

	constructor() {
		this.x = getExports();
	}

	mac(key: Uint8Array, msg: Uint8Array): Uint8Array {
		if (key.length !== 32)
			throw new RangeError(`Poly1305 key must be 32 bytes (got ${key.length})`);
		const mem    = new Uint8Array(this.x.memory.buffer);
		const keyOff = this.x.getPolyKeyOffset();
		const msgOff = this.x.getPolyMsgOffset();
		const tagOff = this.x.getPolyTagOffset();

		mem.set(key, keyOff);
		this.x.polyInit();

		let pos = 0;
		while (pos < msg.length) {
			const chunk = Math.min(64, msg.length - pos);
			mem.set(msg.subarray(pos, pos + chunk), msgOff);
			this.x.polyUpdate(chunk);
			pos += chunk;
		}

		this.x.polyFinal();
		return new Uint8Array(this.x.memory.buffer).slice(tagOff, tagOff + 16);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── ChaCha20Poly1305 ─────────────────────────────────────────────────────────

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
 *
 * `decrypt()` uses constant-time tag comparison — XOR-accumulate pattern,
 * no early return on mismatch. Plaintext is never returned on failure.
 */
export class ChaCha20Poly1305 {
	private readonly x: ChaChaExports;

	constructor() {
		this.x = getExports();
	}

	encrypt(
		key:       Uint8Array,
		nonce:     Uint8Array,
		plaintext: Uint8Array,
		aad:       Uint8Array = new Uint8Array(0),
	): { ciphertext: Uint8Array; tag: Uint8Array } {
		if (key.length !== 32)
			throw new RangeError(`key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 12)
			throw new RangeError(`nonce must be 12 bytes (got ${nonce.length})`);
		const maxChunk = this.x.getChunkSize();
		if (plaintext.length > maxChunk)
			throw new RangeError(`plaintext exceeds ${maxChunk} bytes — split into smaller chunks`);

		const mem = new Uint8Array(this.x.memory.buffer);

		// Step 1: Generate Poly1305 one-time key at counter=0 (RFC 8439 §2.6)
		mem.set(key,   this.x.getKeyOffset());
		mem.set(nonce, this.x.getChachaNonceOffset());
		this.x.chachaSetCounter(1);
		this.x.chachaLoadKey();
		this.x.chachaGenPolyKey();

		// Step 2: Initialise Poly1305
		this.x.polyInit();

		// Step 3: MAC AAD + pad
		this._polyFeed(aad);
		const aadPad = (16 - aad.length % 16) % 16;
		if (aadPad > 0) this._polyFeed(new Uint8Array(aadPad));

		// Step 4: Re-init ChaCha20 at counter=1
		this.x.chachaSetCounter(1);
		this.x.chachaLoadKey();

		// Step 5: Encrypt
		mem.set(plaintext, this.x.getChunkPtOffset());
		this.x.chachaEncryptChunk(plaintext.length);
		const ctOff     = this.x.getChunkCtOffset();
		const ciphertext = new Uint8Array(this.x.memory.buffer).slice(ctOff, ctOff + plaintext.length);

		// Step 6: MAC ciphertext + pad
		this._polyFeed(ciphertext);
		const ctPad = (16 - plaintext.length % 16) % 16;
		if (ctPad > 0) this._polyFeed(new Uint8Array(ctPad));

		// Step 7: MAC length footer
		this._polyFeed(this._lenBlock(aad.length, plaintext.length));

		// Step 8: Finalise
		this.x.polyFinal();
		const tagOff = this.x.getPolyTagOffset();
		const tag    = new Uint8Array(this.x.memory.buffer).slice(tagOff, tagOff + 16);

		return { ciphertext, tag };
	}

	decrypt(
		key:        Uint8Array,
		nonce:      Uint8Array,
		ciphertext: Uint8Array,
		tag:        Uint8Array,
		aad:        Uint8Array = new Uint8Array(0),
	): Uint8Array {
		if (key.length !== 32)
			throw new RangeError(`key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 12)
			throw new RangeError(`nonce must be 12 bytes (got ${nonce.length})`);
		if (tag.length !== 16)
			throw new RangeError(`tag must be 16 bytes (got ${tag.length})`);
		const maxChunk = this.x.getChunkSize();
		if (ciphertext.length > maxChunk)
			throw new RangeError(`ciphertext exceeds ${maxChunk} bytes — split into smaller chunks`);

		const mem = new Uint8Array(this.x.memory.buffer);

		// Compute expected tag
		mem.set(key,   this.x.getKeyOffset());
		mem.set(nonce, this.x.getChachaNonceOffset());
		this.x.chachaSetCounter(1);
		this.x.chachaLoadKey();
		this.x.chachaGenPolyKey();

		this.x.polyInit();
		this._polyFeed(aad);
		const aadPad = (16 - aad.length % 16) % 16;
		if (aadPad > 0) this._polyFeed(new Uint8Array(aadPad));
		this._polyFeed(ciphertext);
		const ctPad = (16 - ciphertext.length % 16) % 16;
		if (ctPad > 0) this._polyFeed(new Uint8Array(ctPad));
		this._polyFeed(this._lenBlock(aad.length, ciphertext.length));
		this.x.polyFinal();

		// Constant-time tag comparison
		const tagOff      = this.x.getPolyTagOffset();
		const expectedTag = new Uint8Array(this.x.memory.buffer).slice(tagOff, tagOff + 16);
		if (!constantTimeEqual(expectedTag, tag))
			throw new Error('ChaCha20Poly1305: authentication failed');

		// Decrypt only after authentication succeeds
		this.x.chachaSetCounter(1);
		this.x.chachaLoadKey();
		new Uint8Array(this.x.memory.buffer).set(ciphertext, this.x.getChunkPtOffset());
		this.x.chachaEncryptChunk(ciphertext.length);
		const ptOff = this.x.getChunkCtOffset();
		return new Uint8Array(this.x.memory.buffer).slice(ptOff, ptOff + ciphertext.length);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}

	private _polyFeed(data: Uint8Array): void {
		if (data.length === 0) return;
		const mem    = new Uint8Array(this.x.memory.buffer);
		const msgOff = this.x.getPolyMsgOffset();
		let pos = 0;
		while (pos < data.length) {
			const chunk = Math.min(64, data.length - pos);
			mem.set(data.subarray(pos, pos + chunk), msgOff);
			this.x.polyUpdate(chunk);
			pos += chunk;
		}
	}

	private _lenBlock(aadLen: number, ctLen: number): Uint8Array {
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
}

// ── XChaCha20Poly1305 ────────────────────────────────────────────────────────

/**
 * XChaCha20-Poly1305 AEAD (IETF draft-irtf-cfrg-xchacha).
 *
 * Recommended authenticated encryption primitive for most use cases.
 * Uses a 24-byte nonce — safe for random generation via crypto.getRandomValues.
 *
 * Pure TypeScript composition over ChaCha20Poly1305 — no additional WASM exports.
 * `decrypt()` constant-time guarantee is inherited from ChaCha20Poly1305.
 */
export class XChaCha20Poly1305 {
	private readonly x:     ChaChaExports;
	private readonly inner: ChaCha20Poly1305;

	constructor() {
		this.x     = getExports();
		this.inner = new ChaCha20Poly1305();
	}

	encrypt(
		key:       Uint8Array,
		nonce:     Uint8Array,
		plaintext: Uint8Array,
		aad:       Uint8Array = new Uint8Array(0),
	): Uint8Array {
		if (key.length !== 32)
			throw new RangeError(`key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 24)
			throw new RangeError(`XChaCha20 nonce must be 24 bytes (got ${nonce.length})`);

		const subkey     = this._deriveSubkey(key, nonce);
		const innerNonce = this._innerNonce(nonce);
		const { ciphertext, tag } = this.inner.encrypt(subkey, innerNonce, plaintext, aad);

		const result = new Uint8Array(ciphertext.length + 16);
		result.set(ciphertext);
		result.set(tag, ciphertext.length);
		return result;
	}

	decrypt(
		key:        Uint8Array,
		nonce:      Uint8Array,
		ciphertext: Uint8Array,
		aad:        Uint8Array = new Uint8Array(0),
	): Uint8Array {
		if (key.length !== 32)
			throw new RangeError(`key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 24)
			throw new RangeError(`XChaCha20 nonce must be 24 bytes (got ${nonce.length})`);
		if (ciphertext.length < 16)
			throw new RangeError(`ciphertext too short — must include 16-byte tag (got ${ciphertext.length})`);

		const ct         = ciphertext.subarray(0, ciphertext.length - 16);
		const tag        = ciphertext.subarray(ciphertext.length - 16);
		const subkey     = this._deriveSubkey(key, nonce);
		const innerNonce = this._innerNonce(nonce);
		return this.inner.decrypt(subkey, innerNonce, ct, tag, aad);
	}

	dispose(): void {
		this.inner.dispose();
		this.x.wipeBuffers();
	}

	private _deriveSubkey(key: Uint8Array, nonce: Uint8Array): Uint8Array {
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(key,                   this.x.getKeyOffset());
		mem.set(nonce.subarray(0, 16), this.x.getXChaChaNonceOffset());
		this.x.hchacha20();
		const off = this.x.getXChaChaSubkeyOffset();
		return new Uint8Array(this.x.memory.buffer).slice(off, off + 32);
	}

	private _innerNonce(nonce: Uint8Array): Uint8Array {
		const n = new Uint8Array(12);
		n.set(nonce.subarray(16, 24), 4);
		return n;
	}
}

// ── Ready check ──────────────────────────────────────────────────────────────

export function _chachaReady(): boolean {
	try {
		getInstance('chacha20');
		return true;
	} catch {
		return false;
	}
}
