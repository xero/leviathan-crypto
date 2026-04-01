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
import type { ChaChaExports } from './types.js';
import { aeadEncrypt, aeadDecrypt, xcEncrypt, xcDecrypt } from './ops.js';
import { hasSIMD, randomBytes, wipe } from '../utils.js';

const _embedded = () => import('../embedded/chacha20.js').then(m => m.WASM_GZ_BASE64);

export async function chacha20Init(
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
		const fn = hasSIMD() ? this.x.chachaEncryptChunk_simd : this.x.chachaEncryptChunk;
		fn(chunk.length);
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
		return aeadEncrypt(this.x, key, nonce, plaintext, aad);
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
		return aeadDecrypt(this.x, key, nonce, ciphertext, tag, aad);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── XChaCha20Poly1305 ────────────────────────────────────────────────────────

/**
 * XChaCha20-Poly1305 AEAD (IETF draft-irtf-cfrg-xchacha).
 *
 * Recommended authenticated encryption primitive for most use cases.
 * Uses a 24-byte nonce — safe for random generation via crypto.getRandomValues.
 *
 * `decrypt()` constant-time guarantee is inherited from the inner AEAD path.
 */
export class XChaCha20Poly1305 {
	private readonly x: ChaChaExports;

	constructor() {
		this.x = getExports();
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
		return xcEncrypt(this.x, key, nonce, plaintext, aad);
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
		return xcDecrypt(this.x, key, nonce, ciphertext, aad);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── XChaCha20Seal ────────────────────────────────────────────────────────────

/**
 * XChaCha20-Poly1305 AEAD with bound key and automatic nonce management.
 * Implements the AEAD interface — encrypt()/decrypt() require only plaintext
 * and optional AAD. Each encrypt() call generates a fresh 24-byte random nonce.
 *
 * Wire format: nonce(24) || ciphertext || tag(16)
 *
 * Use this when you want the simplest correct API and do not need to manage
 * nonces yourself. For protocol interop requiring explicit nonce control,
 * use XChaCha20Poly1305 directly.
 */
export class XChaCha20Seal {
	private readonly _x:   ChaChaExports;
	private readonly _key: Uint8Array;

	constructor(key: Uint8Array) {
		if (!_chachaReady())
			throw new Error('leviathan-crypto: call init([\'chacha20\']) before using XChaCha20Seal');
		if (key.length !== 32)
			throw new RangeError(`XChaCha20Seal key must be 32 bytes (got ${key.length})`);
		this._x   = getExports();
		this._key = key.slice();
	}

	// _nonce: test seam only — inject a fixed nonce for deterministic KAT vectors
	encrypt(plaintext: Uint8Array, aad: Uint8Array = new Uint8Array(0), _nonce?: Uint8Array): Uint8Array {
		const nonce = (_nonce && _nonce.length === 24) ? _nonce : randomBytes(24);
		const sealed = xcEncrypt(this._x, this._key, nonce, plaintext, aad);
		// Prepend nonce to sealed output (ciphertext || tag)
		const out = new Uint8Array(24 + sealed.length);
		out.set(nonce, 0);
		out.set(sealed, 24);
		return out;
	}

	decrypt(ciphertext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
		if (ciphertext.length < 40)
			throw new RangeError(
				`XChaCha20Seal ciphertext too short — need nonce(24)+tag(16)=40 bytes minimum (got ${ciphertext.length})`,
			);
		const nonce   = ciphertext.subarray(0, 24);
		const payload = ciphertext.subarray(24);
		return xcDecrypt(this._x, this._key, nonce, payload, aad);
	}

	dispose(): void {
		wipe(this._key);
		this._x.wipeBuffers();
	}
}

export { XChaCha20StreamSealer, XChaCha20StreamOpener } from './stream-sealer.js';

// ── Ready check ──────────────────────────────────────────────────────────────

export function _chachaReady(): boolean {
	try {
		getInstance('chacha20');
		return true;
	} catch {
		return false;
	}
}
