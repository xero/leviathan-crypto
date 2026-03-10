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

// ── Ready check ──────────────────────────────────────────────────────────────

export function _chachaReady(): boolean {
	try {
		getInstance('chacha20');
		return true;
	} catch {
		return false;
	}
}
