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
// src/ts/aes/aes-cbc.ts
//
// AESCbc, AES-128/192/256 CBC + PKCS7, stateful TS wrapper.
// SP 800-38A §6.2 (mode), RFC 5652 §6.3 (PKCS7 padding).
// Mirrors `src/ts/serpent/serpent-cbc.ts` exactly in shape; only the
// underlying WASM module and the PKCS7 import path differ.

import { getInstance, _acquireModule, _releaseModule } from '../init.js';
import { pkcs7Pad, pkcs7Strip, PKCS7_INVALID } from '../shared/pkcs7.js';

/** Typed subset of the AES WASM module exports used by `AESCbc`. @internal */
interface AesCbcExports {
	memory:               WebAssembly.Memory
	getKeyOffset:         () => number
	getChunkPtOffset:     () => number
	getChunkCtOffset:     () => number
	getChunkSize:         () => number
	getCbcIvOffset:       () => number
	loadKey:              (n: number) => number
	cbcEncryptChunk:      (n: number) => number
	cbcDecryptChunk_simd: (n: number) => number
	wipeBuffers:          () => void
}

/** Returns the raw AES WASM export object. @internal */
function getExports(): AesCbcExports {
	return getInstance('aes').exports as unknown as AesCbcExports;
}

// ── AESCbc ──────────────────────────────────────────────────────────────────

/**
 * AES-128/192/256 in CBC mode with PKCS7 padding.
 *
 * **WARNING: CBC mode is unauthenticated.** Always authenticate the output
 * with HMAC-SHA256 (Encrypt-then-MAC) or use an authenticated cipher
 * (`XChaCha20Poly1305`, `Seal` with `SerpentCipher`) instead.
 *
 * Holds exclusive access to the `aes` WASM module from construction until
 * `dispose()`. Constructing a second AES-using class while this instance
 * is live throws. Call `dispose()` when done.
 */
export class AESCbc {
	private readonly x: AesCbcExports;
	private _tok: symbol | undefined;

	constructor(opts?: { dangerUnauthenticated: true }) {
		if (!opts?.dangerUnauthenticated) {
			throw new Error(
				'leviathan-crypto: AESCbc is unauthenticated, use Seal with SerpentCipher or XChaCha20Cipher instead. ' +
				'To use AESCbc directly, pass { dangerUnauthenticated: true }.',
			);
		}
		this.x = getExports();
		this._tok = _acquireModule('aes');
	}

	/** View over WASM linear memory. Rebind on every access, memory can be detached after grow. @internal */
	private get mem(): Uint8Array {
		return new Uint8Array(this.x.memory.buffer);
	}

	/**
	 * Encrypt plaintext with AES CBC + PKCS7 padding.
	 *
	 * @param key       16, 24, or 32 bytes (AES-128 / 192 / 256)
	 * @param iv        16 bytes, must be random and unique per (key, message)
	 * @param plaintext any length, PKCS7 padding applied automatically
	 * @returns         ciphertext (length = ceil((plaintext.length + 1) / 16) * 16)
	 */
	encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
		if (this._tok === undefined)
			throw new Error('AESCbc: instance has been disposed');
		this._loadKey(key);
		this._setIv(iv);
		const padded = pkcs7Pad(plaintext);
		const output = new Uint8Array(padded.length);
		const ptOff  = this.x.getChunkPtOffset();
		const ctOff  = this.x.getChunkCtOffset();
		const maxChunk = this.x.getChunkSize();
		for (let off = 0; off < padded.length; off += maxChunk) {
			const chunk = padded.subarray(off, Math.min(off + maxChunk, padded.length));
			this.mem.set(chunk, ptOff);
			const ret = this.x.cbcEncryptChunk(chunk.length);
			if (ret < 0) throw new RangeError(
				`cbcEncryptChunk rejected len=${chunk.length}` +
				` (WASM CHUNK_SIZE=${this.x.getChunkSize()})`,
			);
			output.set(new Uint8Array(this.x.memory.buffer).subarray(ctOff, ctOff + chunk.length), off);
		}
		return output;
	}

	/**
	 * Decrypt AES CBC + PKCS7.
	 *
	 * All failure modes, empty input, non-multiple-of-16 length, and any
	 * PKCS7 validation failure, throw the same generic `RangeError` with
	 * message `'invalid ciphertext'`. Padding validation runs branch-free
	 * over the last 16 bytes regardless of where the mismatch is, closing
	 * the Vaudenay 2002 padding-oracle surface for callers using
	 * `{ dangerUnauthenticated: true }` without an outer HMAC.
	 */
	decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
		if (this._tok === undefined)
			throw new Error('AESCbc: instance has been disposed');
		if (ciphertext.length === 0 || ciphertext.length % 16 !== 0)
			throw new RangeError(PKCS7_INVALID);
		this._loadKey(key);
		this._setIv(iv);
		const output = new Uint8Array(ciphertext.length);
		const ctOff  = this.x.getChunkCtOffset();
		const ptOff  = this.x.getChunkPtOffset();
		const maxChunk = this.x.getChunkSize();
		for (let off = 0; off < ciphertext.length; off += maxChunk) {
			const chunk = ciphertext.subarray(off, Math.min(off + maxChunk, ciphertext.length));
			this.mem.set(chunk, ctOff);
			const ret = this.x.cbcDecryptChunk_simd(chunk.length);
			if (ret < 0) throw new RangeError(
				`cbcDecryptChunk_simd rejected len=${chunk.length}` +
				` (WASM CHUNK_SIZE=${this.x.getChunkSize()})`,
			);
			output.set(new Uint8Array(this.x.memory.buffer).subarray(ptOff, ptOff + chunk.length), off);
		}
		return pkcs7Strip(output);
	}

	/** Wipe WASM state and release exclusive module access. Idempotent. */
	dispose(): void {
		if (this._tok === undefined) return;
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('aes', this._tok);
			this._tok = undefined;
		}
	}

	/**
	 * Validate and load `key` into the WASM key schedule.
	 * @param key  16, 24, or 32 bytes
	 * @internal
	 */
	private _loadKey(key: Uint8Array): void {
		if (key.length !== 16 && key.length !== 24 && key.length !== 32)
			throw new RangeError(`AES key must be 16, 24, or 32 bytes (got ${key.length})`);
		this.mem.set(key, this.x.getKeyOffset());
		if (this.x.loadKey(key.length) !== 0) {
			this.x.wipeBuffers();
			throw new Error('AESCbc: loadKey failed');
		}
	}

	/**
	 * Write `iv` into the WASM CBC IV buffer.
	 * @param iv  16 bytes
	 * @internal
	 */
	private _setIv(iv: Uint8Array): void {
		if (iv.length !== 16)
			throw new RangeError(`CBC IV must be 16 bytes (got ${iv.length})`);
		this.mem.set(iv, this.x.getCbcIvOffset());
	}
}
