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
// src/ts/serpent/serpent-cbc.ts
//
// SerpentCbc — Serpent-256 CBC + PKCS7, internal module.
// Extracted to break the cipher-suite.ts ↔ index.ts circular dependency.
// Import from here directly; index.ts re-exports for the public API surface.

import { getInstance } from '../init.js';

// Exports needed from the serpent WASM module (CBC subset)
interface SerpentExports {
	memory:              WebAssembly.Memory
	getKeyOffset:        () => number
	getChunkPtOffset:    () => number
	getChunkCtOffset:    () => number
	getChunkSize:        () => number
	getCbcIvOffset:      () => number
	loadKey:             (n: number) => number
	cbcEncryptChunk:     (n: number) => number
	cbcDecryptChunk_simd:(n: number) => number
	wipeBuffers:         () => void
}

function getExports(): SerpentExports {
	return getInstance('serpent').exports as unknown as SerpentExports;
}

// ── PKCS7 helpers ────────────────────────────────────────────────────────────

function pkcs7Pad(data: Uint8Array): Uint8Array {
	const padLen = 16 - (data.length % 16);  // 1..16
	const out    = new Uint8Array(data.length + padLen);
	out.set(data);
	out.fill(padLen, data.length);
	return out;
}

// pkcs7Strip is only called after HMAC authentication succeeds (verify-then-decrypt).
// The early throw on invalid padLen is not a padding oracle in this context —
// the HMAC check is the oracle gate and runs in constant time before this point.
// If you move this call to a pre-auth site, revisit the timing properties.
function pkcs7Strip(data: Uint8Array): Uint8Array {
	if (data.length === 0) throw new RangeError('empty ciphertext');
	const padLen = data[data.length - 1];
	if (padLen === 0 || padLen > 16)
		throw new RangeError(`invalid PKCS7 padding byte: ${padLen}`);
	if (padLen > data.length)
		throw new RangeError(`invalid PKCS7 padding: pad length ${padLen} exceeds data length ${data.length}`);
	let bad = 0;
	for (let i = data.length - padLen; i < data.length; i++)
		bad |= data[i] ^ padLen;
	if (bad !== 0) throw new RangeError('invalid PKCS7 padding');
	return data.subarray(0, data.length - padLen);
}

// ── SerpentCbc ───────────────────────────────────────────────────────────────

/**
 * Serpent-256 in CBC mode with PKCS7 padding.
 *
 * **WARNING: CBC mode is unauthenticated.** Always authenticate the output
 * with HMAC-SHA256 (Encrypt-then-MAC) or use `XChaCha20Poly1305` instead.
 */
export class SerpentCbc {
	private readonly x: SerpentExports;

	constructor(opts?: { dangerUnauthenticated: true }) {
		if (!opts?.dangerUnauthenticated) {
			throw new Error(
				'leviathan-crypto: SerpentCbc is unauthenticated — use Seal with SerpentCipher instead. ' +
				'To use SerpentCbc directly, pass { dangerUnauthenticated: true }.',
			);
		}
		this.x = getExports();
	}

	private get mem(): Uint8Array {
		return new Uint8Array(this.x.memory.buffer);
	}

	/**
   * Encrypt plaintext with Serpent-256 CBC + PKCS7 padding.
   *
   * @param key       16, 24, or 32 bytes
   * @param iv        16 bytes — must be random and unique per (key, message)
   * @param plaintext any length — PKCS7 padding applied automatically
   * @returns         ciphertext (length = ceil((plaintext.length + 1) / 16) * 16)
   */
	encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
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
   * Decrypt Serpent-256 CBC + PKCS7.
   * Throws if ciphertext length is not a non-zero multiple of 16 or PKCS7 is invalid.
   */
	decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
		if (ciphertext.length === 0 || ciphertext.length % 16 !== 0)
			throw new RangeError('ciphertext length must be a non-zero multiple of 16');
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

	dispose(): void {
		this.x.wipeBuffers();
	}

	private _loadKey(key: Uint8Array): void {
		if (key.length !== 16 && key.length !== 24 && key.length !== 32)
			throw new RangeError(`Serpent key must be 16, 24, or 32 bytes (got ${key.length})`);
		this.mem.set(key, this.x.getKeyOffset());
		this.x.loadKey(key.length);
	}

	private _setIv(iv: Uint8Array): void {
		if (iv.length !== 16)
			throw new RangeError(`CBC IV must be 16 bytes (got ${iv.length})`);
		this.mem.set(iv, this.x.getCbcIvOffset());
	}
}
