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
// src/ts/serpent/index.ts
//
// Public API classes for the Serpent-256 WASM module.
// Uses the init() module cache — call init('serpent') before constructing.

import { getInstance, initModule } from '../init.js';
import type { Mode, InitOpts } from '../init.js';

const _embedded = () => import('../embedded/serpent.js').then(m => m.WASM_BASE64);

export async function serpentInit(
	mode: Mode = 'embedded',
	opts?: InitOpts,
): Promise<void> {
	return initModule('serpent', _embedded, mode, opts);
}

// Exports needed from the serpent WASM module
interface SerpentExports {
  memory:           WebAssembly.Memory
  getKeyOffset:     () => number
  getBlockPtOffset: () => number
  getBlockCtOffset: () => number
  getNonceOffset:   () => number
  getCounterOffset: () => number
  getChunkPtOffset: () => number
  getChunkCtOffset: () => number
  getChunkSize:     () => number
  getCbcIvOffset:   () => number
  loadKey:          (n: number) => number
  encryptBlock:     () => void
  decryptBlock:     () => void
  resetCounter:     () => void
  setCounter:       (lo: bigint, hi: bigint) => void
  encryptChunk:     (n: number) => number
  decryptChunk:     (n: number) => number
  cbcEncryptChunk:  (n: number) => number
  cbcDecryptChunk:  (n: number) => number
  encryptChunk_simd: (n: number) => number
  decryptChunk_simd: (n: number) => number
  cbcDecryptChunk_simd: (n: number) => number
  wipeBuffers:      () => void
}

function getExports(): SerpentExports {
	return getInstance('serpent').exports as unknown as SerpentExports;
}

// Lazy SIMD capability detection (computed once)
let _simd: boolean | null = null;
function hasSIMD(): boolean {
	if (_simd !== null) return _simd;
	if (typeof WebAssembly === 'undefined' || typeof WebAssembly.validate !== 'function') {
		_simd = false;
		return _simd;
	}
	// Minimal WASM module using v128 — validates iff SIMD is supported
	try {
		_simd = WebAssembly.validate(new Uint8Array([
			0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123,
			3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253, 15, 253, 98, 11,
		]));
	} catch {
		_simd = false;
	}
	return _simd;
}

// ── Serpent ──────────────────────────────────────────────────────────────────

export class Serpent {
	private readonly x: SerpentExports;

	constructor() {
		this.x = getExports();
	}

	loadKey(key: Uint8Array): void {
		if (key.length !== 16 && key.length !== 24 && key.length !== 32)
			throw new RangeError(`key must be 16, 24, or 32 bytes (got ${key.length})`);
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(key, this.x.getKeyOffset());
		if (this.x.loadKey(key.length) !== 0) throw new Error('loadKey failed');
	}

	encryptBlock(plaintext: Uint8Array): Uint8Array {
		if (plaintext.length !== 16)
			throw new RangeError(`block must be 16 bytes (got ${plaintext.length})`);
		const mem   = new Uint8Array(this.x.memory.buffer);
		const ptOff = this.x.getBlockPtOffset();
		const ctOff = this.x.getBlockCtOffset();
		mem.set(plaintext, ptOff);
		this.x.encryptBlock();
		return mem.slice(ctOff, ctOff + 16);
	}

	decryptBlock(ciphertext: Uint8Array): Uint8Array {
		if (ciphertext.length !== 16)
			throw new RangeError(`block must be 16 bytes (got ${ciphertext.length})`);
		const mem   = new Uint8Array(this.x.memory.buffer);
		const ptOff = this.x.getBlockPtOffset();
		const ctOff = this.x.getBlockCtOffset();
		mem.set(ciphertext, ctOff);
		this.x.decryptBlock();
		return mem.slice(ptOff, ptOff + 16);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── SerpentCtr ───────────────────────────────────────────────────────────────

/**
 * Serpent-256 in CTR mode.
 *
 * **WARNING: CTR mode is unauthenticated.** An attacker can flip ciphertext
 * bits without detection. Always pair with HMAC-SHA256 (Encrypt-then-MAC)
 * or use `XChaCha20Poly1305` instead.
 */
export class SerpentCtr {
	private readonly x: SerpentExports;

	constructor(opts?: { dangerUnauthenticated: true }) {
		if (!opts?.dangerUnauthenticated) {
			throw new Error(
				'leviathan-crypto: SerpentCtr is unauthenticated — use SerpentSeal instead. ' +
				'To use SerpentCtr directly, pass { dangerUnauthenticated: true }.'
			);
		}
		this.x = getExports();
	}

	beginEncrypt(key: Uint8Array, nonce: Uint8Array): void {
		if (key.length !== 16 && key.length !== 24 && key.length !== 32)
			throw new RangeError('key must be 16, 24, or 32 bytes');
		if (nonce.length !== 16)
			throw new RangeError(`nonce must be 16 bytes (got ${nonce.length})`);
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(key,   this.x.getKeyOffset());
		mem.set(nonce, this.x.getNonceOffset());
		this.x.loadKey(key.length);
		this.x.resetCounter();
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
		const fn = hasSIMD() ? this.x.encryptChunk_simd : this.x.encryptChunk;
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

// ── PKCS7 helpers ────────────────────────────────────────────────────────────

function pkcs7Pad(data: Uint8Array): Uint8Array {
	const padLen = 16 - (data.length % 16);  // 1..16
	const out    = new Uint8Array(data.length + padLen);
	out.set(data);
	out.fill(padLen, data.length);
	return out;
}

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
				'leviathan-crypto: SerpentCbc is unauthenticated — use SerpentSeal instead. ' +
				'To use SerpentCbc directly, pass { dangerUnauthenticated: true }.'
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
		const maxChunk = 65536;
		for (let off = 0; off < padded.length; off += maxChunk) {
			const chunk = padded.subarray(off, Math.min(off + maxChunk, padded.length));
			this.mem.set(chunk, ptOff);
			this.x.cbcEncryptChunk(chunk.length);
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
		const maxChunk = 65536;
		for (let off = 0; off < ciphertext.length; off += maxChunk) {
			const chunk = ciphertext.subarray(off, Math.min(off + maxChunk, ciphertext.length));
			this.mem.set(chunk, ctOff);
			const fn = hasSIMD() ? this.x.cbcDecryptChunk_simd : this.x.cbcDecryptChunk;
			fn(chunk.length);
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

// ── SerpentSeal re-export ─────────────────────────────────────────────────────

export { SerpentSeal } from './seal.js';

// ── SerpentStream re-export ───────────────────────────────────────────────────

export { SerpentStream, sealChunk, openChunk } from './stream.js';

// ── SerpentStreamPool re-export ───────────────────────────────────────────────

export { SerpentStreamPool } from './stream-pool.js';
export type { StreamPoolOpts } from './stream-pool.js';

// ── SerpentStreamSealer / SerpentStreamOpener re-export ───────────────────────

export { SerpentStreamSealer, SerpentStreamOpener } from './stream-sealer.js';

// ── SerpentStreamEncoder / SerpentStreamDecoder re-export ─────────────────────

export { SerpentStreamEncoder, SerpentStreamDecoder } from './stream-encoder.js';

// ── Ready check ──────────────────────────────────────────────────────────────

export function _serpentReady(): boolean {
	try {
		getInstance('serpent');
		return true;
	} catch {
		return false;
	}
}
