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
// Uses the init() module cache — call serpentInit(source) before constructing.

import { getInstance, initModule, _acquireModule, _releaseModule, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';

export async function serpentInit(source: WasmSource): Promise<void> {
	return initModule('serpent', source);
}

export type { WasmSource };

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
  loadKey:          (n: number) => number
  encryptBlock:     () => void
  decryptBlock:     () => void
  resetCounter:     () => void
  setCounter:       (lo: bigint, hi: bigint) => void
  encryptChunk:     (n: number) => number
  decryptChunk:     (n: number) => number
  encryptChunk_simd: (n: number) => number
  decryptChunk_simd: (n: number) => number
  wipeBuffers:      () => void
}

function getExports(): SerpentExports {
	return getInstance('serpent').exports as unknown as SerpentExports;
}

// ── Serpent ──────────────────────────────────────────────────────────────────

export class Serpent {
	private readonly x: SerpentExports;

	constructor() {
		this.x = getExports();
	}

	loadKey(key: Uint8Array): void {
		_assertNotOwned('serpent');
		if (key.length !== 16 && key.length !== 24 && key.length !== 32)
			throw new RangeError(`key must be 16, 24, or 32 bytes (got ${key.length})`);
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(key, this.x.getKeyOffset());
		if (this.x.loadKey(key.length) !== 0) throw new Error('loadKey failed');
	}

	encryptBlock(plaintext: Uint8Array): Uint8Array {
		_assertNotOwned('serpent');
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
		_assertNotOwned('serpent');
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
		_assertNotOwned('serpent');
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
 *
 * Holds exclusive access to the `serpent` WASM module from construction
 * until `dispose()`. Constructing a second SerpentCtr/SerpentCbc/
 * SerpentCipher or any other serpent user while this instance is live
 * throws. Call `dispose()` when done.
 */
export class SerpentCtr {
	private readonly x: SerpentExports;
	private _tok: symbol | undefined;

	constructor(opts?: { dangerUnauthenticated: true }) {
		if (!opts?.dangerUnauthenticated) {
			throw new Error(
				'leviathan-crypto: SerpentCtr is unauthenticated — use Seal with SerpentCipher instead. ' +
				'To use SerpentCtr directly, pass { dangerUnauthenticated: true }.'
			);
		}
		this.x = getExports();
		this._tok = _acquireModule('serpent');
	}

	beginEncrypt(key: Uint8Array, nonce: Uint8Array): void {
		if (this._tok === undefined)
			throw new Error('SerpentCtr: instance has been disposed');
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
		if (this._tok === undefined)
			throw new Error('SerpentCtr: instance has been disposed');
		const maxChunk = this.x.getChunkSize();
		if (chunk.length > maxChunk)
			throw new RangeError(
				`chunk exceeds maximum size of ${maxChunk} bytes — split into smaller chunks`,
			);
		const mem   = new Uint8Array(this.x.memory.buffer);
		const ptOff = this.x.getChunkPtOffset();
		const ctOff = this.x.getChunkCtOffset();
		mem.set(chunk, ptOff);
		this.x.encryptChunk_simd(chunk.length);
		return mem.slice(ctOff, ctOff + chunk.length);
	}

	beginDecrypt(key: Uint8Array, nonce: Uint8Array): void {
		this.beginEncrypt(key, nonce);
	}

	decryptChunk(chunk: Uint8Array): Uint8Array {
		return this.encryptChunk(chunk);
	}

	dispose(): void {
		if (this._tok === undefined) return;
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('serpent', this._tok);
			this._tok = undefined;
		}
	}
}

// ── SerpentCbc ───────────────────────────────────────────────────────────────

export { SerpentCbc } from './serpent-cbc.js';

export { AuthenticationError } from '../errors.js';

// ── SerpentCipher re-export ───────────────────────────────────────────────────

export { SerpentCipher } from './cipher-suite.js';

// ── SerpentGenerator ─────────────────────────────────────────────────────────

export { SerpentGenerator } from './generator.js';

// ── Ready check ──────────────────────────────────────────────────────────────

export function _serpentReady(): boolean {
	try {
		getInstance('serpent');
		return true;
	} catch {
		return false;
	}
}
