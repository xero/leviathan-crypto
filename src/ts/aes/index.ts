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
// src/ts/aes/index.ts
//
// Public API classes for the AES WASM module.
// AES-128/192/256 supported.

import { getInstance, initModule, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';

/**
 * Load and initialise the AES WASM module from `source`.
 * Must be called before constructing any AES class.
 * @param source  WASM binary — gzip+base64 string, URL, ArrayBuffer, Uint8Array,
 *                pre-compiled WebAssembly.Module, Response, or Promise<Response>
 */
export async function aesInit(source: WasmSource): Promise<void> {
	return initModule('aes', source);
}

export type { WasmSource };
export { isInitialized } from '../init.js';

/** Typed subset of the AES WASM module exports used by this file. @internal */
interface AesExports {
	memory:                     WebAssembly.Memory
	getKeyOffset:               () => number
	getBlockPtOffset:           () => number
	getBlockCtOffset:           () => number
	getBlockPt8xOffset:         () => number
	getBlockCt8xOffset:         () => number
	getRoundKeysOffset:         () => number
	getBitslicedStateOffset:    () => number
	getCanrightScratchOffset:   () => number
	getKeyScheduleScratchOffset:() => number
	getInvRoundKeysOffset:      () => number
	getChunkPtOffset:           () => number
	getChunkCtOffset:           () => number
	getChunkSize:               () => number
	loadKey:                    (n: number) => number
	encryptBlock:               () => void
	encryptBlock_8x:            () => void
	decryptBlock:               () => void
	decryptBlock_8x:            () => void
	wipeBuffers:                () => void
	// Debug-only exports used by gate tests.
	transposeRoundTrip:         () => void
	sboxRoundTrip:              () => void
	singleRound:                (roundIdx: number) => void
}

/** Returns the raw AES WASM export object. @internal */
function getExports(): AesExports {
	return getInstance('aes').exports as unknown as AesExports;
}

// ── AES ─────────────────────────────────────────────────────────────────────

/**
 * Low-level AES block cipher — raw ECB encrypt + decrypt.
 *
 * AES-128/192/256 supported. `loadKey` accepts 16, 24, or 32 byte keys;
 * Nr (10, 12, or 14) is derived and persisted in WASM memory between
 * `loadKey` and the cipher calls.
 *
 * Decrypt uses the FIPS 197 §5.3.5 Equivalent Inverse Cipher: the round
 * loop mirrors encrypt, and round keys 1..Nr-1 are pre-transformed by
 * InvMixColumns inside `loadKey`.
 *
 * Atomic (stateless): each method call is independent. Does not hold
 * exclusive module access. Call `dispose()` after use to wipe WASM key
 * material.
 */
export class AES {
	private readonly x: AesExports;

	constructor() {
		this.x = getExports();
	}

	/**
	 * Expand `key` into the WASM key schedule (forward + EqInvCipher
	 * inverse round keys). Must be called before `encryptBlock` or
	 * `decryptBlock`.
	 * @param key  16, 24, or 32 bytes (AES-128 / 192 / 256)
	 */
	loadKey(key: Uint8Array): void {
		_assertNotOwned('aes');
		if (key.length !== 16 && key.length !== 24 && key.length !== 32)
			throw new RangeError(
				`AES.loadKey: key must be 16, 24, or 32 bytes (got ${key.length})`,
			);
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(key, this.x.getKeyOffset());
		if (this.x.loadKey(key.length) !== 0) throw new Error('loadKey failed');
	}

	/**
	 * Encrypt one 128-bit block with the previously loaded key schedule.
	 * FIPS 197 §5.1 Algorithm 1, Nr ∈ {10, 12, 14}.
	 * @param plaintext  16-byte plaintext block
	 * @returns          16-byte ciphertext block
	 */
	encryptBlock(plaintext: Uint8Array): Uint8Array {
		_assertNotOwned('aes');
		if (plaintext.length !== 16)
			throw new RangeError(`block must be 16 bytes (got ${plaintext.length})`);
		const mem   = new Uint8Array(this.x.memory.buffer);
		const ptOff = this.x.getBlockPtOffset();
		const ctOff = this.x.getBlockCtOffset();
		mem.set(plaintext, ptOff);
		this.x.encryptBlock();
		return mem.slice(ctOff, ctOff + 16);
	}

	/**
	 * Decrypt one 128-bit block with the previously loaded key schedule.
	 * FIPS 197 §5.3.5 Equivalent Inverse Cipher, Nr ∈ {10, 12, 14}.
	 * @param ciphertext  16-byte ciphertext block
	 * @returns           16-byte plaintext block
	 */
	decryptBlock(ciphertext: Uint8Array): Uint8Array {
		_assertNotOwned('aes');
		if (ciphertext.length !== 16)
			throw new RangeError(`block must be 16 bytes (got ${ciphertext.length})`);
		const mem   = new Uint8Array(this.x.memory.buffer);
		const ptOff = this.x.getBlockPtOffset();
		const ctOff = this.x.getBlockCtOffset();
		mem.set(ciphertext, ptOff);
		this.x.decryptBlock();
		return mem.slice(ctOff, ctOff + 16);
	}

	/** Wipe WASM key material and intermediate buffers. */
	dispose(): void {
		_assertNotOwned('aes');
		this.x.wipeBuffers();
	}
}

// ── CBC + CTR + GCM mode wrappers ───────────────────────────────────────────

export { AESCbc } from './aes-cbc.js';
export { AESCtr } from './aes-ctr.js';
export { AESGCM } from './aes-gcm.js';
