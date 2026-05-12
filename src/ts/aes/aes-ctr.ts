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
// src/ts/aes/aes-ctr.ts
//
// AESCtr, AES-128/192/256 in CTR mode, stateful TS wrapper.
// SP 800-38A §6.5 (mode), Appendix B.1 (counter increment).
// Counter direction: 128-bit big-endian, matching the SP 800-38A §F.5
// worked examples and the canonical AES CTR convention. Configured in
// the underlying WASM (`src/asm/aes/ctr.ts`).

import { getInstance, _acquireModule, _releaseModule } from '../init.js';

/** Typed subset of the AES WASM module exports used by `AESCtr`. @internal */
interface AesCtrExports {
	memory:             WebAssembly.Memory
	getKeyOffset:       () => number
	getNonceOffset:     () => number
	getChunkPtOffset:   () => number
	getChunkCtOffset:   () => number
	getChunkSize:       () => number
	loadKey:            (n: number) => number
	resetCounter:       () => void
	encryptChunk_simd:  (n: number) => number
	decryptChunk_simd:  (n: number) => number
	wipeBuffers:        () => void
}

/** Returns the raw AES WASM export object. @internal */
function getExports(): AesCtrExports {
	return getInstance('aes').exports as unknown as AesCtrExports;
}

// ── AESCtr ──────────────────────────────────────────────────────────────────

/**
 * AES-128/192/256 in CTR mode.
 *
 * **WARNING: CTR mode is unauthenticated.** An attacker can flip ciphertext
 * bits without detection. Always pair with HMAC-SHA256 (Encrypt-then-MAC)
 * or use an authenticated cipher (`AESGCM`, `AESGCMSIV`, or `Seal` with
 * `AESGCMSIVCipher` / `SerpentCipher` / `XChaCha20Cipher`) instead.
 *
 * The constructor requires `{ dangerUnauthenticated: true }` so callers
 * cannot reach the unauthenticated path by accident, same gate as
 * `AESCbc` and `SerpentCtr`.
 *
 * The counter is 128-bit big-endian (SP 800-38A Appendix B.1 / §F.5).
 *
 * Stateful, the counter advances across `encrypt`/`decrypt` calls. Reset
 * with `setNonce()` before each new message. Holds exclusive access to the
 * `aes` WASM module from construction until `dispose()`.
 */
export class AESCtr {
	private readonly x: AesCtrExports;
	private _tok: symbol | undefined;

	constructor(opts?: { dangerUnauthenticated: true }) {
		if (!opts?.dangerUnauthenticated) {
			throw new Error(
				'leviathan-crypto: AESCtr is unauthenticated, use Seal with AESGCMSIVCipher, SerpentCipher, or XChaCha20Cipher instead. ' +
				'To use AESCtr directly, pass { dangerUnauthenticated: true }.',
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
	 * Expand `key` into the WASM key schedule. Must be called before
	 * `setNonce` / `encrypt` / `decrypt`.
	 * @param key  16, 24, or 32 bytes (AES-128 / 192 / 256)
	 */
	loadKey(key: Uint8Array): void {
		if (this._tok === undefined)
			throw new Error('AESCtr: instance has been disposed');
		if (key.length !== 16 && key.length !== 24 && key.length !== 32)
			throw new RangeError(`AES key must be 16, 24, or 32 bytes (got ${key.length})`);
		this.mem.set(key, this.x.getKeyOffset());
		if (this.x.loadKey(key.length) !== 0) {
			this.x.wipeBuffers();
			throw new Error('loadKey failed');
		}
	}

	/**
	 * Set the 128-bit initial counter block (the full IC, not a separate
	 * nonce/counter split). Resets the working counter so subsequent
	 * encrypt/decrypt calls start at this value.
	 * @param nonce  16 bytes, must be unique per (key, message)
	 */
	setNonce(nonce: Uint8Array): void {
		if (this._tok === undefined)
			throw new Error('AESCtr: instance has been disposed');
		if (nonce.length !== 16)
			throw new RangeError(`AES CTR nonce must be 16 bytes (got ${nonce.length})`);
		this.mem.set(nonce, this.x.getNonceOffset());
		this.x.resetCounter();
	}

	/**
	 * XOR `plaintext` with AES CTR keystream. The counter advances by
	 * ceil(plaintext.length / 16) blocks; counter state persists across
	 * calls until `setNonce()` resets it.
	 * @param plaintext  any length; internally chunked to WASM CHUNK_SIZE
	 * @returns          ciphertext of the same length
	 */
	encrypt(plaintext: Uint8Array): Uint8Array {
		if (this._tok === undefined)
			throw new Error('AESCtr: instance has been disposed');
		const output = new Uint8Array(plaintext.length);
		if (plaintext.length === 0) return output;
		const ptOff   = this.x.getChunkPtOffset();
		const ctOff   = this.x.getChunkCtOffset();
		const maxChunk = this.x.getChunkSize();
		for (let off = 0; off < plaintext.length; off += maxChunk) {
			const chunk = plaintext.subarray(off, Math.min(off + maxChunk, plaintext.length));
			this.mem.set(chunk, ptOff);
			const ret = this.x.encryptChunk_simd(chunk.length);
			if (ret < 0) throw new RangeError(
				`encryptChunk_simd rejected len=${chunk.length}` +
				` (WASM CHUNK_SIZE=${this.x.getChunkSize()})`,
			);
			output.set(new Uint8Array(this.x.memory.buffer).subarray(ctOff, ctOff + chunk.length), off);
		}
		return output;
	}

	/** Alias for `encrypt`, CTR mode is symmetric. */
	decrypt(ciphertext: Uint8Array): Uint8Array {
		return this.encrypt(ciphertext);
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
}
