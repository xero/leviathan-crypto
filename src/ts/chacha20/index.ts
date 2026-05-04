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
// Uses the init() module cache — call chacha20Init(source) before constructing.

import { getInstance, initModule, _acquireModule, _releaseModule, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import type { ChaChaExports } from './types.js';
import { aeadEncrypt, aeadDecrypt, xcEncrypt, xcDecrypt } from './ops.js';
import { AuthenticationError } from '../errors.js';

export { AuthenticationError };

/**
 * Load and initialise the ChaCha20 WASM module from `source`.
 * Must be called before constructing any ChaCha20 class.
 * @param source  WASM binary — gzip+base64 string, URL, ArrayBuffer, Uint8Array,
 *                pre-compiled WebAssembly.Module, Response, or Promise<Response>
 */
export async function chacha20Init(source: WasmSource): Promise<void> {
	return initModule('chacha20', source);
}

export type { WasmSource };
export { isInitialized } from '../init.js';

/** Returns the raw chacha20 WASM export object. @internal */
function getExports(): ChaChaExports {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

// ── ChaCha20 ────────────────────────────────────────────────────────────────

/**
 * Raw ChaCha20 stream cipher (RFC 8439 §2.4).
 *
 * Holds exclusive access to the `chacha20` WASM module from construction
 * until `dispose()`. Constructing a second ChaCha20 or any other chacha20
 * user while this instance is live throws. Call `dispose()` when done.
 */
export class ChaCha20 {
	private readonly x: ChaChaExports;
	private _tok: symbol | undefined;

	constructor() {
		this.x = getExports();
		this._tok = _acquireModule('chacha20');
	}

	/**
	 * Load key and nonce into WASM state and set the block counter to 1.
	 * Must be called before each message (RFC 8439 §2.4).
	 * @param key    32 bytes
	 * @param nonce  12 bytes — must be unique per (key, message)
	 */
	beginEncrypt(key: Uint8Array, nonce: Uint8Array): void {
		if (this._tok === undefined)
			throw new Error('ChaCha20: instance has been disposed');
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

	/**
	 * XOR `chunk` with the next keystream block(s). Counter advances automatically.
	 * @param chunk  Plaintext chunk — must not exceed WASM CHUNK_SIZE
	 * @returns      Ciphertext of the same length
	 */
	encryptChunk(chunk: Uint8Array): Uint8Array {
		if (this._tok === undefined)
			throw new Error('ChaCha20: instance has been disposed');
		const maxChunk = this.x.getChunkSize();
		if (chunk.length > maxChunk)
			throw new RangeError(
				`chunk exceeds maximum size of ${maxChunk} bytes — split into smaller chunks`,
			);
		const mem   = new Uint8Array(this.x.memory.buffer);
		const ptOff = this.x.getChunkPtOffset();
		const ctOff = this.x.getChunkCtOffset();
		mem.set(chunk, ptOff);
		this.x.chachaEncryptChunk_simd(chunk.length);
		return mem.slice(ctOff, ctOff + chunk.length);
	}

	/**
	 * Alias for `beginEncrypt` — ChaCha20 is a stream cipher (symmetric).
	 * @param key    32 bytes
	 * @param nonce  12 bytes — must match the value used to encrypt
	 */
	beginDecrypt(key: Uint8Array, nonce: Uint8Array): void {
		this.beginEncrypt(key, nonce);
	}

	/**
	 * Alias for `encryptChunk` — ChaCha20 is a stream cipher (symmetric).
	 * @param chunk  Ciphertext chunk
	 * @returns      Plaintext of the same length
	 */
	decryptChunk(chunk: Uint8Array): Uint8Array {
		return this.encryptChunk(chunk);
	}

	/** Wipe WASM state and release exclusive module access. Idempotent. */
	dispose(): void {
		if (this._tok === undefined) return;
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('chacha20', this._tok);
			this._tok = undefined;
		}
	}
}

// ── Poly1305 ────────────────────────────────────────────────────────────────

/**
 * Poly1305 one-time MAC (RFC 8439 §2.5).
 *
 * Atomic (stateless) class: each `mac()` call is independent.
 * The key must never be reused across messages. For most use cases, prefer
 * `ChaCha20Poly1305` or `XChaCha20Poly1305` which manage the one-time key
 * automatically.
 */
export class Poly1305 {
	private readonly x: ChaChaExports;

	constructor() {
		this.x = getExports();
	}

	/**
	 * Compute a 16-byte Poly1305 MAC for `msg` using `key`.
	 * @param key  32-byte one-time key — must not be reused across messages
	 * @param msg  Message to authenticate
	 * @returns    16-byte Poly1305 tag
	 */
	mac(key: Uint8Array, msg: Uint8Array): Uint8Array {
		_assertNotOwned('chacha20');
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

	/** Wipe WASM MAC state. */
	dispose(): void {
		_assertNotOwned('chacha20');
		this.x.wipeBuffers();
	}
}

// ── ChaCha20Poly1305 ────────────────────────────────────────────────────────

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
 *
 * `encrypt()` returns ciphertext || tag(16) as a single Uint8Array.
 * `decrypt()` accepts the same combined format and splits internally.
 *
 * Single-use encrypt guard: `encrypt()` may only be called once per instance.
 * Create a new instance for each encryption to prevent nonce reuse.
 *
 * `decrypt()` uses constant-time tag comparison — XOR-accumulate pattern,
 * no early return on mismatch. Plaintext is never returned on failure.
 */
export class ChaCha20Poly1305 {
	private readonly x: ChaChaExports;
	private _used = false;

	constructor() {
		this.x = getExports();
	}

	/**
	 * Encrypt and authenticate `plaintext` with ChaCha20-Poly1305 (RFC 8439 §2.8).
	 *
	 * **Single-use guard:** `encrypt()` may only be called once per instance.
	 * Any throw — including validation errors — permanently locks this instance.
	 * Always create a new `ChaCha20Poly1305` per message.
	 * @param key        32 bytes
	 * @param nonce      12 bytes — must be unique per (key, message)
	 * @param plaintext  Data to encrypt
	 * @param aad        Additional authenticated data (optional)
	 * @returns          Ciphertext || 16-byte Poly1305 tag
	 */
	encrypt(
		key:       Uint8Array,
		nonce:     Uint8Array,
		plaintext: Uint8Array,
		aad:       Uint8Array = new Uint8Array(0),
	): Uint8Array {
		if (this._used)
			throw new Error(
				'leviathan-crypto: encrypt() already called on this instance. '
				+ 'Create a new instance for each encryption to prevent nonce reuse.',
			);
		// Strict single-use: lock FIRST, before anything else. Any subsequent
		// throw — including validation errors — terminates the instance.
		this._used = true;
		_assertNotOwned('chacha20');
		if (key.length !== 32)
			throw new RangeError(`key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 12)
			throw new RangeError(`nonce must be 12 bytes (got ${nonce.length})`);
		const { ciphertext, tag } = aeadEncrypt(this.x, key, nonce, plaintext, aad);
		const out = new Uint8Array(ciphertext.length + 16);
		out.set(ciphertext);
		out.set(tag, ciphertext.length);
		return out;
	}

	/**
	 * Verify and decrypt a ChaCha20-Poly1305 ciphertext (RFC 8439 §2.8).
	 * Throws `AuthenticationError` if the tag does not match.
	 * @param key         32 bytes
	 * @param nonce       12 bytes — must match the value used to encrypt
	 * @param ciphertext  Ciphertext || 16-byte tag (combined format from `encrypt`)
	 * @param aad         Additional authenticated data (optional)
	 * @returns           Plaintext
	 */
	decrypt(
		key:        Uint8Array,
		nonce:      Uint8Array,
		ciphertext: Uint8Array,   // ciphertext || tag(16) combined
		aad:        Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('chacha20');
		if (key.length !== 32)
			throw new RangeError(`key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 12)
			throw new RangeError(`nonce must be 12 bytes (got ${nonce.length})`);
		if (ciphertext.length < 16)
			throw new RangeError(`ciphertext too short — must include 16-byte tag (got ${ciphertext.length})`);
		const ct  = ciphertext.subarray(0, ciphertext.length - 16);
		const tag = ciphertext.subarray(ciphertext.length - 16);
		return aeadDecrypt(this.x, key, nonce, ct, tag, aad);
	}

	/** Wipe WASM cipher and MAC state. */
	dispose(): void {
		_assertNotOwned('chacha20');
		this.x.wipeBuffers();
	}
}

// ── XChaCha20Poly1305 ───────────────────────────────────────────────────────

/**
 * XChaCha20-Poly1305 AEAD (IETF draft-irtf-cfrg-xchacha).
 *
 * Recommended authenticated encryption primitive for most use cases.
 * Uses a 24-byte nonce — safe for random generation via crypto.getRandomValues.
 *
 * Single-use encrypt guard: `encrypt()` may only be called once per instance.
 * Create a new instance for each encryption to prevent nonce reuse.
 *
 * `decrypt()` constant-time guarantee is inherited from the inner AEAD path.
 */
export class XChaCha20Poly1305 {
	private readonly x: ChaChaExports;
	private _used = false;

	constructor() {
		this.x = getExports();
	}

	/**
	 * Encrypt and authenticate `plaintext` with XChaCha20-Poly1305
	 * (draft-irtf-cfrg-xchacha). Recommended for general-purpose AEAD.
	 *
	 * **Single-use guard:** `encrypt()` may only be called once per instance.
	 * Any throw — including validation errors — permanently locks this instance.
	 * Always create a new `XChaCha20Poly1305` per message to prevent nonce reuse.
	 * @param key        32 bytes
	 * @param nonce      24 bytes — safe to generate randomly via `randomBytes(24)`
	 * @param plaintext  Data to encrypt
	 * @param aad        Additional authenticated data (optional)
	 * @returns          Ciphertext || 16-byte Poly1305 tag
	 */
	encrypt(
		key:       Uint8Array,
		nonce:     Uint8Array,
		plaintext: Uint8Array,
		aad:       Uint8Array = new Uint8Array(0),
	): Uint8Array {
		if (this._used)
			throw new Error(
				'leviathan-crypto: encrypt() already called on this instance. '
				+ 'Create a new instance for each encryption to prevent nonce reuse.',
			);
		// Strict single-use: lock FIRST, before anything else. Any subsequent
		// throw — including validation errors — terminates the instance.
		this._used = true;
		_assertNotOwned('chacha20');
		if (key.length !== 32)
			throw new RangeError(`key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 24)
			throw new RangeError(`XChaCha20 nonce must be 24 bytes (got ${nonce.length})`);
		return xcEncrypt(this.x, key, nonce, plaintext, aad);
	}

	/**
	 * Verify and decrypt an XChaCha20-Poly1305 ciphertext.
	 * Throws `AuthenticationError` if the tag does not match.
	 * @param key         32 bytes
	 * @param nonce       24 bytes — must match the value used to encrypt
	 * @param ciphertext  Ciphertext || 16-byte tag (combined format from `encrypt`)
	 * @param aad         Additional authenticated data (optional)
	 * @returns           Plaintext
	 */
	decrypt(
		key:        Uint8Array,
		nonce:      Uint8Array,
		ciphertext: Uint8Array,
		aad:        Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('chacha20');
		if (key.length !== 32)
			throw new RangeError(`key must be 32 bytes (got ${key.length})`);
		if (nonce.length !== 24)
			throw new RangeError(`XChaCha20 nonce must be 24 bytes (got ${nonce.length})`);
		if (ciphertext.length < 16)
			throw new RangeError(`ciphertext too short — must include 16-byte tag (got ${ciphertext.length})`);
		return xcDecrypt(this.x, key, nonce, ciphertext, aad);
	}

	/** Wipe WASM cipher and MAC state. */
	dispose(): void {
		_assertNotOwned('chacha20');
		this.x.wipeBuffers();
	}
}

export { XChaCha20Cipher } from './cipher-suite.js';

// ── ChaCha20Generator ───────────────────────────────────────────────────────

export { ChaCha20Generator } from './generator.js';
