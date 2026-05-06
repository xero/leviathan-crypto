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
// src/ts/aes/aes-gcm.ts
//
// AESGCM — AES-128/192/256 in GCM mode (NIST SP 800-38D §7), atomic
// authenticated AEAD. Tag length is fixed at 128 bits.

import { getInstance, _acquireModule, _releaseModule } from '../init.js';
import { constantTimeEqual } from '../utils.js';

// Maximum plaintext per (key, IV) per SP 800-38D §5.2.1.1: 2^39 - 256 bits
// = 2^36 - 32 bytes. Practical JS Uint8Array is much smaller, but we still
// enforce the spec bound explicitly.
const MAX_PT_BYTES = 0x1000000000 - 32;     // 2^36 - 32

// Maximum AAD bytes per buffer-bounded WASM API. The dedicated AAD_BUFFER
// is 64 KiB; longer AAD requires a streaming API not in scope for v2.2.0.
const MAX_AAD_BYTES = 65536;

// Maximum IV bytes our atomic class accepts. The spec permits any IV up to
// 2^64 - 1 bits; the typical recommended value is 12 bytes (96 bits). We
// reuse CHUNK_PT_BUFFER as IV scratch for the variable-length-IV path,
// which means the IV must fit in 64 KiB. Anyone using IVs longer than
// that is doing something unusual and can build it themselves.
const MAX_IV_BYTES = 65536;

// Single-call PT/CT cap: the chunk buffer is 64 KiB. Chunked iteration
// across the WASM boundary works for larger inputs; we wire that into
// the seal/open methods below.
const PT_CHUNK_LIMIT = 65536;

const AUTH_FAILED = 'authentication failed';

/** Typed subset of the AES WASM module exports used by `AESGCM`. @internal */
interface AesGcmExports {
	memory:               WebAssembly.Memory;
	getKeyOffset:         () => number;
	getChunkPtOffset:     () => number;
	getChunkCtOffset:     () => number;
	getChunkSize:         () => number;
	getAadOffset:         () => number;
	getAadBufferSize:     () => number;
	getTagOffset:         () => number;
	loadKey:              (n: number) => number;
	gcmStart:             (ivLen: number, aadLen: number) => number;
	gcmEncryptChunk:      (srcOff: number, dstOff: number, len: number) => number;
	gcmAbsorbCtChunk:     (srcOff: number, len: number) => number;
	gcmDecryptChunk:      (srcOff: number, dstOff: number, len: number) => number;
	gcmResetCtrToJ0Plus1: () => void;
	gcmFinalize:          () => void;
	wipeBuffers:          () => void;
}

/** Returns the raw AES WASM export object. @internal */
function getExports(): AesGcmExports {
	return getInstance('aes').exports as unknown as AesGcmExports;
}

// ── AESGCM ──────────────────────────────────────────────────────────────────

/**
 * AES-128/192/256 in GCM mode (SP 800-38D §7). Authenticated AEAD with
 * 128-bit tag. Tag length is fixed; shorter tags (32/64/96/104/112/120)
 * are out of scope for this version.
 *
 * `seal(key, iv, aad, pt)` returns `ciphertext || tag` (length pt.length + 16).
 * `open(key, iv, aad, sealed)` verifies the tag and returns the plaintext;
 * throws `RangeError('authentication failed')` on any verification failure
 * (the same generic error as a tag mismatch — no detail leak).
 *
 * Holds exclusive access to the `aes` WASM module from construction until
 * `dispose()`. Constructing a second AES-using class while this instance is
 * live throws. Always dispose when done so key material is wiped.
 */
export class AESGCM {
	private readonly x: AesGcmExports;
	private _tok: symbol | undefined;

	constructor() {
		this.x   = getExports();
		this._tok = _acquireModule('aes');
	}

	/** View over WASM linear memory. Rebind every access — memory can be detached. @internal */
	private get mem(): Uint8Array {
		return new Uint8Array(this.x.memory.buffer);
	}

	/**
	 * Authenticated encryption.
	 *
	 * @param key  16, 24, or 32 bytes (AES-128 / 192 / 256)
	 * @param iv   1+ bytes; 12-byte (96-bit) IV is the recommended fast path
	 * @param aad  any length up to 64 KiB; may be empty
	 * @param pt   any length up to 2^36 - 32 bytes; may be empty
	 * @returns    ciphertext concatenated with the 128-bit tag
	 *             (length = pt.length + 16)
	 *
	 * @throws RangeError if key/iv/aad/pt lengths violate the spec or the
	 *         buffer-bounded API.
	 */
	seal(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, pt: Uint8Array): Uint8Array {
		if (this._tok === undefined)
			throw new Error('AESGCM: instance has been disposed');
		this._validateInputs(key, iv, aad, pt.length);

		this._loadKey(key);
		this._writeIv(iv);
		this._writeAad(aad);
		const startRc = this.x.gcmStart(iv.length, aad.length);
		if (startRc !== 0) throw new RangeError('invalid GCM input');

		const output = new Uint8Array(pt.length + 16);
		const ptOff  = this.x.getChunkPtOffset();
		const ctOff  = this.x.getChunkCtOffset();
		const tagOff = this.x.getTagOffset();

		for (let off = 0; off < pt.length; off += PT_CHUNK_LIMIT) {
			const chunkLen = Math.min(PT_CHUNK_LIMIT, pt.length - off);
			this.mem.set(pt.subarray(off, off + chunkLen), ptOff);
			const rc = this.x.gcmEncryptChunk(ptOff, ctOff, chunkLen);
			if (rc !== 0) throw new RangeError('GCM counter overflow');
			output.set(this.mem.subarray(ctOff, ctOff + chunkLen), off);
		}

		this.x.gcmFinalize();
		output.set(this.mem.subarray(tagOff, tagOff + 16), pt.length);
		return output;
	}

	/**
	 * Authenticated decryption.
	 *
	 * Performs verify-before-decrypt (SP 800-38D §7.2 permits the tag check
	 * to precede plaintext computation): the entire ciphertext is absorbed
	 * into GHASH, the tag is computed and constant-time-compared with the
	 * received tag, and only then is the ciphertext decrypted to plaintext.
	 * This avoids leaking decrypted bytes to higher layers when the tag
	 * fails to verify.
	 *
	 * @param key     same constraints as `seal`
	 * @param iv      same iv used during the matching `seal` call
	 * @param aad     same aad used during the matching `seal` call
	 * @param sealed  output of a previous `seal` call (ciphertext || tag)
	 * @returns       plaintext (length = sealed.length - 16)
	 *
	 * @throws RangeError('authentication failed') if the tag fails to
	 *         verify, or if the sealed input is too short, or any input
	 *         length violates the spec. The same generic error covers all
	 *         failure modes — no detail is leaked about which check failed.
	 */
	open(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Uint8Array {
		if (this._tok === undefined)
			throw new Error('AESGCM: instance has been disposed');
		if (sealed.length < 16) throw new RangeError(AUTH_FAILED);
		const ctLen = sealed.length - 16;
		// Throw the generic auth-failed error rather than 'invalid input' on
		// length validation, to keep failure modes indistinguishable.
		try {
			this._validateInputs(key, iv, aad, ctLen);
		} catch {
			throw new RangeError(AUTH_FAILED);
		}

		this._loadKey(key);
		this._writeIv(iv);
		this._writeAad(aad);
		const startRc = this.x.gcmStart(iv.length, aad.length);
		if (startRc !== 0) throw new RangeError(AUTH_FAILED);

		const ptOff  = this.x.getChunkPtOffset();
		const ctOff  = this.x.getChunkCtOffset();

		// Pass 1: absorb every CT chunk into GHASH (no decryption yet).
		for (let off = 0; off < ctLen; off += PT_CHUNK_LIMIT) {
			const chunkLen = Math.min(PT_CHUNK_LIMIT, ctLen - off);
			this.mem.set(sealed.subarray(off, off + chunkLen), ctOff);
			const rc = this.x.gcmAbsorbCtChunk(ctOff, chunkLen);
			if (rc !== 0) throw new RangeError(AUTH_FAILED);
		}

		// Compute tag → TAG_OFFSET, then constant-time compare with sealed[ctLen..].
		this.x.gcmFinalize();
		// Slice the computed tag out of WASM memory (defensive copy — the
		// WASM memory view can be reattached on grow). Compare via the
		// dedicated `ct` WASM module exposed as `constantTimeEqual` in
		// `../utils.js`. No tag compare lives inside the AES module
		// itself — this is library-wide policy for atomic AEADs.
		const tagOff = this.x.getTagOffset();
		const expectedTag = this.mem.slice(tagOff, tagOff + 16);
		const providedTag = sealed.slice(ctLen, ctLen + 16);
		if (!constantTimeEqual(expectedTag, providedTag)) {
			this.x.wipeBuffers();
			throw new RangeError(AUTH_FAILED);
		}

		// Pass 2: re-init counter, GCTR-decrypt every CT chunk → output.
		this.x.gcmResetCtrToJ0Plus1();
		const output = new Uint8Array(ctLen);
		for (let off = 0; off < ctLen; off += PT_CHUNK_LIMIT) {
			const chunkLen = Math.min(PT_CHUNK_LIMIT, ctLen - off);
			this.mem.set(sealed.subarray(off, off + chunkLen), ctOff);
			const rc = this.x.gcmDecryptChunk(ctOff, ptOff, chunkLen);
			if (rc !== 0) {
				this.x.wipeBuffers();
				throw new RangeError(AUTH_FAILED);
			}
			output.set(this.mem.subarray(ptOff, ptOff + chunkLen), off);
		}

		return output;
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

	// ── Internal helpers ───────────────────────────────────────────────────

	private _validateInputs(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, dataLen: number): void {
		if (key.length !== 16 && key.length !== 24 && key.length !== 32)
			throw new RangeError(`AES key must be 16, 24, or 32 bytes (got ${key.length})`);
		if (iv.length < 1)
			throw new RangeError('GCM IV must be ≥ 1 byte');
		if (iv.length > MAX_IV_BYTES)
			throw new RangeError(`GCM IV must be ≤ ${MAX_IV_BYTES} bytes (got ${iv.length})`);
		if (aad.length > MAX_AAD_BYTES)
			throw new RangeError(`GCM AAD must be ≤ ${MAX_AAD_BYTES} bytes (got ${aad.length})`);
		if (dataLen > MAX_PT_BYTES)
			throw new RangeError(`GCM plaintext must be ≤ 2^36 - 32 bytes (got ${dataLen})`);
	}

	private _loadKey(key: Uint8Array): void {
		this.mem.set(key, this.x.getKeyOffset());
		if (this.x.loadKey(key.length) !== 0) {
			this.x.wipeBuffers();
			throw new Error('AESGCM: loadKey failed');
		}
	}

	private _writeIv(iv: Uint8Array): void {
		this.mem.set(iv, this.x.getChunkPtOffset());
	}

	private _writeAad(aad: Uint8Array): void {
		if (aad.length === 0) return;
		this.mem.set(aad, this.x.getAadOffset());
	}
}
