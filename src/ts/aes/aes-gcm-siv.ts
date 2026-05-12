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
// src/ts/aes/aes-gcm-siv.ts
//
// AESGCMSIV, AES-128/256 in GCM-SIV mode (RFC 8452), nonce-misuse-
// resistant authenticated encryption with a 128-bit tag. Atomic single-
// shot AEAD bounded by CHUNK_PT_BUFFER (64 KiB plaintext cap).
//
// AES-192 is NOT supported. RFC 8452 §6 fixes K_LEN ∈ {16, 32}; there is
// no AES-192-GCM-SIV variant. Passing a 24-byte key to the constructor
// throws.
//
// Tag verification routes through `constantTimeEqual` in `../utils.js`
// (the dedicated `ct` WASM module), per library policy: atomic AEADs do
// not compare tags inside their own module.
//
// On authentication failure, `open()` calls the WASM `sivWipeOnFail`
// helper before throwing, ensuring the decrypted-but-unauthenticated
// plaintext at CHUNK_PT_OFFSET is zeroed before any TS code can read it.
// (The CHUNK_PT staging is required by SIV's verify-after-decrypt flow,
// the tag is a function of the plaintext.)

import { getInstance, _acquireModule, _releaseModule } from '../init.js';
import { constantTimeEqual, wipe } from '../utils.js';
import { AuthenticationError } from '../errors.js';

// RFC 8452 §6: K_LEN ∈ {16, 32}, AES-128-GCM-SIV or AES-256-GCM-SIV.
const KEY_LEN_128 = 16;
const KEY_LEN_256 = 32;

// RFC 8452 §6: nonce length is fixed at 96 bits (12 bytes).
const NONCE_LEN = 12;

// Single-shot bound: plaintext fits in CHUNK_PT (64 KiB). Larger inputs
// would need a streaming SIV API; not in scope for this phase.
const MAX_PT_BYTES = 65536;

// AAD is bounded by the dedicated AAD_BUFFER (64 KiB).
const MAX_AAD_BYTES = 65536;

// 16-byte authentication tag.
const TAG_LEN = 16;

/** Typed subset of the AES WASM module exports used by `AESGCMSIV`. @internal */
interface AesGcmSivExports {
	memory:                  WebAssembly.Memory;
	getKeyOffset:            () => number;
	getNonceOffset:          () => number;
	getChunkPtOffset:        () => number;
	getChunkCtOffset:        () => number;
	getAadOffset:            () => number;
	getTagOffset:            () => number;
	getPolyvalAuthKeyOffset: () => number;
	getPolyvalEncKeyOffset:  () => number;
	getSivIcOffset:          () => number;
	loadKey:                 (n: number) => number;
	sivDeriveKeys:           (nonceOff: number) => void;
	sivSeal:                 (aadLen: number, ptLen: number) => void;
	sivOpen:                 (aadLen: number, ctLen: number) => void;
	sivWipeOnFail:           () => void;
	wipeBuffers:             () => void;
}

/** Returns the raw AES WASM export object. @internal */
function getExports(): AesGcmSivExports {
	return getInstance('aes').exports as unknown as AesGcmSivExports;
}

// ── AESGCMSIV ───────────────────────────────────────────────────────────────

/**
 * AES-128-GCM-SIV / AES-256-GCM-SIV (RFC 8452). Nonce-misuse-resistant
 * authenticated AEAD with a 128-bit tag. AES-192 keys are rejected
 * (RFC 8452 §6, no AES-192-GCM-SIV variant exists).
 *
 * Single-shot only: each `seal` / `open` call processes one complete
 * message bounded by 64 KiB of plaintext. Larger messages are out of
 * scope for this primitive; a future streaming variant will lift the
 * cap via the seal/sealstream layer.
 *
 * `seal(nonce, plaintext, aad?)` returns `ciphertext || tag` (length
 * pt.length + 16). `open(nonce, sealed, aad?)` verifies the tag and
 * returns the plaintext; throws `AuthenticationError('siv')` on any
 * verification failure.
 *
 * Atomic, does not hold exclusive access between calls. `dispose()`
 * wipes the stored key from the JS-side cache.
 */
export class AESGCMSIV {
	private readonly _key: Uint8Array;
	private _disposed = false;

	/**
	 * @param key  16 bytes (AES-128-GCM-SIV) or 32 bytes (AES-256-GCM-SIV).
	 *             24-byte keys are rejected, RFC 8452 §6 does not define
	 *             an AES-192-GCM-SIV variant.
	 */
	constructor(key: Uint8Array) {
		if (key.length !== KEY_LEN_128 && key.length !== KEY_LEN_256) {
			throw new RangeError(
				`AESGCMSIV key must be 16 or 32 bytes (got ${key.length}); `
				+ 'AES-192-GCM-SIV is not defined by RFC 8452',
			);
		}
		// Defensive copy so external mutation cannot change the live key.
		this._key = new Uint8Array(key);
	}

	/**
	 * Authenticated encryption.
	 *
	 * @param nonce  exactly 12 bytes (RFC 8452 §6 fixes nonce length)
	 * @param plaintext  any length up to 64 KiB; may be empty
	 * @param aad  any length up to 64 KiB; may be empty
	 * @returns  ciphertext concatenated with the 128-bit tag
	 *           (length = plaintext.length + 16)
	 *
	 * @throws RangeError if any input length violates the spec or the
	 *         buffer-bounded API.
	 */
	seal(nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
		this._assertAlive();
		this._validate(nonce, plaintext.length, aad);

		const x = getExports();
		const tok = _acquireModule('aes');
		try {
			this._stage(x, nonce, aad);
			this._mem(x).set(plaintext, x.getChunkPtOffset());

			x.sivDeriveKeys(x.getNonceOffset());
			x.sivSeal(aad.length, plaintext.length);

			const ctOff = x.getChunkPtOffset();
			const tagOff = x.getTagOffset();
			const out = new Uint8Array(plaintext.length + TAG_LEN);
			out.set(this._mem(x).subarray(ctOff,  ctOff  + plaintext.length), 0);
			out.set(this._mem(x).subarray(tagOff, tagOff + TAG_LEN), plaintext.length);
			return out;
		} finally {
			x.wipeBuffers();
			_releaseModule('aes', tok);
		}
	}

	/**
	 * Authenticated decryption. `sealed` is the output of a matching
	 * `seal(nonce, plaintext, aad)` call.
	 *
	 * Verification routes through `constantTimeEqual` from
	 * `../utils.js` (the dedicated `ct` WASM module). On mismatch the
	 * WASM `sivWipeOnFail` helper zeroes the decrypted-but-
	 * unauthenticated plaintext at CHUNK_PT_OFFSET before this method
	 * throws, the bytes never become reachable from JS.
	 *
	 * @throws AuthenticationError('siv') if the tag fails to verify, or
	 *         if `sealed` is too short, or any input length violates the
	 *         spec.
	 */
	open(nonce: Uint8Array, sealed: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
		this._assertAlive();
		if (sealed.length < TAG_LEN) {
			throw new AuthenticationError('siv');
		}
		const ctLen = sealed.length - TAG_LEN;
		try {
			this._validate(nonce, ctLen, aad);
		} catch {
			// Same generic error so failure modes are indistinguishable.
			throw new AuthenticationError('siv');
		}

		const ct = sealed.subarray(0, ctLen);
		const providedTag = sealed.subarray(ctLen, sealed.length);

		const x = getExports();
		const tok = _acquireModule('aes');
		try {
			this._stage(x, nonce, aad);
			this._mem(x).set(ct, x.getChunkCtOffset());
			// Stage the provided tag at SIV_IC_OFFSET, sivOpen will
			// read it from there as the input to the CTR initial counter.
			this._mem(x).set(providedTag, x.getSivIcOffset());

			x.sivDeriveKeys(x.getNonceOffset());
			x.sivOpen(aad.length, ctLen);

			// Read the EXPECTED tag computed by sivOpen from TAG_OFFSET.
			// Use slice() rather than subarray() so the buffer survives
			// any subsequent WASM memory growth or wipe.
			const expectedTag = this._mem(x).slice(
				x.getTagOffset(),
				x.getTagOffset() + TAG_LEN,
			);
			// Defensive copy of providedTag for the constant-time compare,
			// the input may be a view over a caller-controlled buffer.
			const providedTagCopy = new Uint8Array(providedTag);

			const ok = constantTimeEqual(expectedTag, providedTagCopy);
			if (!ok) {
				// Belt-and-suspenders: surgical wipe of the unauthenticated
				// plaintext before the broader wipeBuffers in finally fires.
				// Also wipe JS-heap tag copies to mirror the discipline in
				// chacha20 ops and serpent cipher-suite.
				x.sivWipeOnFail();
				wipe(expectedTag);
				wipe(providedTagCopy);
				throw new AuthenticationError('siv');
			}

			// Match, read PT before wiping. pt is a JS-heap slice copy.
			const ptOff = x.getChunkPtOffset();
			const pt = this._mem(x).slice(ptOff, ptOff + ctLen);
			wipe(expectedTag);
			wipe(providedTagCopy);
			return pt;
		} finally {
			x.wipeBuffers();
			_releaseModule('aes', tok);
		}
	}

	/**
	 * Wipe the in-memory copy of the key. Idempotent. Subsequent calls
	 * to `seal` / `open` throw. WASM-side state is wiped at the end of
	 * every successful operation regardless of `dispose()`.
	 */
	dispose(): void {
		if (this._disposed) return;
		this._key.fill(0);
		this._disposed = true;
	}

	// ── Internal helpers ───────────────────────────────────────────────────

	private _mem(x: AesGcmSivExports): Uint8Array {
		return new Uint8Array(x.memory.buffer);
	}

	private _assertAlive(): void {
		if (this._disposed) throw new Error('AESGCMSIV: instance has been disposed');
	}

	private _validate(nonce: Uint8Array, dataLen: number, aad: Uint8Array): void {
		if (nonce.length !== NONCE_LEN)
			throw new RangeError(`AESGCMSIV nonce must be ${NONCE_LEN} bytes (got ${nonce.length})`);
		if (dataLen > MAX_PT_BYTES)
			throw new RangeError(`AESGCMSIV plaintext must be ≤ ${MAX_PT_BYTES} bytes (got ${dataLen})`);
		if (aad.length > MAX_AAD_BYTES)
			throw new RangeError(`AESGCMSIV AAD must be ≤ ${MAX_AAD_BYTES} bytes (got ${aad.length})`);
	}

	/** Push KGK + nonce + AAD into WASM memory. Common to seal/open. */
	private _stage(x: AesGcmSivExports, nonce: Uint8Array, aad: Uint8Array): void {
		const mem = this._mem(x);
		mem.set(this._key, x.getKeyOffset());
		if (x.loadKey(this._key.length) !== 0) {
			x.wipeBuffers();
			throw new Error('AESGCMSIV: loadKey failed');
		}
		mem.set(nonce, x.getNonceOffset());
		if (aad.length > 0) {
			mem.set(aad, x.getAadOffset());
		}
	}
}
