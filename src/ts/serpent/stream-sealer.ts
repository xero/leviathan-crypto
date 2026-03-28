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
// src/ts/serpent/stream-sealer.ts
//
// Tier 2 pure-TS composition: SerpentCbc + HMAC_SHA256 + HKDF_SHA256.
// Incremental streaming AEAD — seal/open one chunk at a time.
// Wire format: header (20) | chunks: IV(16) || ct(padded) || HMAC(32)

import { SerpentCbc, _serpentReady } from './index.js';
import { HMAC_SHA256, HKDF_SHA256, _sha2Ready } from '../sha2/index.js';
import { concat, constantTimeEqual, wipe } from '../utils.js';
import { u32be, u64be } from './stream.js';

const DOMAIN      = 'serpent-sealstream-v1';
const DOMAIN_BYTES = new TextEncoder().encode(DOMAIN);  // 21 bytes
const CHUNK_MIN   = 1024;
const CHUNK_MAX   = 65536;
const CHUNK_DEF   = 65536;

type SealerState = 'fresh' | 'sealing' | 'dead';

function chunkInfo(
	streamNonce: Uint8Array,
	chunkSize:   number,
	index:       number,
	isLast:      boolean,
): Uint8Array {
	// 21 + 16 + 4 + 8 + 1 = 50 bytes
	const info = new Uint8Array(50);
	let off = 0;
	info.set(DOMAIN_BYTES, off); off += 21;
	info.set(streamNonce,  off); off += 16;
	info.set(u32be(chunkSize), off); off += 4;
	info.set(u64be(index), off); off += 8;
	info[off] = isLast ? 0x01 : 0x00;
	return info;
}

function deriveChunkKeys(
	hkdf:        HKDF_SHA256,
	key:         Uint8Array,
	streamNonce: Uint8Array,
	chunkSize:   number,
	index:       number,
	isLast:      boolean,
): { encKey: Uint8Array; macKey: Uint8Array } {
	const info    = chunkInfo(streamNonce, chunkSize, index, isLast);
	const derived = hkdf.derive(key, new Uint8Array(0), info, 64);
	return {
		encKey: derived.subarray(0, 32),
		macKey: derived.subarray(32, 64),
	};
}

export class SerpentStreamSealer {
	private readonly _key:    Uint8Array;
	private readonly _cs:     number;          // chunk size
	private readonly _nonce:  Uint8Array;      // stream nonce (16 bytes)
	private readonly _cbc:    SerpentCbc;
	private readonly _hmac:   HMAC_SHA256;
	private readonly _hkdf:   HKDF_SHA256;
	private readonly _framed: boolean;
	private readonly _ivs:    Uint8Array[] | undefined;  // test seam: fixed IVs
	private _ivIdx: number;
	private _index: number;
	private _state: SealerState;

	/** Public: consumers use this 3-param form. */
	constructor(key: Uint8Array, chunkSize?: number, opts?: { framed?: boolean })
	/** @internal Test-only overload to inject fixed nonce/IVs for deterministic KAT vectors. */
	constructor(
		key:       Uint8Array,
		chunkSize: number | undefined,
		opts:      { framed?: boolean } | undefined,
		_nonce:    Uint8Array,
		_ivs?:     Uint8Array[],
	)
	constructor(
		key:        Uint8Array,
		chunkSize?: number,
		opts?:      { framed?: boolean },
		_nonce?:    Uint8Array,
		_ivs?:      Uint8Array[],
	) {
		if (!_serpentReady()) throw new Error('leviathan-crypto: call init([\'serpent\']) before using SerpentStreamSealer');
		if (!_sha2Ready())    throw new Error('leviathan-crypto: call init([\'sha2\']) before using SerpentStreamSealer');
		if (key.length !== 64) throw new RangeError(`SerpentStreamSealer key must be 64 bytes (got ${key.length})`);
		const cs = chunkSize ?? CHUNK_DEF;
		if (cs < CHUNK_MIN || cs > CHUNK_MAX)
			throw new RangeError(`SerpentStreamSealer chunkSize must be ${CHUNK_MIN}..${CHUNK_MAX} (got ${cs})`);
		this._key    = key.slice();
		this._cs     = cs;
		this._framed = opts?.framed ?? false;
		this._nonce  = new Uint8Array(16);
		if (_nonce && _nonce.length === 16) {
			this._nonce.set(_nonce);
		} else {
			crypto.getRandomValues(this._nonce);
		}
		this._cbc   = new SerpentCbc({ dangerUnauthenticated: true });
		this._hmac  = new HMAC_SHA256();
		this._hkdf  = new HKDF_SHA256();
		this._ivs   = _ivs;
		this._ivIdx = 0;
		this._index = 0;
		this._state = 'fresh';
	}

	header(): Uint8Array {
		if (this._state === 'sealing') throw new Error('SerpentStreamSealer: header() already called');
		if (this._state === 'dead')    throw new Error('SerpentStreamSealer: stream is closed');
		this._state = 'sealing';
		const hdr = new Uint8Array(20);
		hdr.set(this._nonce, 0);
		hdr.set(u32be(this._cs), 16);
		return hdr;
	}

	seal(plaintext: Uint8Array): Uint8Array {
		if (this._state === 'fresh') throw new Error('SerpentStreamSealer: call header() first');
		if (this._state === 'dead')  throw new Error('SerpentStreamSealer: stream is closed');
		if (plaintext.length !== this._cs)
			throw new RangeError(`SerpentStreamSealer: seal() requires exactly ${this._cs} bytes (got ${plaintext.length})`);
		return this._sealChunk(plaintext, false);
	}

	final(plaintext: Uint8Array): Uint8Array {
		if (this._state === 'fresh') throw new Error('SerpentStreamSealer: call header() first');
		if (this._state === 'dead')  throw new Error('SerpentStreamSealer: stream is closed');
		if (plaintext.length > this._cs)
			throw new RangeError(`SerpentStreamSealer: final() plaintext exceeds chunkSize (got ${plaintext.length})`);
		const out = this._sealChunk(plaintext, true);
		this._wipe();
		return out;
	}

	private _sealChunk(plaintext: Uint8Array, isLast: boolean): Uint8Array {
		const { encKey, macKey } = deriveChunkKeys(
			this._hkdf, this._key, this._nonce, this._cs, this._index, isLast,
		);
		const iv = new Uint8Array(16);
		if (this._ivs && this._ivIdx < this._ivs.length) {
			iv.set(this._ivs[this._ivIdx++]);
		} else {
			crypto.getRandomValues(iv);
		}
		const ciphertext = this._cbc.encrypt(encKey, iv, plaintext);
		const tag        = this._hmac.hash(macKey, concat(iv, ciphertext));
		this._index++;
		const sealed = concat(concat(iv, ciphertext), tag);
		if (!this._framed) return sealed;
		const out = new Uint8Array(4 + sealed.length);
		out.set(u32be(sealed.length), 0);
		out.set(sealed, 4);
		return out;
	}

	private _wipe(): void {
		wipe(this._key);
		wipe(this._nonce);
		this._cbc.dispose();
		this._hmac.dispose();
		this._hkdf.dispose();
		this._state = 'dead';
	}

	dispose(): void {
		if (this._state !== 'dead') this._wipe();
	}
}

export class SerpentStreamOpener {
	private readonly _key:      Uint8Array;
	private readonly _cs:       number;
	private readonly _nonce:    Uint8Array;
	private readonly _cbc:      SerpentCbc;
	private readonly _hmac:     HMAC_SHA256;
	private readonly _hkdf:     HKDF_SHA256;
	private readonly _framed:   boolean;
	private readonly _buf:      Uint8Array | undefined;
	private readonly _maxFrame: number | undefined;
	private _bufLen:  number;
	private _index:   number;
	private _dead:    boolean;

	constructor(key: Uint8Array, header: Uint8Array, opts?: { framed?: boolean }) {
		if (!_serpentReady()) throw new Error('leviathan-crypto: call init([\'serpent\']) before using SerpentStreamOpener');
		if (!_sha2Ready())    throw new Error('leviathan-crypto: call init([\'sha2\']) before using SerpentStreamOpener');
		if (key.length !== 64)     throw new RangeError(`SerpentStreamOpener key must be 64 bytes (got ${key.length})`);
		if (header.length !== 20)  throw new RangeError(`SerpentStreamOpener header must be 20 bytes (got ${header.length})`);
		this._key    = key.slice();
		this._nonce  = header.slice(0, 16);
		this._cs     = (header[16] << 24 | header[17] << 16 | header[18] << 8 | header[19]) >>> 0;
		if (this._cs < CHUNK_MIN || this._cs > CHUNK_MAX)
			throw new RangeError(`SerpentStreamOpener: header contains invalid chunkSize ${this._cs} (expected ${CHUNK_MIN}..${CHUNK_MAX})`);
		this._framed = opts?.framed ?? false;
		this._cbc    = new SerpentCbc({ dangerUnauthenticated: true });
		this._hmac   = new HMAC_SHA256();
		this._hkdf   = new HKDF_SHA256();
		this._index  = 0;
		this._dead   = false;
		this._bufLen = 0;
		if (this._framed) {
			const cs        = this._cs;
			const maxSealed = 16 + (cs + (16 - (cs % 16))) + 32;
			this._maxFrame  = 4 + maxSealed;
			this._buf       = new Uint8Array(this._maxFrame);
		}
	}

	get closed(): boolean {
		return this._dead;
	}

	open(chunk: Uint8Array): Uint8Array {
		if (this._dead) throw new Error('SerpentStreamOpener: stream is closed');
		if (this._framed) throw new Error('SerpentStreamOpener: call feed() on framed openers — open() expects raw sealed chunks without length prefix');
		return this._openRaw(chunk);
	}

	private _openRaw(chunk: Uint8Array): Uint8Array {
		// Try isLast = true first, then false.
		// Whichever passes auth is the correct interpretation.
		for (const isLast of [true, false]) {
			const { encKey, macKey } = deriveChunkKeys(
				this._hkdf, this._key, this._nonce, this._cs, this._index, isLast,
			);
			// chunk = IV (16) || ciphertext || HMAC (32)
			if (chunk.length < 16 + 16 + 32) continue; // too short to be valid
			const iv         = chunk.subarray(0, 16);
			const ciphertext = chunk.subarray(16, chunk.length - 32);
			const tag        = chunk.subarray(chunk.length - 32);
			const expectedTag = this._hmac.hash(macKey, concat(iv, ciphertext));
			if (!constantTimeEqual(tag, expectedTag)) continue;
			const plaintext = this._cbc.decrypt(encKey, iv, ciphertext);
			this._index++;
			if (isLast) {
				this._wipe();
			}
			return plaintext;
		}

		throw new Error('SerpentStreamOpener: authentication failed');
	}

	feed(bytes: Uint8Array): Uint8Array[] {
		if (!this._framed) throw new Error('SerpentStreamOpener: feed() requires { framed: true }');
		if (this._dead) throw new Error('SerpentStreamOpener: stream is closed');
		const buf      = this._buf as Uint8Array;
		const maxFrame = this._maxFrame as number;

		const results: Uint8Array[] = [];
		let consumed = 0;

		// ── Phase 1: drain carry-over ─────────────────────────────────────
		if (this._bufLen > 0) {
			// Sub-case A: partial prefix — we have < 4 bytes buffered
			if (this._bufLen < 4) {
				const need = 4 - this._bufLen;
				const take = Math.min(need, bytes.length - consumed);
				buf.set(bytes.subarray(consumed, consumed + take), this._bufLen);
				this._bufLen += take;
				consumed += take;
				if (this._bufLen < 4) return results;
			}

			const sealedLen = (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0;
			if (sealedLen === 0 || sealedLen > (maxFrame - 4)) {
				this._wipe();
				throw new Error('SerpentStreamOpener: invalid sealed chunk length');
			}
			const frameLen = 4 + sealedLen;

			// Sub-case B: partial frame body
			const haveInBuf = this._bufLen;
			const needMore  = frameLen - haveInBuf;
			if (needMore > 0) {
				const take = Math.min(needMore, bytes.length - consumed);
				buf.set(bytes.subarray(consumed, consumed + take), haveInBuf);
				this._bufLen += take;
				consumed += take;
				if (this._bufLen < frameLen) return results;
			}

			const plaintext = this._openRaw(buf.subarray(4, frameLen));
			results.push(plaintext);
			this._bufLen = 0;

			if (this._dead) {
				if (consumed < bytes.length) {
					this._wipe();
					throw new Error('SerpentStreamOpener: unexpected bytes after final chunk');
				}
				return results;
			}
		}

		// ── Phase 2: parse complete frames directly from bytes ────────────
		let pos = consumed;
		while (true) {
			if (bytes.length - pos < 4) break;
			const sealedLen = (bytes[pos] << 24 | bytes[pos + 1] << 16 | bytes[pos + 2] << 8 | bytes[pos + 3]) >>> 0;
			if (sealedLen === 0 || sealedLen > (maxFrame - 4)) {
				this._wipe();
				throw new Error('SerpentStreamOpener: invalid sealed chunk length');
			}
			const frameLen = 4 + sealedLen;
			if (bytes.length - pos < frameLen) break;

			const plaintext = this._openRaw(bytes.subarray(pos + 4, pos + frameLen));
			results.push(plaintext);

			if (this._dead) {
				const remaining = bytes.length - pos - frameLen;
				if (remaining > 0) {
					this._wipe();
					throw new Error('SerpentStreamOpener: unexpected bytes after final chunk');
				}
				return results;
			}
			pos += frameLen;
		}

		// ── Carry over any incomplete trailing bytes into _buf ────────────
		const leftover = bytes.length - pos;
		if (leftover > 0) {
			if (leftover > maxFrame) {
				this._wipe();
				throw new Error('SerpentStreamOpener: input exceeds maximum frame size');
			}
			buf.set(bytes.subarray(pos), 0);
			this._bufLen = leftover;
		}
		return results;
	}

	private _wipe(): void {
		if (this._dead) return;
		wipe(this._key);
		wipe(this._nonce);
		this._cbc.dispose();
		this._hmac.dispose();
		this._hkdf.dispose();
		if (this._framed) {
			wipe(this._buf as Uint8Array); this._bufLen = 0;
		}
		this._dead = true;
	}

	dispose(): void {
		if (!this._dead) this._wipe();
	}
}
