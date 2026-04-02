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
// src/ts/chacha20/stream-sealer.ts
//
// XChaCha20Stream — chunked authenticated encryption for large payloads.
// Tier 2 pure-TS: XChaCha20-Poly1305 per chunk. Simpler than SerpentStream —
// no HKDF, no HMAC; Poly1305 handles auth. Stream binding via per-chunk AAD.
// Wire format: header(20) | chunks: isLast(1) || nonce(24) || ct || tag(16)

import { getInstance } from '../init.js';
import type { ChaChaExports } from './types.js';
import { xcEncrypt, xcDecrypt } from './ops.js';
import { randomBytes, wipe } from '../utils.js';
import { _chachaReady } from './index.js';

const CHUNK_MIN = 1024;
const CHUNK_MAX = 65536;
const CHUNK_DEF = 65536;

type SealerState = 'fresh' | 'sealing' | 'dead';

export function u32be(n: number): Uint8Array {
	const b = new Uint8Array(4);
	b[0] = (n >>> 24) & 0xff; b[1] = (n >>> 16) & 0xff;
	b[2] = (n >>> 8)  & 0xff; b[3] = n & 0xff;
	return b;
}

export function u64be(n: number): Uint8Array {
	const b  = new Uint8Array(8);
	const hi = Math.floor(n / 0x100000000);
	const lo = n >>> 0;
	b[0] = (hi >>> 24) & 0xff; b[1] = (hi >>> 16) & 0xff;
	b[2] = (hi >>> 8)  & 0xff; b[3] = hi & 0xff;
	b[4] = (lo >>> 24) & 0xff; b[5] = (lo >>> 16) & 0xff;
	b[6] = (lo >>> 8)  & 0xff; b[7] = lo & 0xff;
	return b;
}

function getExports(): ChaChaExports {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

/** Build internal AAD: stream_id(16) || u64be(index) || isLast(1) || u32be(userAad.length) || userAad */
export function chunkAAD(streamId: Uint8Array, index: number, isLast: boolean, userAad: Uint8Array): Uint8Array {
	const out = new Uint8Array(16 + 8 + 1 + 4 + userAad.length);
	let off = 0;
	out.set(streamId, off); off += 16;
	out.set(u64be(index), off); off += 8;
	out[off++] = isLast ? 1 : 0;
	out.set(u32be(userAad.length), off); off += 4;
	out.set(userAad, off);
	return out;
}

export class XChaCha20StreamSealer {
	private readonly _x:      ChaChaExports;
	private readonly _key:    Uint8Array;
	private readonly _cs:     number;
	private readonly _id:     Uint8Array;   // stream_id (16 bytes)
	private readonly _framed: boolean;
	private readonly _aad:    Uint8Array;
	private _index:  number;
	private _state:  SealerState;

	/** Public: consumers use this 3-param form. */
	constructor(key: Uint8Array, chunkSize?: number, opts?: { framed?: boolean; aad?: Uint8Array })
	/** @internal Test-only overload to inject fixed stream_id for deterministic output. */
	constructor(key: Uint8Array, chunkSize: number | undefined, opts: { framed?: boolean; aad?: Uint8Array } | undefined, _id: Uint8Array)
	constructor(
		key:        Uint8Array,
		chunkSize?: number,
		opts?:      { framed?: boolean; aad?: Uint8Array },
		_id?:       Uint8Array,
	) {
		if (!_chachaReady())
			throw new Error('leviathan-crypto: call init([\'chacha20\']) before using XChaCha20StreamSealer');
		if (key.length !== 32)
			throw new RangeError(`XChaCha20StreamSealer key must be 32 bytes (got ${key.length})`);
		const cs = chunkSize ?? CHUNK_DEF;
		if (cs < CHUNK_MIN || cs > CHUNK_MAX)
			throw new RangeError(`XChaCha20StreamSealer chunkSize must be ${CHUNK_MIN}..${CHUNK_MAX} (got ${cs})`);
		this._x      = getExports();
		this._key    = key.slice();
		this._cs     = cs;
		this._framed = opts?.framed ?? false;
		this._aad    = opts?.aad ? opts.aad.slice() : new Uint8Array(0);
		this._id     = new Uint8Array(16);
		if (_id && _id.length === 16) this._id.set(_id);
		else crypto.getRandomValues(this._id);
		this._index = 0;
		this._state = 'fresh';
	}

	header(): Uint8Array {
		if (this._state === 'sealing') throw new Error('XChaCha20StreamSealer: header() already called');
		if (this._state === 'dead')    throw new Error('XChaCha20StreamSealer: stream is closed');
		this._state = 'sealing';
		const hdr = new Uint8Array(20);
		hdr.set(this._id, 0);
		hdr.set(u32be(this._cs), 16);
		return hdr;
	}

	seal(plaintext: Uint8Array): Uint8Array {
		if (this._state === 'fresh') throw new Error('XChaCha20StreamSealer: call header() first');
		if (this._state === 'dead')  throw new Error('XChaCha20StreamSealer: stream is closed');
		if (plaintext.length !== this._cs)
			throw new RangeError(`XChaCha20StreamSealer: seal() requires exactly ${this._cs} bytes (got ${plaintext.length})`);
		return this._sealChunk(plaintext, false);
	}

	final(plaintext: Uint8Array): Uint8Array {
		if (this._state === 'fresh') throw new Error('XChaCha20StreamSealer: call header() first');
		if (this._state === 'dead')  throw new Error('XChaCha20StreamSealer: stream is closed');
		if (plaintext.length > this._cs)
			throw new RangeError(`XChaCha20StreamSealer: final() plaintext exceeds chunkSize (got ${plaintext.length})`);
		const out = this._sealChunk(plaintext, true);
		this._wipe();
		return out;
	}

	private _sealChunk(plaintext: Uint8Array, isLast: boolean): Uint8Array {
		const nonce  = randomBytes(24);
		const aad    = chunkAAD(this._id, this._index, isLast, this._aad);
		const sealed = xcEncrypt(this._x, this._key, nonce, plaintext, aad);
		this._index++;
		// sealed = ciphertext || tag(16)
		// wire chunk = isLast(1) || nonce(24) || sealed
		const chunk = new Uint8Array(1 + 24 + sealed.length);
		chunk[0] = isLast ? 1 : 0;
		chunk.set(nonce, 1);
		chunk.set(sealed, 25);
		if (!this._framed) return chunk;
		const out = new Uint8Array(4 + chunk.length);
		out.set(u32be(chunk.length), 0);
		out.set(chunk, 4);
		return out;
	}

	private _wipe(): void {
		wipe(this._key);
		wipe(this._id);
		wipe(this._aad);
		this._x.wipeBuffers();
		this._state = 'dead';
	}

	dispose(): void {
		if (this._state !== 'dead') this._wipe();
	}
}

export class XChaCha20StreamOpener {
	private readonly _x:       ChaChaExports;
	private readonly _key:     Uint8Array;
	private readonly _cs:      number;
	private readonly _id:      Uint8Array;   // stream_id from header
	private readonly _framed:  boolean;
	private readonly _aad:     Uint8Array;
	private readonly _buf:     Uint8Array | undefined;
	private readonly _maxFrame: number | undefined;
	private _bufLen: number;
	private _index:  number;
	private _dead:   boolean;

	constructor(key: Uint8Array, header: Uint8Array, opts?: { framed?: boolean; aad?: Uint8Array }) {
		if (!_chachaReady())
			throw new Error('leviathan-crypto: call init([\'chacha20\']) before using XChaCha20StreamOpener');
		if (key.length !== 32)    throw new RangeError(`XChaCha20StreamOpener key must be 32 bytes (got ${key.length})`);
		if (header.length !== 20) throw new RangeError(`XChaCha20StreamOpener header must be 20 bytes (got ${header.length})`);
		this._x      = getExports();
		this._key    = key.slice();
		this._id     = header.slice(0, 16);
		this._cs     = (header[16] << 24 | header[17] << 16 | header[18] << 8 | header[19]) >>> 0;
		if (this._cs < CHUNK_MIN || this._cs > CHUNK_MAX)
			throw new RangeError(`XChaCha20StreamOpener: header contains invalid chunkSize ${this._cs} (expected ${CHUNK_MIN}..${CHUNK_MAX})`);
		this._framed = opts?.framed ?? false;
		this._aad    = opts?.aad ? opts.aad.slice() : new Uint8Array(0);
		this._index  = 0;
		this._dead   = false;
		this._bufLen = 0;
		if (this._framed) {
			// max sealed chunk: 1 + 24 + CHUNK_MAX + 16
			this._maxFrame = 4 + 1 + 24 + CHUNK_MAX + 16;
			this._buf      = new Uint8Array(this._maxFrame);
		}
	}

	get closed(): boolean {
		return this._dead;
	}

	open(chunk: Uint8Array): Uint8Array {
		if (this._dead) throw new Error('XChaCha20StreamOpener: stream is closed');
		if (this._framed) throw new Error('XChaCha20StreamOpener: call feed() on framed openers — open() expects raw sealed chunks without length prefix');
		return this._openRaw(chunk);
	}

	private _openRaw(chunk: Uint8Array): Uint8Array {
		// isLast(1) || nonce(24) || ciphertext || tag(16)
		if (chunk.length < 1 + 24 + 16)
			throw new RangeError('XChaCha20StreamOpener: chunk too short');
		const isLast  = chunk[0] !== 0;
		const nonce   = chunk.subarray(1, 25);
		const payload = chunk.subarray(25); // ciphertext || tag(16)
		if (payload.length < 16)
			throw new RangeError('XChaCha20StreamOpener: chunk too short for tag');
		const aad = chunkAAD(this._id, this._index, isLast, this._aad);
		// xcDecrypt expects ciphertext || tag combined
		const plaintext = xcDecrypt(this._x, this._key, nonce, payload, aad);
		this._index++;
		if (isLast) this._wipe();
		return plaintext;
	}

	feed(bytes: Uint8Array): Uint8Array[] {
		if (!this._framed) throw new Error('XChaCha20StreamOpener: feed() requires { framed: true }');
		if (this._dead)    throw new Error('XChaCha20StreamOpener: stream is closed');
		const buf      = this._buf as Uint8Array;
		const maxFrame = this._maxFrame as number;

		const results: Uint8Array[] = [];
		let consumed = 0;

		// ── Phase 1: drain carry-over ─────────────────────────────────────
		if (this._bufLen > 0) {
			if (this._bufLen < 4) {
				const need = 4 - this._bufLen;
				const take = Math.min(need, bytes.length - consumed);
				buf.set(bytes.subarray(consumed, consumed + take), this._bufLen);
				this._bufLen += take; consumed += take;
				if (this._bufLen < 4) return results;
			}
			const sealedLen = (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0;
			if (sealedLen === 0 || sealedLen > (maxFrame - 4)) {
				this._wipe();
				throw new Error('XChaCha20StreamOpener: invalid sealed chunk length');
			}
			const frameLen    = 4 + sealedLen;
			const haveInBuf   = this._bufLen;
			const needMore    = frameLen - haveInBuf;
			if (needMore > 0) {
				const take = Math.min(needMore, bytes.length - consumed);
				buf.set(bytes.subarray(consumed, consumed + take), haveInBuf);
				this._bufLen += take; consumed += take;
				if (this._bufLen < frameLen) return results;
			}
			results.push(this._openRaw(buf.subarray(4, frameLen)));
			this._bufLen = 0;
			if (this._dead) {
				if (consumed < bytes.length) {
					this._wipe(); throw new Error('XChaCha20StreamOpener: unexpected bytes after final chunk');
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
				throw new Error('XChaCha20StreamOpener: invalid sealed chunk length');
			}
			const frameLen = 4 + sealedLen;
			if (bytes.length - pos < frameLen) break;
			results.push(this._openRaw(bytes.subarray(pos + 4, pos + frameLen)));
			if (this._dead) {
				const remaining = bytes.length - pos - frameLen;
				if (remaining > 0) {
					this._wipe(); throw new Error('XChaCha20StreamOpener: unexpected bytes after final chunk');
				}
				return results;
			}
			pos += frameLen;
		}

		// ── Carry over incomplete trailing bytes ──────────────────────────
		const leftover = bytes.length - pos;
		if (leftover > 0) {
			if (leftover > maxFrame) {
				this._wipe(); throw new Error('XChaCha20StreamOpener: input exceeds maximum frame size');
			}
			buf.set(bytes.subarray(pos), 0);
			this._bufLen = leftover;
		}
		return results;
	}

	private _wipe(): void {
		if (this._dead) return;
		wipe(this._key);
		wipe(this._id);
		wipe(this._aad);
		this._x.wipeBuffers();
		if (this._framed) {
			wipe(this._buf as Uint8Array); this._bufLen = 0;
		}
		this._dead = true;
	}

	dispose(): void {
		if (!this._dead) this._wipe();
	}
}
