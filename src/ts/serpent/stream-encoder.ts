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
// src/ts/serpent/stream-encoder.ts
//
// Tier 2 pure-TS composition: SerpentStreamSealer / SerpentStreamOpener
// with u32be length-prefixed framing.
//
// SerpentStreamEncoder: wraps SerpentStreamSealer, prepends u32be(sealedLen)
// SerpentStreamDecoder: wraps SerpentStreamOpener, buffers input and assembles
//                       complete frames before dispatching to opener.open()
//
// Wire format per chunk:
//   u32be(sealedLen) || IV(16) || CBC_ciphertext(padded) || HMAC(32)
//
// Use these classes when chunks will be concatenated into a flat byte array
// (files, buffered TCP, etc). Use SerpentStreamSealer/Opener directly when
// the transport already frames messages (WebSocket, IPC, etc).

import { SerpentStreamSealer, SerpentStreamOpener } from './stream-sealer.js';
import { _serpentReady } from './index.js';
import { _sha2Ready } from '../sha2/index.js';
import { wipe } from '../utils.js';
import { u32be } from './stream.js';

// ── SerpentStreamEncoder ─────────────────────────────────────────────────────

type EncoderState = 'fresh' | 'encoding' | 'dead';

export class SerpentStreamEncoder {
	private readonly _sealer: SerpentStreamSealer;
	private _state: EncoderState;

	// _nonce, _ivs: test seams — passed through to SerpentStreamSealer
	constructor(key: Uint8Array, chunkSize?: number, _nonce?: Uint8Array, _ivs?: Uint8Array[]) {
		if (!_serpentReady()) throw new Error('leviathan-crypto: call init([\'serpent\']) before using SerpentStreamEncoder');
		if (!_sha2Ready())    throw new Error('leviathan-crypto: call init([\'sha2\']) before using SerpentStreamEncoder');
		this._sealer = new SerpentStreamSealer(key, chunkSize, _nonce, _ivs);
		this._state  = 'fresh';
	}

	header(): Uint8Array {
		if (this._state === 'encoding') throw new Error('SerpentStreamEncoder: header() already called');
		if (this._state === 'dead')     throw new Error('SerpentStreamEncoder: stream is closed');
		this._state = 'encoding';
		return this._sealer.header();
	}

	encode(plaintext: Uint8Array): Uint8Array {
		if (this._state === 'fresh') throw new Error('SerpentStreamEncoder: call header() first');
		if (this._state === 'dead')  throw new Error('SerpentStreamEncoder: stream is closed');
		const sealed = this._sealer.seal(plaintext);
		return _prependLen(sealed);
	}

	encodeFinal(plaintext: Uint8Array): Uint8Array {
		if (this._state === 'fresh') throw new Error('SerpentStreamEncoder: call header() first');
		if (this._state === 'dead')  throw new Error('SerpentStreamEncoder: stream is closed');
		const sealed = this._sealer.final(plaintext);
		this._state  = 'dead';
		return _prependLen(sealed);
	}

	dispose(): void {
		if (this._state !== 'dead') {
			this._sealer.dispose();
			this._state = 'dead';
		}
	}
}

// ── SerpentStreamDecoder ─────────────────────────────────────────────────────

export class SerpentStreamDecoder {
	private readonly _opener:   SerpentStreamOpener;
	private readonly _buf:      Uint8Array;  // fixed-size accumulation buffer
	private readonly _maxFrame: number;      // 4 + max sealed chunk size
	private _bufLen: number;                 // valid bytes currently in _buf
	private _dead:   boolean;

	constructor(key: Uint8Array, header: Uint8Array) {
		if (!_serpentReady()) throw new Error('leviathan-crypto: call init([\'serpent\']) before using SerpentStreamDecoder');
		if (!_sha2Ready())    throw new Error('leviathan-crypto: call init([\'sha2\']) before using SerpentStreamDecoder');
		this._opener = new SerpentStreamOpener(key, header);

		// Parse chunkSize from stream header (bytes 16..20, u32be)
		const cs = (header[16] << 24 | header[17] << 16 | header[18] << 8 | header[19]) >>> 0;

		// Max sealed chunk size: IV(16) + PKCS7-padded ciphertext + HMAC(32)
		// PKCS7: plaintext always padded to next multiple of 16 (minimum 1 pad byte)
		const maxSealed   = 16 + (cs + (16 - (cs % 16))) + 32;
		this._maxFrame    = 4 + maxSealed;
		this._buf         = new Uint8Array(this._maxFrame);
		this._bufLen      = 0;
		this._dead        = false;
	}

	feed(bytes: Uint8Array): Uint8Array[] {
		if (this._dead) throw new Error('SerpentStreamDecoder: stream is closed');

		// Append incoming bytes to accumulation buffer
		if (this._bufLen + bytes.length > this._maxFrame) {
			throw new Error('SerpentStreamDecoder: input exceeds maximum frame size');
		}
		this._buf.set(bytes, this._bufLen);
		this._bufLen += bytes.length;

		const results: Uint8Array[] = [];

		while (true) {
			// Need at least 4 bytes for the length prefix
			if (this._bufLen < 4) break;

			const sealedLen = (
				(this._buf[0] << 24 | this._buf[1] << 16 |
				 this._buf[2] << 8  | this._buf[3]) >>> 0
			);
			const frameLen = 4 + sealedLen;

			// Need the full frame
			if (this._bufLen < frameLen) break;

			// Complete frame — dispatch to opener
			const sealedChunk = this._buf.subarray(4, frameLen);
			const plaintext   = this._opener.open(sealedChunk);
			results.push(plaintext);

			if (this._opener.closed) {
				// After final chunk: any leftover bytes are a protocol error
				const remaining = this._bufLen - frameLen;
				if (remaining > 0) {
					this._wipe();
					throw new Error('SerpentStreamDecoder: unexpected bytes after final chunk');
				}
				this._wipe();
				return results;
			}

			// Shift remaining bytes to front of buffer — no allocation
			const remaining = this._bufLen - frameLen;
			this._buf.copyWithin(0, frameLen, frameLen + remaining);
			this._bufLen = remaining;
		}

		return results;
	}

	private _wipe(): void {
		wipe(this._buf);
		this._bufLen = 0;
		this._opener.dispose();
		this._dead = true;
	}

	dispose(): void {
		if (!this._dead) this._wipe();
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

function _prependLen(chunk: Uint8Array): Uint8Array {
	const out = new Uint8Array(4 + chunk.length);
	out.set(u32be(chunk.length), 0);
	out.set(chunk, 4);
	return out;
}
