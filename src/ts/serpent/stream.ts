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
// src/ts/serpent/stream.ts
//
// SerpentStream — chunked authenticated encryption for large payloads.
// Tier 2 pure-TS composition: SerpentCtr + HMAC_SHA256 + HKDF_SHA256.

import { SerpentCtr, _serpentReady } from './index.js';
import { HMAC_SHA256, HKDF_SHA256, _sha2Ready } from '../sha2/index.js';
import { constantTimeEqual } from '../utils.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const DOMAIN    = 'serpent-stream-v1';  // UTF-8, 17 bytes
const ZERO_IV   = new Uint8Array(16);   // fixed zero IV for CTR
const CHUNK_MIN = 1024;                 // 1 KB
const CHUNK_MAX = 65536;               // 64 KB
const CHUNK_DEF = 65536;               // default

// ── Internal helpers ──────────────────────────────────────────────────────────

export function u32be(n: number): Uint8Array {
	const b = new Uint8Array(4);
	b[0] = (n >>> 24) & 0xff;
	b[1] = (n >>> 16) & 0xff;
	b[2] = (n >>> 8) & 0xff;
	b[3] = n & 0xff;
	return b;
}

export function u64be(n: number): Uint8Array {
	const b = new Uint8Array(8);
	// high 32 bits (safe for n < 2^53)
	const hi = Math.floor(n / 0x100000000);
	const lo = n >>> 0;
	b[0] = (hi >>> 24) & 0xff;
	b[1] = (hi >>> 16) & 0xff;
	b[2] = (hi >>> 8) & 0xff;
	b[3] = hi & 0xff;
	b[4] = (lo >>> 24) & 0xff;
	b[5] = (lo >>> 16) & 0xff;
	b[6] = (lo >>> 8) & 0xff;
	b[7] = lo & 0xff;
	return b;
}

const DOMAIN_BYTES = new TextEncoder().encode(DOMAIN);

export function chunkInfo(
	streamNonce: Uint8Array,
	chunkSize:   number,
	chunkCount:  number,
	index:       number,
	isLast:      boolean,
): Uint8Array {
	// 17 + 16 + 4 + 8 + 8 + 1 = 54 bytes
	const info = new Uint8Array(54);
	let off = 0;
	info.set(DOMAIN_BYTES, off); off += 17;
	info.set(streamNonce, off); off += 16;
	info.set(u32be(chunkSize), off); off += 4;
	info.set(u64be(chunkCount), off); off += 8;
	info.set(u64be(index), off); off += 8;
	info[off] = isLast ? 0x01 : 0x00;
	return info;
}

export function deriveChunkKeys(
	hkdf:        HKDF_SHA256,
	masterKey:   Uint8Array,
	streamNonce: Uint8Array,
	chunkSize:   number,
	chunkCount:  number,
	index:       number,
	isLast:      boolean,
): { encKey: Uint8Array; macKey: Uint8Array } {
	const info = chunkInfo(streamNonce, chunkSize, chunkCount, index, isLast);
	const derived = hkdf.derive(masterKey, streamNonce, info, 64);
	return {
		encKey: derived.subarray(0, 32),
		macKey: derived.subarray(32, 64),
	};
}

// ── Exported chunk-level ops (used by Part 2 pool worker) ─────────────────────

/**
 * Encrypt one chunk. Returns ciphertext || hmac_tag (32 bytes).
 * Does not generate keys -- caller provides encKey and macKey.
 */
export function sealChunk(
	ctr:     SerpentCtr,
	hmac:    HMAC_SHA256,
	encKey:  Uint8Array,
	macKey:  Uint8Array,
	chunk:   Uint8Array,
): Uint8Array {
	ctr.beginEncrypt(encKey, ZERO_IV);
	const ciphertext = ctr.encryptChunk(chunk);
	const tag = hmac.hash(macKey, ciphertext);
	const out = new Uint8Array(ciphertext.length + 32);
	out.set(ciphertext, 0);
	out.set(tag, ciphertext.length);
	return out;
}

/**
 * Decrypt one chunk. Throws 'SerpentStream: authentication failed' on bad tag.
 * Returns plaintext.
 */
export function openChunk(
	ctr:     SerpentCtr,
	hmac:    HMAC_SHA256,
	encKey:  Uint8Array,
	macKey:  Uint8Array,
	wire:    Uint8Array,
): Uint8Array {
	if (wire.length < 32)
		throw new RangeError('SerpentStream: chunk wire data too short');
	const ciphertext = wire.subarray(0, wire.length - 32);
	const tag = wire.subarray(wire.length - 32);
	const expectedTag = hmac.hash(macKey, ciphertext);
	if (!constantTimeEqual(tag, expectedTag))
		throw new Error('SerpentStream: authentication failed');
	ctr.beginEncrypt(encKey, ZERO_IV);
	return ctr.encryptChunk(ciphertext);
}

// ── SerpentStream class ───────────────────────────────────────────────────────

export class SerpentStream {
	private readonly _ctr:  SerpentCtr;
	private readonly _hmac: HMAC_SHA256;
	private readonly _hkdf: HKDF_SHA256;

	constructor() {
		if (!_serpentReady() || !_sha2Ready())
			throw new Error('leviathan-crypto: call init([\'serpent\', \'sha2\']) before using SerpentStream');
		this._ctr = new SerpentCtr({ dangerUnauthenticated: true });
		this._hmac = new HMAC_SHA256();
		this._hkdf = new HKDF_SHA256();
	}

	seal(key: Uint8Array, plaintext: Uint8Array, chunkSize?: number): Uint8Array {
		if (key.length !== 32)
			throw new RangeError(`SerpentStream key must be 32 bytes (got ${key.length})`);
		const cs = chunkSize ?? CHUNK_DEF;
		if (cs < CHUNK_MIN || cs > CHUNK_MAX)
			throw new RangeError(`SerpentStream chunkSize must be ${CHUNK_MIN}..${CHUNK_MAX} (got ${cs})`);

		const streamNonce = new Uint8Array(16);
		crypto.getRandomValues(streamNonce);

		const chunkCount = plaintext.length === 0 ? 1 : Math.ceil(plaintext.length / cs);

		// Compute total output size
		let totalWire = 28; // header
		for (let i = 0; i < chunkCount; i++) {
			const start = i * cs;
			const end = Math.min(start + cs, plaintext.length);
			totalWire += (end - start) + 32;
		}

		const out = new Uint8Array(totalWire);
		// Write header
		out.set(streamNonce, 0);
		out.set(u32be(cs), 16);
		out.set(u64be(chunkCount), 20);

		let pos = 28;
		for (let i = 0; i < chunkCount; i++) {
			const start = i * cs;
			const end = Math.min(start + cs, plaintext.length);
			const slice = plaintext.subarray(start, end);
			const isLast = i === chunkCount - 1;
			const { encKey, macKey } = deriveChunkKeys(
				this._hkdf, key, streamNonce, cs, chunkCount, i, isLast,
			);
			const wire = sealChunk(this._ctr, this._hmac, encKey, macKey, slice);
			out.set(wire, pos);
			pos += wire.length;
		}

		return out;
	}

	open(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
		if (key.length !== 32)
			throw new RangeError(`SerpentStream key must be 32 bytes (got ${key.length})`);
		if (ciphertext.length < 28 + 32)
			throw new RangeError('SerpentStream: ciphertext too short');

		// Parse header
		const streamNonce = ciphertext.subarray(0, 16);
		const csView = ciphertext.subarray(16, 20);
		const cs = (csView[0] << 24) | (csView[1] << 16) | (csView[2] << 8) | csView[3];
		const ccView = ciphertext.subarray(20, 28);
		let chunkCount = 0;
		for (let i = 0; i < 8; i++) chunkCount = chunkCount * 256 + ccView[i];

		// Compute total plaintext size
		let totalPt = 0;
		let pos = 28;
		for (let i = 0; i < chunkCount; i++) {
			const isLast = i === chunkCount - 1;
			const wireLen = isLast ? ciphertext.length - pos : cs + 32;
			totalPt += wireLen - 32;
			if (!isLast) pos += wireLen;
		}

		const plaintext = new Uint8Array(totalPt);
		pos = 28;
		let ptPos = 0;
		for (let i = 0; i < chunkCount; i++) {
			const isLast = i === chunkCount - 1;
			const wireLen = isLast ? ciphertext.length - pos : cs + 32;
			const wireSlice = ciphertext.subarray(pos, pos + wireLen);
			const { encKey, macKey } = deriveChunkKeys(
				this._hkdf, key, streamNonce, cs, chunkCount, i, isLast,
			);
			const pt = openChunk(this._ctr, this._hmac, encKey, macKey, wireSlice);
			plaintext.set(pt, ptPos);
			ptPos += pt.length;
			pos += wireLen;
		}

		return plaintext;
	}

	dispose(): void {
		this._ctr.dispose();
		this._hmac.dispose();
		this._hkdf.dispose();
	}
}
