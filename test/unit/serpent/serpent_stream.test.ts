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
/**
 * SerpentStream unit tests — chunked authenticated encryption
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, SerpentStream, hexToBytes, bytesToHex } from '../../../src/ts/index.js';
import { serpentStreamFixture } from '../../vectors/serpent.js';

let stream: SerpentStream;

beforeAll(async () => {
	await init(['serpent', 'sha2']);
	stream = new SerpentStream();
});

// ── Round-trip correctness ────────────────────────────────────────────────────

describe('SerpentStream — round-trip correctness', () => {
	// GATE
	it('gate — fixture round-trip (3 x 1024-byte chunks)', () => {
		const key = hexToBytes(serpentStreamFixture.key);
		const pt = hexToBytes(serpentStreamFixture.plaintext);
		const ct = stream.seal(key, pt, serpentStreamFixture.chunkSize);
		const recovered = stream.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});

	it('round-trip with default chunk size (64KB), 200KB plaintext', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(200 * 1024);
		for (let off = 0; off < pt.length; off += 65536)
			crypto.getRandomValues(pt.subarray(off, Math.min(off + 65536, pt.length)));
		const ct = stream.seal(key, pt);
		const recovered = stream.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});

	it('round-trip with empty plaintext', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(0);
		const ct = stream.seal(key, pt);
		const recovered = stream.open(key, ct);
		expect(recovered.length).toBe(0);
	});

	it('round-trip with plaintext exactly one chunk', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const cs = 1024;
		const pt = new Uint8Array(cs);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, cs);
		const recovered = stream.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});

	it('round-trip with plaintext exactly chunk_size + 1 (forces 2 chunks)', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const cs = 1024;
		const pt = new Uint8Array(cs + 1);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, cs);
		const recovered = stream.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});

	it('open() output is byte-identical to original plaintext', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(256);
		for (let i = 0; i < 256; i++) pt[i] = i & 0xff;
		const ct = stream.seal(key, pt, 1024);
		const recovered = stream.open(key, ct);
		expect(Array.from(recovered)).toEqual(Array.from(pt));
	});
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('SerpentStream — authentication', () => {
	it('tampered ciphertext byte throws on open()', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(128);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024).slice();
		// Flip a byte in the first chunk body (after 28-byte header)
		ct[30] ^= 0x01;
		expect(() => stream.open(key, ct)).toThrow('SerpentStream: authentication failed');
	});

	it('tampered tag byte throws on open()', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(128);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024).slice();
		// Flip a byte in the tag area (last 32 bytes of the chunk)
		ct[ct.length - 1] ^= 0x01;
		expect(() => stream.open(key, ct)).toThrow('SerpentStream: authentication failed');
	});

	it('open() never returns partial plaintext — exception propagates', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		// 3 chunks at 1024 bytes each
		const pt = new Uint8Array(3 * 1024);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024).slice();
		// Tamper with the second chunk body (after header + first chunk wire)
		// First chunk wire = 1024 + 32 = 1056 bytes, starts at 28
		// Second chunk starts at 28 + 1056 = 1084
		ct[1084 + 10] ^= 0x01;
		expect(() => stream.open(key, ct)).toThrow('SerpentStream: authentication failed');
	});

	it('wrong key on open() throws', () => {
		const key1 = new Uint8Array(32);
		crypto.getRandomValues(key1);
		const key2 = new Uint8Array(32);
		crypto.getRandomValues(key2);
		const pt = new Uint8Array(128);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key1, pt, 1024);
		expect(() => stream.open(key2, ct)).toThrow('SerpentStream: authentication failed');
	});
});

// ── Header integrity (implicit) ───────────────────────────────────────────────

describe('SerpentStream — header integrity', () => {
	it('truncated wire format throws on open()', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(2 * 1024);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024);
		// Remove final chunk bytes (keep only header + first chunk)
		const truncated = ct.slice(0, 28 + 1024 + 32);
		expect(() => stream.open(key, truncated)).toThrow();
	});
});

// ── Position binding ──────────────────────────────────────────────────────────

describe('SerpentStream — position binding', () => {
	it('swapped chunk wire blocks cause open() to throw', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const cs = 1024;
		const pt = new Uint8Array(3 * cs);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, cs).slice();

		// Parse chunk boundaries and swap chunks 0 and 1
		const wireChunkSize = cs + 32;
		const chunk0Start = 28;
		const chunk1Start = 28 + wireChunkSize;
		const chunk0 = ct.slice(chunk0Start, chunk0Start + wireChunkSize);
		const chunk1 = ct.slice(chunk1Start, chunk1Start + wireChunkSize);
		// Swap
		ct.set(chunk1, chunk0Start);
		ct.set(chunk0, chunk1Start);

		expect(() => stream.open(key, ct)).toThrow('SerpentStream: authentication failed');
	});
});

// ── Input validation ──────────────────────────────────────────────────────────

describe('SerpentStream — input validation', () => {
	it('seal() throws RangeError for wrong key length', () => {
		expect(() => stream.seal(new Uint8Array(16), new Uint8Array(64))).toThrow(RangeError);
	});

	it('seal() throws RangeError for chunkSize < CHUNK_MIN', () => {
		const key = new Uint8Array(32);
		expect(() => stream.seal(key, new Uint8Array(64), 512)).toThrow(RangeError);
	});

	it('seal() throws RangeError for chunkSize > CHUNK_MAX', () => {
		const key = new Uint8Array(32);
		expect(() => stream.seal(key, new Uint8Array(64), 65537)).toThrow(RangeError);
	});

	it('open() throws RangeError for wrong key length', () => {
		const key = new Uint8Array(32);
		const ct = stream.seal(key, new Uint8Array(64));
		expect(() => stream.open(new Uint8Array(16), ct)).toThrow(RangeError);
	});

	it('open() throws RangeError for ciphertext too short', () => {
		const key = new Uint8Array(32);
		expect(() => stream.open(key, new Uint8Array(59))).toThrow(RangeError);
		expect(() => stream.open(key, new Uint8Array(59))).toThrow('SerpentStream: ciphertext too short');
	});
});

// ── Lifecycle ─────────────────────────────────────────────────────────────────

describe('SerpentStream — lifecycle', () => {
	it('multiple seal() calls produce independent results', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(64);
		crypto.getRandomValues(pt);
		const ct1 = stream.seal(key, pt, 1024);
		const ct2 = stream.seal(key, pt, 1024);
		// Different stream nonces mean different outputs
		let same = true;
		for (let i = 0; i < ct1.length; i++) {
			if (ct1[i] !== ct2[i]) {
				same = false; break;
			}
		}
		expect(same).toBe(false);
		// But both decrypt correctly
		expect(bytesToHex(stream.open(key, ct1))).toBe(bytesToHex(pt));
		expect(bytesToHex(stream.open(key, ct2))).toBe(bytesToHex(pt));
	});

	it('dispose() does not throw', () => {
		const s = new SerpentStream();
		expect(() => s.dispose()).not.toThrow();
	});
});
