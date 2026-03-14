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
 * SerpentStreamEncoder / SerpentStreamDecoder unit tests
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, SerpentStreamEncoder, SerpentStreamDecoder, hexToBytes, bytesToHex } from '../../../src/ts/index.js';
import { SE1, SE2, SE3 } from '../../vectors/serpent_stream_encoder.js';

beforeAll(async () => {
	await init(['serpent', 'sha2']);
});

// ── helpers ──────────────────────────────────────────────────────────────────

function encodeVector(v: typeof SE1) {
	const key   = hexToBytes(v.key);
	const nonce = hexToBytes(v.nonce);
	const ivs   = v.ivs.map(hexToBytes);
	const enc   = new SerpentStreamEncoder(key, v.chunkSize, nonce, ivs);
	const hdr   = enc.header();
	const chunks: Uint8Array[] = [];
	for (let i = 0; i < v.plaintexts.length; i++) {
		const isLast = i === v.plaintexts.length - 1;
		chunks.push(isLast
			? enc.encodeFinal(hexToBytes(v.plaintexts[i]))
			: enc.encode(hexToBytes(v.plaintexts[i])));
	}
	return { hdr, chunks };
}

// ── Gate ─────────────────────────────────────────────────────────────────────

describe('SerpentStreamEncoder — Gate 12', () => {
	// GATE
	it('SE1: encoder produces expected header and encoded chunk', () => {
		const { hdr, chunks } = encodeVector(SE1);
		expect(bytesToHex(hdr)).toBe(SE1.header);
		expect(chunks.length).toBe(1);
		expect(bytesToHex(chunks[0])).toBe(SE1.encodedChunks[0]);
	});
});

// ── KAT ──────────────────────────────────────────────────────────────────────

describe('SerpentStreamEncoder — KAT', () => {
	it('SE1: decoder recovers plaintext from single feed() call', () => {
		const key   = hexToBytes(SE1.key);
		const header = hexToBytes(SE1.header);
		const decoder = new SerpentStreamDecoder(key, header);
		const encoded = hexToBytes(SE1.encodedChunks[0]);
		const results = decoder.feed(encoded);
		expect(results.length).toBe(1);
		expect(bytesToHex(results[0])).toBe(SE1.plaintexts[0]);
	});

	it('SE2: three-chunk encode round-trip', () => {
		const { hdr, chunks } = encodeVector(SE2);
		for (let i = 0; i < chunks.length; i++) {
			expect(bytesToHex(chunks[i])).toBe(SE2.encodedChunks[i]);
		}
		const decoder = new SerpentStreamDecoder(hexToBytes(SE2.key), hdr);
		const results: Uint8Array[] = [];
		for (const chunk of chunks) {
			results.push(...decoder.feed(chunk));
		}
		expect(results.length).toBe(3);
		for (let i = 0; i < 3; i++) {
			expect(bytesToHex(results[i])).toBe(SE2.plaintexts[i]);
		}
	});

	it('SE3: two-chunk round-trip', () => {
		const { hdr, chunks } = encodeVector(SE3);
		for (let i = 0; i < chunks.length; i++) {
			expect(bytesToHex(chunks[i])).toBe(SE3.encodedChunks[i]);
		}
		const decoder = new SerpentStreamDecoder(hexToBytes(SE3.key), hdr);
		const results: Uint8Array[] = [];
		for (const chunk of chunks) {
			results.push(...decoder.feed(chunk));
		}
		expect(results.length).toBe(2);
		for (let i = 0; i < 2; i++) {
			expect(bytesToHex(results[i])).toBe(SE3.plaintexts[i]);
		}
	});

	it('SE2: length prefix of each chunk is correct', () => {
		const { chunks } = encodeVector(SE2);
		for (const chunk of chunks) {
			const prefixLen = (chunk[0] << 24 | chunk[1] << 16 | chunk[2] << 8 | chunk[3]) >>> 0;
			expect(prefixLen).toBe(chunk.length - 4);
		}
	});
});

// ── Framing ──────────────────────────────────────────────────────────────────

describe('SerpentStreamEncoder — framing', () => {
	it('byte-at-a-time feed: SE1 — correct plaintext emitted only on final completing byte', () => {
		const key     = hexToBytes(SE1.key);
		const header  = hexToBytes(SE1.header);
		const encoded = hexToBytes(SE1.encodedChunks[0]);
		const decoder = new SerpentStreamDecoder(key, header);
		const results: Uint8Array[] = [];
		for (let i = 0; i < encoded.length; i++) {
			const out = decoder.feed(encoded.subarray(i, i + 1));
			results.push(...out);
		}
		expect(results.length).toBe(1);
		expect(bytesToHex(results[0])).toBe(SE1.plaintexts[0]);
	});

	it('split feed: SE1 ciphertext split at arbitrary mid-frame boundary', () => {
		const { hdr, chunks } = encodeVector(SE1);
		const encoded = chunks[0];
		// Split a single frame at its midpoint
		const split = Math.floor(encoded.length / 2);
		const decoder = new SerpentStreamDecoder(hexToBytes(SE1.key), hdr);
		const r1 = decoder.feed(encoded.subarray(0, split));
		expect(r1.length).toBe(0);
		const r2 = decoder.feed(encoded.subarray(split));
		expect(r2.length).toBe(1);
		expect(bytesToHex(r2[0])).toBe(SE1.plaintexts[0]);
	});

	it('multi-frame feed: SE2 chunks fed sequentially — all plaintext returned', () => {
		const { hdr, chunks } = encodeVector(SE2);
		const decoder = new SerpentStreamDecoder(hexToBytes(SE2.key), hdr);
		const results: Uint8Array[] = [];
		for (const chunk of chunks) {
			results.push(...decoder.feed(chunk));
		}
		expect(results.length).toBe(3);
		for (let i = 0; i < 3; i++) {
			expect(bytesToHex(results[i])).toBe(SE2.plaintexts[i]);
		}
	});

	it('post-final leftover bytes → throws', () => {
		const { hdr, chunks } = encodeVector(SE2);
		// SE2's final chunk is a partial chunk (ef×512) — sealed size is well
		// under maxFrame, so appending a trailing byte fits in the buffer and
		// exercises the leftover-after-final path inside feed().
		const finalChunk = chunks[2]; // encodeFinal(ef×512)
		const withExtra = new Uint8Array(finalChunk.length + 1);
		withExtra.set(finalChunk, 0);
		withExtra[finalChunk.length] = 0xff;
		const decoder = new SerpentStreamDecoder(hexToBytes(SE2.key), hdr);
		// Feed the first two chunks to advance the opener to the final position
		decoder.feed(chunks[0]);
		decoder.feed(chunks[1]);
		expect(() => decoder.feed(withExtra)).toThrow('unexpected bytes after final chunk');
	});

	it('feed after dead → throws', () => {
		const { hdr, chunks } = encodeVector(SE1);
		const decoder = new SerpentStreamDecoder(hexToBytes(SE1.key), hdr);
		decoder.feed(chunks[0]);
		expect(() => decoder.feed(new Uint8Array(1))).toThrow('stream is closed');
	});
});

// ── Security ─────────────────────────────────────────────────────────────────

describe('SerpentStreamEncoder — security', () => {
	it('tampered length prefix → decoder throws', () => {
		const { hdr, chunks } = encodeVector(SE1);
		const tampered = chunks[0].slice();
		// Shrink the length prefix so decoder extracts a truncated sealed chunk
		tampered[2] ^= 0x04;
		const decoder = new SerpentStreamDecoder(hexToBytes(SE1.key), hdr);
		expect(() => decoder.feed(tampered)).toThrow('authentication failed');
	});

	it('tampered chunk body → throws', () => {
		const { hdr, chunks } = encodeVector(SE1);
		const tampered = chunks[0].slice();
		// Flip a byte in the sealed payload (after the 4-byte prefix + 16-byte IV)
		tampered[24] ^= 0xff;
		const decoder = new SerpentStreamDecoder(hexToBytes(SE1.key), hdr);
		expect(() => decoder.feed(tampered)).toThrow('authentication failed');
	});

	it('cross-stream splice: SE1 encoded chunk fed to SE3 decoder → throws', () => {
		const se1enc = encodeVector(SE1);
		const se3enc = encodeVector(SE3);
		const decoder = new SerpentStreamDecoder(hexToBytes(SE3.key), se3enc.hdr);
		expect(() => decoder.feed(se1enc.chunks[0])).toThrow('authentication failed');
	});

	it('out-of-order chunks from SE2 → throws', () => {
		const { hdr, chunks } = encodeVector(SE2);
		const decoder = new SerpentStreamDecoder(hexToBytes(SE2.key), hdr);
		// Feed chunk[1] first (out of order) — auth should fail at index 0
		expect(() => decoder.feed(chunks[1])).toThrow('authentication failed');
	});
});

// ── State machine ────────────────────────────────────────────────────────────

describe('SerpentStreamEncoder — state machine', () => {
	it('header() twice → throws', () => {
		const key = new Uint8Array(64);
		const enc = new SerpentStreamEncoder(key);
		enc.header();
		expect(() => enc.header()).toThrow('header() already called');
		enc.dispose();
	});

	it('encode() before header() → throws', () => {
		const key = new Uint8Array(64);
		const enc = new SerpentStreamEncoder(key);
		expect(() => enc.encode(new Uint8Array(65536))).toThrow('call header() first');
		enc.dispose();
	});

	it('encode() after encodeFinal() → throws', () => {
		const key = new Uint8Array(64);
		const enc = new SerpentStreamEncoder(key);
		enc.header();
		enc.encodeFinal(new Uint8Array(0));
		expect(() => enc.encode(new Uint8Array(65536))).toThrow('stream is closed');
	});

	it('constructor with wrong key length → RangeError', () => {
		expect(() => new SerpentStreamEncoder(new Uint8Array(32))).toThrow(RangeError);
	});

	it('decoder constructor with wrong header length → RangeError', () => {
		expect(() => new SerpentStreamDecoder(new Uint8Array(64), new Uint8Array(10))).toThrow(RangeError);
	});
});

// ── Lifecycle ────────────────────────────────────────────────────────────────

describe('SerpentStreamEncoder — lifecycle', () => {
	it('dispose() mid-stream encoder → no throw, dead', () => {
		const key = new Uint8Array(64);
		const enc = new SerpentStreamEncoder(key, 1024);
		enc.header();
		enc.dispose();
		expect(() => enc.encode(new Uint8Array(1024))).toThrow('stream is closed');
	});

	it('dispose() mid-stream decoder → no throw, dead', () => {
		const { hdr, chunks } = encodeVector(SE2);
		const decoder = new SerpentStreamDecoder(hexToBytes(SE2.key), hdr);
		decoder.feed(chunks[0]);
		decoder.dispose();
		expect(() => decoder.feed(chunks[1])).toThrow('stream is closed');
	});

	it('dispose() after encodeFinal() → no-op', () => {
		const key = new Uint8Array(64);
		const enc = new SerpentStreamEncoder(key);
		enc.header();
		enc.encodeFinal(new Uint8Array(0));
		expect(() => enc.dispose()).not.toThrow();
	});
});
