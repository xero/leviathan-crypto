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
 * SerpentStream KAT tests — known-answer, security property, and boundary tests.
 * Vectors are self-generated with nonce injection seam, verified against primitives.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, SerpentStream, hexToBytes, bytesToHex } from '../../../src/ts/index.js';
import { streamSS1, streamSS3, streamSS6 } from '../../vectors/serpent_composition.js';

let stream: SerpentStream;

beforeAll(async () => {
	await init(['serpent', 'sha2']);
	stream = new SerpentStream();
});

// ── Known-answer tests ──────────────────────────────────────────────────────

describe('SerpentStream KAT — known-answer', () => {
	// GATE
	it('SS-1: seal with injected nonce matches expected output', () => {
		const key = hexToBytes(streamSS1.key);
		const pt = hexToBytes(streamSS1.plaintext);
		const nonce = hexToBytes(streamSS1.streamNonce);
		const out = stream.seal(key, pt, streamSS1.chunkSize, nonce);
		expect(bytesToHex(out)).toBe(streamSS1.output);
	});

	it('SS-1: header fields — nonce, chunkSize, chunkCount', () => {
		const out = hexToBytes(streamSS1.output);
		expect(bytesToHex(out.subarray(0, 16))).toBe(streamSS1.streamNonce);
		// chunkSize u32be = 0x00000400 = 1024
		expect(bytesToHex(out.subarray(16, 20))).toBe('00000400');
		// chunkCount u64be = 1
		expect(bytesToHex(out.subarray(20, 28))).toBe('0000000000000001');
	});

	it('SS-3: seal with injected nonce matches expected output', () => {
		const key = hexToBytes(streamSS3.key);
		const pt = hexToBytes(streamSS3.plaintext);
		const nonce = hexToBytes(streamSS3.streamNonce);
		const out = stream.seal(key, pt, streamSS3.chunkSize, nonce);
		expect(bytesToHex(out)).toBe(streamSS3.output);
	});

	it('SS-3: all 3 chunk tags match expected values', () => {
		const out = hexToBytes(streamSS3.output);
		for (const chunk of streamSS3.chunks) {
			const wireStart = 28 + chunk.index * (streamSS3.chunkSize + 32);
			const tag = out.subarray(wireStart + streamSS3.chunkSize, wireStart + streamSS3.chunkSize + 32);
			expect(bytesToHex(tag)).toBe(chunk.tag);
		}
	});

	it('SS-6: seal with injected nonce matches expected output', () => {
		const key = hexToBytes(streamSS6.key);
		const pt = hexToBytes(streamSS6.plaintext);
		const nonce = hexToBytes(streamSS6.streamNonce);
		const out = stream.seal(key, pt, streamSS6.chunkSize, nonce);
		expect(bytesToHex(out)).toBe(streamSS6.output);
	});
});

// ── Security property tests (random nonces) ─────────────────────────────────

describe('SerpentStream KAT — security properties', () => {
	it('truncation: seal 3 chunks, strip last chunk → open throws', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(3 * 1024);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024);
		// Keep only header + first 2 chunk wires (strip last chunk)
		const truncated = ct.slice(0, 28 + 2 * (1024 + 32));
		expect(() => stream.open(key, truncated)).toThrow();
	});

	it('reorder: swap chunk 0 and 1 in a 3-chunk stream → open throws', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(3 * 1024);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024).slice();
		const wireChunkSize = 1024 + 32;
		const chunk0 = ct.slice(28, 28 + wireChunkSize);
		const chunk1 = ct.slice(28 + wireChunkSize, 28 + 2 * wireChunkSize);
		ct.set(chunk1, 28);
		ct.set(chunk0, 28 + wireChunkSize);
		expect(() => stream.open(key, ct)).toThrow('SerpentStream: authentication failed');
	});

	it('reorder: swap chunk 0 and 1 in a 6-chunk stream → open throws', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(6 * 1024);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024).slice();
		const wireChunkSize = 1024 + 32;
		const chunk0 = ct.slice(28, 28 + wireChunkSize);
		const chunk1 = ct.slice(28 + wireChunkSize, 28 + 2 * wireChunkSize);
		ct.set(chunk1, 28);
		ct.set(chunk0, 28 + wireChunkSize);
		expect(() => stream.open(key, ct)).toThrow('SerpentStream: authentication failed');
	});

	it('cross-stream: splice chunk 0 from stream A into stream B → open throws', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const ptA = new Uint8Array(3 * 1024);
		crypto.getRandomValues(ptA);
		const ptB = new Uint8Array(3 * 1024);
		crypto.getRandomValues(ptB);
		const ctA = stream.seal(key, ptA, 1024);
		const ctB = stream.seal(key, ptB, 1024).slice();
		// Splice chunk 0 from stream A into stream B at position 0
		const wireChunkSize = 1024 + 32;
		const chunkA0 = ctA.slice(28, 28 + wireChunkSize);
		ctB.set(chunkA0, 28);
		expect(() => stream.open(key, ctB)).toThrow('SerpentStream: authentication failed');
	});

	it('auth: flip one byte in chunk body of a 3-chunk stream → throws', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(3 * 1024);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024).slice();
		ct[30] ^= 0x01; // flip byte in first chunk body
		expect(() => stream.open(key, ct)).toThrow('SerpentStream: authentication failed');
	});
});

// ── Chunk size boundary tests ───────────────────────────────────────────────

describe('SerpentStream KAT — chunk size boundaries', () => {
	it('chunk size boundary min (1024): round-trip 1024-byte plaintext', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(1024);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 1024);
		const recovered = stream.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});

	it('chunk size boundary max (65536): round-trip 65536-byte plaintext', () => {
		const key = new Uint8Array(32);
		crypto.getRandomValues(key);
		const pt = new Uint8Array(65536);
		crypto.getRandomValues(pt);
		const ct = stream.seal(key, pt, 65536);
		const recovered = stream.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});
});
