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
 * SerpentStreamSealer / SerpentStreamOpener unit tests
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, SerpentStreamSealer, SerpentStreamOpener, hexToBytes, bytesToHex } from '../../../src/ts/index.js';
import { SS1, SS2, SS3 } from '../../vectors/serpent_stream_sealer.js';

beforeAll(async () => {
	await init(['serpent', 'sha2']);
});

// ── Gate ────────────────────────────────────────────────────────────────────

describe('SerpentStreamSealer — Gate 11', () => {
	// GATE
	it('SS1: sealer produces expected header and ciphertext chunk', () => {
		const key   = hexToBytes(SS1.key);
		const nonce = hexToBytes(SS1.nonce);
		const ivs   = SS1.ivs.map(hexToBytes);
		const sealer = new SerpentStreamSealer(key, SS1.chunkSize, nonce, ivs);
		const hdr = sealer.header();
		expect(bytesToHex(hdr)).toBe(SS1.header);
		const chunk = sealer.final(hexToBytes(SS1.plaintexts[0]));
		expect(bytesToHex(chunk)).toBe(SS1.cipherChunks[0]);
	});
});

// ── KAT ─────────────────────────────────────────────────────────────────────

describe('SerpentStreamSealer — KAT', () => {
	it('SS1: opener recovers plaintext from sealer output', () => {
		const key    = hexToBytes(SS1.key);
		const header = hexToBytes(SS1.header);
		const opener = new SerpentStreamOpener(key, header);
		const pt = opener.open(hexToBytes(SS1.cipherChunks[0]));
		expect(bytesToHex(pt)).toBe(SS1.plaintexts[0]);
	});

	it('SS2: three-chunk round-trip — seal×2 + final, open×3', () => {
		const key   = hexToBytes(SS2.key);
		const nonce = hexToBytes(SS2.nonce);
		const ivs   = SS2.ivs.map(hexToBytes);
		const sealer = new SerpentStreamSealer(key, SS2.chunkSize, nonce, ivs);
		const hdr = sealer.header();
		const c0 = sealer.seal(hexToBytes(SS2.plaintexts[0]));
		const c1 = sealer.seal(hexToBytes(SS2.plaintexts[1]));
		const c2 = sealer.final(hexToBytes(SS2.plaintexts[2]));
		expect(bytesToHex(c0)).toBe(SS2.cipherChunks[0]);
		expect(bytesToHex(c1)).toBe(SS2.cipherChunks[1]);
		expect(bytesToHex(c2)).toBe(SS2.cipherChunks[2]);

		const opener = new SerpentStreamOpener(key, hdr);
		expect(bytesToHex(opener.open(c0))).toBe(SS2.plaintexts[0]);
		expect(bytesToHex(opener.open(c1))).toBe(SS2.plaintexts[1]);
		expect(bytesToHex(opener.open(c2))).toBe(SS2.plaintexts[2]);
	});

	it('SS3: two-chunk round-trip — seal×1 + final', () => {
		const key   = hexToBytes(SS3.key);
		const nonce = hexToBytes(SS3.nonce);
		const ivs   = SS3.ivs.map(hexToBytes);
		const sealer = new SerpentStreamSealer(key, SS3.chunkSize, nonce, ivs);
		const hdr = sealer.header();
		const c0 = sealer.seal(hexToBytes(SS3.plaintexts[0]));
		const c1 = sealer.final(hexToBytes(SS3.plaintexts[1]));
		expect(bytesToHex(c0)).toBe(SS3.cipherChunks[0]);
		expect(bytesToHex(c1)).toBe(SS3.cipherChunks[1]);

		const opener = new SerpentStreamOpener(key, hdr);
		expect(bytesToHex(opener.open(c0))).toBe(SS3.plaintexts[0]);
		expect(bytesToHex(opener.open(c1))).toBe(SS3.plaintexts[1]);
	});

	it('SS2: header bytes match nonce || u32be(chunkSize)', () => {
		const hdr = hexToBytes(SS2.header);
		expect(bytesToHex(hdr.subarray(0, 16))).toBe(SS2.nonce);
		const cs = (hdr[16] << 24 | hdr[17] << 16 | hdr[18] << 8 | hdr[19]) >>> 0;
		expect(cs).toBe(SS2.chunkSize);
	});
});

// ── Security ────────────────────────────────────────────────────────────────

describe('SerpentStreamSealer — security', () => {
	it('tampered ciphertext body → opener throws', () => {
		const key   = hexToBytes(SS1.key);
		const header = hexToBytes(SS1.header);
		const chunk = hexToBytes(SS1.cipherChunks[0]);
		// Flip a byte in the CBC ciphertext region (after IV, before HMAC)
		const tampered = chunk.slice();
		tampered[20] ^= 0xff;
		const opener = new SerpentStreamOpener(key, header);
		expect(() => opener.open(tampered)).toThrow('authentication failed');
	});

	it('tampered HMAC tag → opener throws', () => {
		const key   = hexToBytes(SS1.key);
		const header = hexToBytes(SS1.header);
		const chunk = hexToBytes(SS1.cipherChunks[0]);
		const tampered = chunk.slice();
		tampered[tampered.length - 1] ^= 0x01;
		const opener = new SerpentStreamOpener(key, header);
		expect(() => opener.open(tampered)).toThrow('authentication failed');
	});

	it('truncated stream — dispose then verify dead state', () => {
		const key   = hexToBytes(SS2.key);
		const header = hexToBytes(SS2.header);
		const opener = new SerpentStreamOpener(key, header);
		opener.open(hexToBytes(SS2.cipherChunks[0]));
		opener.dispose();
		expect(() => opener.open(hexToBytes(SS2.cipherChunks[1]))).toThrow('stream is closed');
	});

	it('cross-stream splice: SS1 chunk rejected by SS3 opener', () => {
		const key3   = hexToBytes(SS3.key);
		const header3 = hexToBytes(SS3.header);
		const opener = new SerpentStreamOpener(key3, header3);
		const ss1Chunk = hexToBytes(SS1.cipherChunks[0]);
		expect(() => opener.open(ss1Chunk)).toThrow('authentication failed');
	});

	it('out-of-order: swap chunk[0] and chunk[1] from SS2 → opener throws on second', () => {
		const key   = hexToBytes(SS2.key);
		const header = hexToBytes(SS2.header);
		const opener = new SerpentStreamOpener(key, header);
		// Feed chunk[1] first (out of order) — should fail at index 0
		expect(() => opener.open(hexToBytes(SS2.cipherChunks[1]))).toThrow('authentication failed');
	});
});

// ── State machine ───────────────────────────────────────────────────────────

describe('SerpentStreamSealer — state machine', () => {
	it('header() twice → throws', () => {
		const key = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key);
		sealer.header();
		expect(() => sealer.header()).toThrow('header() already called');
		sealer.dispose();
	});

	it('seal() before header() → throws', () => {
		const key = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key);
		expect(() => sealer.seal(new Uint8Array(65536))).toThrow('call header() first');
		sealer.dispose();
	});

	it('seal() after final() → throws', () => {
		const key = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key);
		sealer.header();
		sealer.final(new Uint8Array(0));
		expect(() => sealer.seal(new Uint8Array(65536))).toThrow('stream is closed');
	});

	it('open() after stream closed (post-isLast) → throws', () => {
		const key   = hexToBytes(SS1.key);
		const header = hexToBytes(SS1.header);
		const opener = new SerpentStreamOpener(key, header);
		opener.open(hexToBytes(SS1.cipherChunks[0]));
		expect(() => opener.open(hexToBytes(SS1.cipherChunks[0]))).toThrow('stream is closed');
	});

	it('seal() with wrong size → RangeError', () => {
		const key = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key, 1024);
		sealer.header();
		expect(() => sealer.seal(new Uint8Array(512))).toThrow(RangeError);
		sealer.dispose();
	});

	it('final() with oversized plaintext → RangeError', () => {
		const key = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key, 1024);
		sealer.header();
		expect(() => sealer.final(new Uint8Array(2048))).toThrow(RangeError);
		sealer.dispose();
	});

	it('constructor with wrong key length → RangeError', () => {
		expect(() => new SerpentStreamSealer(new Uint8Array(32))).toThrow(RangeError);
	});

	it('opener constructor with wrong header length → RangeError', () => {
		expect(() => new SerpentStreamOpener(new Uint8Array(64), new Uint8Array(10))).toThrow(RangeError);
	});
});

// ── Lifecycle ───────────────────────────────────────────────────────────────

describe('SerpentStreamSealer — lifecycle', () => {
	it('dispose() on sealer mid-stream → no throw, instance dead', () => {
		const key = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key, 1024);
		sealer.header();
		sealer.dispose();
		expect(() => sealer.seal(new Uint8Array(1024))).toThrow('stream is closed');
	});

	it('dispose() on opener mid-stream → no throw, instance dead', () => {
		const key   = hexToBytes(SS2.key);
		const header = hexToBytes(SS2.header);
		const opener = new SerpentStreamOpener(key, header);
		opener.open(hexToBytes(SS2.cipherChunks[0]));
		opener.dispose();
		expect(() => opener.open(hexToBytes(SS2.cipherChunks[1]))).toThrow('stream is closed');
	});

	it('dispose() after final() → no-op, no double-wipe error', () => {
		const key = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key);
		sealer.header();
		sealer.final(new Uint8Array(0));
		expect(() => sealer.dispose()).not.toThrow();
	});
});
