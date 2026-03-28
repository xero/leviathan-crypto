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
import { SE1, SE2, SE3 } from '../../vectors/serpent_stream_encoder.js';

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
		const sealer = new SerpentStreamSealer(key, SS1.chunkSize, undefined, nonce, ivs);
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
		const sealer = new SerpentStreamSealer(key, SS2.chunkSize, undefined, nonce, ivs);
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
		const sealer = new SerpentStreamSealer(key, SS3.chunkSize, undefined, nonce, ivs);
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

	it('empty final() — round-trips to zero-length plaintext', () => {
		const key    = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key);
		const header = sealer.header();
		// seal one full chunk, then final with zero bytes
		const pt0    = new Uint8Array(65536).fill(0xab);
		const chunk0 = sealer.seal(pt0);
		const last   = sealer.final(new Uint8Array(0));

		const opener = new SerpentStreamOpener(key, header);
		const rec0   = opener.open(chunk0);
		const recLast = opener.open(last);

		expect(rec0.length).toBe(65536);
		expect(Array.from(rec0)).toEqual(Array.from(pt0));
		expect(recLast.length).toBe(0);
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

	it('SerpentStreamOpener: header with out-of-range chunkSize → RangeError', () => {
		const key = new Uint8Array(64);
		// Craft a header with chunkSize = 0xffffffff
		const hdr = new Uint8Array(20);
		hdr[16] = 0xff; hdr[17] = 0xff; hdr[18] = 0xff; hdr[19] = 0xff;
		expect(() => new SerpentStreamOpener(key, hdr, { framed: true })).toThrow(RangeError);
	});

	it('SerpentStreamOpener: header with zero chunkSize → RangeError', () => {
		const key = new Uint8Array(64);
		const hdr = new Uint8Array(20); // all zeros → chunkSize = 0
		expect(() => new SerpentStreamOpener(key, hdr, { framed: true })).toThrow(RangeError);
	});

	it('open() on framed opener → throws with feed() guidance', () => {
		const key    = hexToBytes(SE1.key);
		const header = hexToBytes(SE1.header);
		const opener = new SerpentStreamOpener(key, header, { framed: true });
		expect(() => opener.open(hexToBytes(SE1.encodedChunks[0]))).toThrow('feed()');
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

// ── Gate 12 — framed mode ────────────────────────────────────────────────────

describe('SerpentStreamSealer — Gate 12 (framed mode)', () => {
	// GATE
	it('SE1: framed sealer matches KAT header', () => {
		const enc = new SerpentStreamSealer(hexToBytes(SE1.key), SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		expect(bytesToHex(enc.header())).toBe(SE1.header);
		enc.dispose();
	});

	it('SE1: framed sealer final() matches KAT encodedChunk', () => {
		const enc   = new SerpentStreamSealer(hexToBytes(SE1.key), SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		enc.header();
		const frame = enc.final(hexToBytes(SE1.plaintexts[0]));
		expect(bytesToHex(frame)).toBe(SE1.encodedChunks[0]);
	});

	it('SE1: framed opener round-trips via feed()', () => {
		const key   = hexToBytes(SE1.key);
		const enc   = new SerpentStreamSealer(key, SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		const hdr   = enc.header();
		const frame = enc.final(hexToBytes(SE1.plaintexts[0]));
		const dec     = new SerpentStreamOpener(key, hdr, { framed: true });
		const results = dec.feed(frame);
		expect(results.length).toBe(1);
		expect(bytesToHex(results[0])).toBe(SE1.plaintexts[0]);
	});

	it('SE1: framed opener — byte-at-a-time feed', () => {
		const key = hexToBytes(SE1.key);
		const enc = new SerpentStreamSealer(key, SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		const hdr = enc.header();
		const frame = enc.final(hexToBytes(SE1.plaintexts[0]));
		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		let all: Uint8Array[] = [];
		for (let i = 0; i < frame.length; i++) all = all.concat(dec.feed(frame.subarray(i, i + 1)));
		expect(all.length).toBe(1);
		expect(bytesToHex(all[0])).toBe(SE1.plaintexts[0]);
	});

	it('feed() throws on unframed opener', () => {
		const dec = new SerpentStreamOpener(hexToBytes(SE1.key), hexToBytes(SE1.header));
		expect(() => dec.feed(new Uint8Array(4))).toThrow('feed() requires { framed: true }');
		dec.dispose();
	});

	it('SE2: three-chunk framed round-trip — seal×2 + final, feed each frame', () => {
		const key  = hexToBytes(SE2.key);
		const enc  = new SerpentStreamSealer(key, SE2.chunkSize, { framed: true }, hexToBytes(SE2.nonce), SE2.ivs.map(hexToBytes));
		const hdr  = enc.header();
		const f0   = enc.seal(hexToBytes(SE2.plaintexts[0]));
		const f1   = enc.seal(hexToBytes(SE2.plaintexts[1]));
		const f2   = enc.final(hexToBytes(SE2.plaintexts[2]));
		expect(bytesToHex(f0)).toBe(SE2.encodedChunks[0]);
		expect(bytesToHex(f1)).toBe(SE2.encodedChunks[1]);
		expect(bytesToHex(f2)).toBe(SE2.encodedChunks[2]);

		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		const r0  = dec.feed(f0);
		const r1  = dec.feed(f1);
		const r2  = dec.feed(f2);
		expect(r0.length).toBe(1); expect(bytesToHex(r0[0])).toBe(SE2.plaintexts[0]);
		expect(r1.length).toBe(1); expect(bytesToHex(r1[0])).toBe(SE2.plaintexts[1]);
		expect(r2.length).toBe(1); expect(bytesToHex(r2[0])).toBe(SE2.plaintexts[2]);
	});

	it('SE2: multi-frame feed — all three frames concatenated', () => {
		const key = hexToBytes(SE2.key);
		const enc = new SerpentStreamSealer(key, SE2.chunkSize, { framed: true }, hexToBytes(SE2.nonce), SE2.ivs.map(hexToBytes));
		const hdr = enc.header();
		const f0  = enc.seal(hexToBytes(SE2.plaintexts[0]));
		const f1  = enc.seal(hexToBytes(SE2.plaintexts[1]));
		const f2  = enc.final(hexToBytes(SE2.plaintexts[2]));

		const all = new Uint8Array(f0.length + f1.length + f2.length);
		all.set(f0, 0);
		all.set(f1, f0.length);
		all.set(f2, f0.length + f1.length);

		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		const out = dec.feed(all);
		expect(out.length).toBe(3);
		for (let i = 0; i < 3; i++) expect(bytesToHex(out[i])).toBe(SE2.plaintexts[i]);
	});

	it('feed(): oversized sealedLen prefix → throws immediately', () => {
		const key = hexToBytes(SE1.key);
		const enc = new SerpentStreamSealer(key, SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		const hdr = enc.header(); enc.dispose();
		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		const bad = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
		expect(() => dec.feed(bad)).toThrow('invalid sealed chunk length');
	});

	it('feed(): zero sealedLen prefix → throws immediately', () => {
		const key = hexToBytes(SE1.key);
		const enc = new SerpentStreamSealer(key, SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		const hdr = enc.header(); enc.dispose();
		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		const bad = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
		expect(() => dec.feed(bad)).toThrow('invalid sealed chunk length');
	});

	it('SE3: two-chunk framed round-trip', () => {
		const key  = hexToBytes(SE3.key);
		const enc  = new SerpentStreamSealer(key, SE3.chunkSize, { framed: true }, hexToBytes(SE3.nonce), SE3.ivs.map(hexToBytes));
		const hdr  = enc.header();
		const f0   = enc.seal(hexToBytes(SE3.plaintexts[0]));
		const f1   = enc.final(hexToBytes(SE3.plaintexts[1]));
		expect(bytesToHex(f0)).toBe(SE3.encodedChunks[0]);
		expect(bytesToHex(f1)).toBe(SE3.encodedChunks[1]);

		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		const r0  = dec.feed(f0);
		const r1  = dec.feed(f1);
		expect(r0.length).toBe(1); expect(bytesToHex(r0[0])).toBe(SE3.plaintexts[0]);
		expect(r1.length).toBe(1); expect(bytesToHex(r1[0])).toBe(SE3.plaintexts[1]);
	});

	it('SE1: split feed at midpoint — correct plaintext emitted on second call', () => {
		const key   = hexToBytes(SE1.key);
		const enc   = new SerpentStreamSealer(key, SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		const hdr   = enc.header();
		const frame = enc.final(hexToBytes(SE1.plaintexts[0]));
		const split = Math.floor(frame.length / 2);
		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		const r1 = dec.feed(frame.subarray(0, split));
		expect(r1.length).toBe(0);
		const r2 = dec.feed(frame.subarray(split));
		expect(r2.length).toBe(1);
		expect(bytesToHex(r2[0])).toBe(SE1.plaintexts[0]);
	});

	it('SE2: post-final leftover bytes → throws', () => {
		const key  = hexToBytes(SE2.key);
		const enc  = new SerpentStreamSealer(key, SE2.chunkSize, { framed: true }, hexToBytes(SE2.nonce), SE2.ivs.map(hexToBytes));
		const hdr  = enc.header();
		const f0   = enc.seal(hexToBytes(SE2.plaintexts[0]));
		const f1   = enc.seal(hexToBytes(SE2.plaintexts[1]));
		const f2   = enc.final(hexToBytes(SE2.plaintexts[2]));
		const withExtra = new Uint8Array(f2.length + 1);
		withExtra.set(f2); withExtra[f2.length] = 0xff;
		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		dec.feed(f0); dec.feed(f1);
		expect(() => dec.feed(withExtra)).toThrow('unexpected bytes after final chunk');
	});

	it('SE1: tampered framed chunk → throws', () => {
		const key   = hexToBytes(SE1.key);
		const enc   = new SerpentStreamSealer(key, SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		const hdr   = enc.header();
		const frame = enc.final(hexToBytes(SE1.plaintexts[0]));
		const tampered = frame.slice();
		tampered[24] ^= 0xff;
		const dec = new SerpentStreamOpener(key, hdr, { framed: true });
		expect(() => dec.feed(tampered)).toThrow('authentication failed');
	});

	it('SE1: cross-stream splice: SE1 framed chunk fed to SE3 opener → throws', () => {
		const key1 = hexToBytes(SE1.key);
		const enc1 = new SerpentStreamSealer(key1, SE1.chunkSize, { framed: true }, hexToBytes(SE1.nonce), SE1.ivs.map(hexToBytes));
		enc1.header();
		const f1 = enc1.final(hexToBytes(SE1.plaintexts[0]));

		const key3 = hexToBytes(SE3.key);
		const enc3 = new SerpentStreamSealer(key3, SE3.chunkSize, { framed: true }, hexToBytes(SE3.nonce), SE3.ivs.map(hexToBytes));
		const hdr3 = enc3.header(); enc3.dispose();

		const dec3 = new SerpentStreamOpener(key3, hdr3, { framed: true });
		expect(() => dec3.feed(f1)).toThrow('authentication failed');
	});

	it('framed — empty final() round-trips via feed()', () => {
		const key    = new Uint8Array(64);
		const sealer = new SerpentStreamSealer(key, 1024, { framed: true });
		const header = sealer.header();
		const pt0    = new Uint8Array(1024).fill(0xcd);
		const frame0 = sealer.seal(pt0);
		const last   = sealer.final(new Uint8Array(0));

		const opener = new SerpentStreamOpener(key, header, { framed: true });
		const res0   = opener.feed(frame0);
		const resLast = opener.feed(last);

		expect(res0.length).toBe(1);
		expect(Array.from(res0[0])).toEqual(Array.from(pt0));
		expect(resLast.length).toBe(1);
		expect(resLast[0].length).toBe(0);
	});
});
