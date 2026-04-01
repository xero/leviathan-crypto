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
// XChaCha20StreamSealer / XChaCha20StreamOpener unit tests.
//
import { describe, it, expect, beforeAll } from 'vitest';
import {
	init,
	XChaCha20StreamSealer, XChaCha20StreamOpener,
	randomBytes,
} from '../../../src/ts/index.js';

beforeAll(async () => {
	await init('chacha20');
});

// ── Gate ──────────────────────────────────────────────────────────────────────
// GATE

describe('XChaCha20StreamSealer — gate', () => {
	it('seal×1 + final round-trips via opener', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024);
		const hdr    = sealer.header();
		const pt1    = randomBytes(1024);
		const pt2    = randomBytes(512);
		const c1     = sealer.seal(pt1);
		const c2     = sealer.final(pt2);

		const opener = new XChaCha20StreamOpener(key, hdr);
		const r1 = opener.open(c1);
		const r2 = opener.open(c2);
		expect(r1).toEqual(pt1);
		expect(r2).toEqual(pt2);
	});
});

// ── Round-trip ────────────────────────────────────────────────────────────────

describe('XChaCha20StreamSealer — round-trip', () => {
	it('seal×2 + final: three chunks', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024);
		const hdr    = sealer.header();
		const pts    = [randomBytes(1024), randomBytes(1024), randomBytes(100)];
		const c0     = sealer.seal(pts[0]);
		const c1     = sealer.seal(pts[1]);
		const c2     = sealer.final(pts[2]);

		const opener = new XChaCha20StreamOpener(key, hdr);
		expect(opener.open(c0)).toEqual(pts[0]);
		expect(opener.open(c1)).toEqual(pts[1]);
		expect(opener.open(c2)).toEqual(pts[2]);
	});

	it('empty final() produces empty plaintext on open()', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024);
		const hdr    = sealer.header();
		const c0     = sealer.final(new Uint8Array(0));

		const opener = new XChaCha20StreamOpener(key, hdr);
		const pt     = opener.open(c0);
		expect(pt.length).toBe(0);
	});

	it('header bytes: stream_id(16) || u32be(chunkSize)', () => {
		const sealer = new XChaCha20StreamSealer(randomBytes(32), 2048);
		const hdr    = sealer.header();
		expect(hdr.length).toBe(20);
		const cs = (hdr[16] << 24 | hdr[17] << 16 | hdr[18] << 8 | hdr[19]) >>> 0;
		expect(cs).toBe(2048);
		sealer.dispose();
	});

	it('each chunk starts with isLast byte', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024);
		sealer.header();
		const notFinal = sealer.seal(randomBytes(1024));
		const final    = sealer.final(randomBytes(10));
		expect(notFinal[0]).toBe(0);  // not final
		expect(final[0]).toBe(1);     // final
	});
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('XChaCha20StreamSealer — authentication', () => {
	it('tampered ciphertext body throws', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024);
		const hdr    = sealer.header();
		const c0     = sealer.final(randomBytes(64));
		const bad    = c0.slice();
		bad[25] ^= 0x01; // flip byte in ciphertext (after isLast + nonce)
		const opener = new XChaCha20StreamOpener(key, hdr);
		expect(() => opener.open(bad)).toThrow();
	});

	it('tampered tag throws', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024);
		const hdr    = sealer.header();
		const c0     = sealer.final(randomBytes(64));
		const bad    = c0.slice();
		bad[bad.length - 1] ^= 0x01;
		const opener = new XChaCha20StreamOpener(key, hdr);
		expect(() => opener.open(bad)).toThrow();
	});

	it('wrong key on open throws', () => {
		const key1   = randomBytes(32);
		const key2   = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key1, 1024);
		const hdr    = sealer.header();
		const c0     = sealer.final(randomBytes(64));
		const opener = new XChaCha20StreamOpener(key2, hdr);
		expect(() => opener.open(c0)).toThrow();
	});

	it('cross-stream splice: chunk from stream A rejected by stream B opener', () => {
		const key  = randomBytes(32);
		const sA   = new XChaCha20StreamSealer(key, 1024);
		sA.header();
		const cA   = sA.final(randomBytes(64));

		const sB   = new XChaCha20StreamSealer(key, 1024);
		const hdrB = sB.header();
		sB.dispose();

		const opener = new XChaCha20StreamOpener(key, hdrB);
		expect(() => opener.open(cA)).toThrow(); // stream_id in AAD differs
	});

	it('swapped chunks cause open() to throw on second', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024);
		const hdr    = sealer.header();
		sealer.seal(randomBytes(1024));
		const c1     = sealer.final(randomBytes(64));

		const opener = new XChaCha20StreamOpener(key, hdr);
		// open c1 first (wrong index) — should throw
		expect(() => opener.open(c1)).toThrow();
	});
});

// ── AAD ───────────────────────────────────────────────────────────────────────

describe('XChaCha20StreamSealer — AAD', () => {
	it('correct AAD allows decryption', () => {
		const key  = randomBytes(32);
		const aad  = new Uint8Array([0x01, 0x02]);
		const sealer = new XChaCha20StreamSealer(key, 1024, { aad });
		const hdr  = sealer.header();
		const c0   = sealer.final(randomBytes(64));

		const opener = new XChaCha20StreamOpener(key, hdr, { aad });
		expect(() => opener.open(c0)).not.toThrow();
	});

	it('wrong AAD on opener throws', () => {
		const key  = randomBytes(32);
		const aad  = new Uint8Array([0x01, 0x02]);
		const sealer = new XChaCha20StreamSealer(key, 1024, { aad });
		const hdr  = sealer.header();
		const c0   = sealer.final(randomBytes(64));

		const opener = new XChaCha20StreamOpener(key, hdr, { aad: new Uint8Array([0xff]) });
		expect(() => opener.open(c0)).toThrow();
	});
});

// ── State machine ─────────────────────────────────────────────────────────────

describe('XChaCha20StreamSealer — state machine', () => {
	it('seal() before header() throws', () => {
		const s = new XChaCha20StreamSealer(randomBytes(32), 1024);
		expect(() => s.seal(randomBytes(1024))).toThrow();
		s.dispose();
	});

	it('header() twice throws', () => {
		const s = new XChaCha20StreamSealer(randomBytes(32), 1024);
		s.header();
		expect(() => s.header()).toThrow();
		s.dispose();
	});

	it('seal() after final() throws', () => {
		const key = randomBytes(32);
		const s   = new XChaCha20StreamSealer(key, 1024);
		s.header();
		s.final(new Uint8Array(0));
		expect(() => s.seal(randomBytes(1024))).toThrow();
	});

	it('seal() wrong size throws RangeError', () => {
		const s = new XChaCha20StreamSealer(randomBytes(32), 1024);
		s.header();
		expect(() => s.seal(randomBytes(1023))).toThrow(RangeError);
		s.dispose();
	});

	it('constructor with wrong key length throws', () => {
		expect(() => new XChaCha20StreamSealer(randomBytes(16), 1024)).toThrow(RangeError);
	});

	it('opener constructor with wrong header length throws', () => {
		expect(() => new XChaCha20StreamOpener(randomBytes(32), new Uint8Array(19))).toThrow(RangeError);
	});

	it('opener header with invalid chunkSize throws', () => {
		const hdr = new Uint8Array(20); // chunkSize = 0
		expect(() => new XChaCha20StreamOpener(randomBytes(32), hdr)).toThrow(RangeError);
	});

	it('open() on framed opener throws with feed() guidance', () => {
		const key = randomBytes(32);
		const s   = new XChaCha20StreamSealer(key, 1024);
		const hdr = s.header();
		s.dispose();
		const opener = new XChaCha20StreamOpener(key, hdr, { framed: true });
		expect(() => opener.open(new Uint8Array(100))).toThrow();
		opener.dispose();
	});
});

// ── Framed mode ───────────────────────────────────────────────────────────────

describe('XChaCha20StreamSealer — framed mode', () => {
	it('framed sealer + opener: single final() round-trip via feed()', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024, { framed: true });
		const hdr    = sealer.header();
		const pt     = randomBytes(512);
		const frame  = sealer.final(pt);

		const opener  = new XChaCha20StreamOpener(key, hdr, { framed: true });
		const results = opener.feed(frame);
		expect(results.length).toBe(1);
		expect(results[0]).toEqual(pt);
	});

	it('framed: seal×2 + final, concatenated feed', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024, { framed: true });
		const hdr    = sealer.header();
		const pts    = [randomBytes(1024), randomBytes(1024), randomBytes(300)];
		const f0     = sealer.seal(pts[0]);
		const f1     = sealer.seal(pts[1]);
		const f2     = sealer.final(pts[2]);

		const all = new Uint8Array(f0.length + f1.length + f2.length);
		all.set(f0, 0); all.set(f1, f0.length); all.set(f2, f0.length + f1.length);

		const opener  = new XChaCha20StreamOpener(key, hdr, { framed: true });
		const results = opener.feed(all);
		expect(results.length).toBe(3);
		expect(results[0]).toEqual(pts[0]);
		expect(results[1]).toEqual(pts[1]);
		expect(results[2]).toEqual(pts[2]);
	});

	it('framed: byte-at-a-time feed reconstructs correctly', () => {
		const key    = randomBytes(32);
		const sealer = new XChaCha20StreamSealer(key, 1024, { framed: true });
		const hdr    = sealer.header();
		const pt     = randomBytes(64);
		const frame  = sealer.final(pt);

		const opener  = new XChaCha20StreamOpener(key, hdr, { framed: true });
		let results: Uint8Array[] = [];
		for (let i = 0; i < frame.length; i++) {
			const r = opener.feed(frame.subarray(i, i + 1));
			results = results.concat(r);
		}
		expect(results.length).toBe(1);
		expect(results[0]).toEqual(pt);
	});
});

// ── Lifecycle ─────────────────────────────────────────────────────────────────

describe('XChaCha20StreamSealer — lifecycle', () => {
	it('dispose() on sealer mid-stream does not throw', () => {
		const s = new XChaCha20StreamSealer(randomBytes(32), 1024);
		s.header();
		expect(() => s.dispose()).not.toThrow();
	});

	it('dispose() on opener mid-stream does not throw', () => {
		const key = randomBytes(32);
		const s   = new XChaCha20StreamSealer(key, 1024);
		const hdr = s.header(); s.dispose();
		const o   = new XChaCha20StreamOpener(key, hdr);
		expect(() => o.dispose()).not.toThrow();
	});

	it('dispose() after final() is a no-op', () => {
		const s = new XChaCha20StreamSealer(randomBytes(32), 1024);
		s.header();
		s.final(new Uint8Array(0));
		expect(() => s.dispose()).not.toThrow();
	});
});
