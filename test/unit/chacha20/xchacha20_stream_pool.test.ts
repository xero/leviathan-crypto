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
// XChaCha20StreamPool unit tests.
//
import '@vitest/web-worker';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init, XChaCha20StreamPool, randomBytes } from '../../../src/ts/index.js';

let pool: XChaCha20StreamPool;

beforeAll(async () => {
	await init('chacha20');
	pool = await XChaCha20StreamPool.create({ workers: 2 });
});

afterAll(() => {
	pool?.dispose();
});

// ── Gate ──────────────────────────────────────────────────────────────────────
// GATE

describe('XChaCha20StreamPool — gate', () => {
	it('seal() → open() round-trip returns original plaintext', async () => {
		const key = randomBytes(32);
		const pt  = randomBytes(2048);
		const ct  = await pool.seal(key, pt, 1024);
		const rt  = await pool.open(key, ct);
		expect(rt).toEqual(pt);
	});
});

// ── Round-trip ────────────────────────────────────────────────────────────────

describe('XChaCha20StreamPool — round-trip', () => {
	it('large payload: multiple chunks (200KB, 64KB chunks)', async () => {
		const key = randomBytes(32);
		const pt  = new Uint8Array(200 * 1024);
		for (let i = 0; i < pt.length; i++) pt[i] = i & 0xff;
		const ct  = await pool.seal(key, pt, 65536);
		const rt  = await pool.open(key, ct);
		expect(rt).toEqual(pt);
	});

	it('empty payload round-trips', async () => {
		const key = randomBytes(32);
		const ct  = await pool.seal(key, new Uint8Array(0), 1024);
		const rt  = await pool.open(key, ct);
		expect(rt.length).toBe(0);
	});

	it('small payload: single chunk smaller than chunkSize', async () => {
		const key = randomBytes(32);
		const pt  = randomBytes(100);
		const ct  = await pool.seal(key, pt, 1024);
		const rt  = await pool.open(key, ct);
		expect(rt).toEqual(pt);
	});

	it('custom chunkSize=4096 round-trip', async () => {
		const key = randomBytes(32);
		const pt  = randomBytes(10000);
		const ct  = await pool.seal(key, pt, 4096);
		const rt  = await pool.open(key, ct);
		expect(rt).toEqual(pt);
	});
});

// ── AAD ───────────────────────────────────────────────────────────────────────

describe('XChaCha20StreamPool — AAD', () => {
	it('round-trip with AAD', async () => {
		const key = randomBytes(32);
		const aad = new Uint8Array([0x01, 0x02, 0x03]);
		const pt  = randomBytes(2048);
		const ct  = await pool.seal(key, pt, 1024, { aad });
		const rt  = await pool.open(key, ct, { aad });
		expect(rt).toEqual(pt);
	});

	it('AAD mismatch causes auth failure', async () => {
		const key = randomBytes(32);
		const pt  = randomBytes(2048);
		const ct  = await pool.seal(key, pt, 1024, { aad: new Uint8Array([0x01]) });
		await expect(pool.open(key, ct, { aad: new Uint8Array([0xff]) })).rejects.toThrow();
	});
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('XChaCha20StreamPool — authentication', () => {
	it('tampered ciphertext byte → open rejects', async () => {
		const key = randomBytes(32);
		const pt  = randomBytes(2048);
		const ct  = await pool.seal(key, pt, 1024);
		const bad = ct.slice();
		bad[28 + 25] ^= 0x01; // flip byte in first chunk's ciphertext
		await expect(pool.open(key, bad)).rejects.toThrow();
	});

	it('wrong key → open rejects', async () => {
		const key1 = randomBytes(32);
		const key2 = randomBytes(32);
		const ct   = await pool.seal(key1, randomBytes(1024), 1024);
		await expect(pool.open(key2, ct)).rejects.toThrow();
	});

	it('trailing bytes after final chunk → open rejects', async () => {
		const key = randomBytes(32);
		const ct  = await pool.seal(key, randomBytes(2048), 1024);
		const bad = new Uint8Array(ct.length + 1);
		bad.set(ct);
		bad[ct.length] = 0x00;
		await expect(pool.open(key, bad)).rejects.toThrow();
	});

	it('tampered isLast byte → open rejects', async () => {
		const key = randomBytes(32);
		const ct  = await pool.seal(key, randomBytes(2048), 1024);
		const bad = ct.slice();
		bad[28] ^= 0x01; // flip isLast byte of first chunk
		await expect(pool.open(key, bad)).rejects.toThrow();
	});

	it('truncated ciphertext → open rejects', async () => {
		const key = randomBytes(32);
		const ct  = await pool.seal(key, randomBytes(2048), 1024);
		const truncated = ct.slice(0, ct.length - 20);
		await expect(pool.open(key, truncated)).rejects.toThrow();
	});
});

// ── Input validation ──────────────────────────────────────────────────────────

describe('XChaCha20StreamPool — validation', () => {
	it('wrong key length throws RangeError', async () => {
		await expect(pool.seal(randomBytes(16), randomBytes(100))).rejects.toThrow(RangeError);
	});

	it('ciphertext too short throws RangeError', async () => {
		await expect(pool.open(randomBytes(32), new Uint8Array(40))).rejects.toThrow(RangeError);
	});
});

// ── Lifecycle ─────────────────────────────────────────────────────────────────

describe('XChaCha20StreamPool — lifecycle', () => {
	it('dispose then seal rejects', async () => {
		const p = await XChaCha20StreamPool.create({ workers: 1 });
		p.dispose();
		await expect(p.seal(randomBytes(32), randomBytes(100))).rejects.toThrow('disposed');
	});

	it('pool.size equals opts.workers', async () => {
		const p = await XChaCha20StreamPool.create({ workers: 2 });
		expect(p.size).toBe(2);
		p.dispose();
	});
});

// ── Parallel correctness ──────────────────────────────────────────────────────

describe('XChaCha20StreamPool — parallel', () => {
	it('seal 5 different messages concurrently, open all, verify each matches', async () => {
		const key = randomBytes(32);
		const messages = Array.from({ length: 5 }, () => randomBytes(3000));
		const sealed = await Promise.all(messages.map(m => pool.seal(key, m, 1024)));
		const opened = await Promise.all(sealed.map(ct => pool.open(key, ct)));
		for (let i = 0; i < messages.length; i++) {
			expect(opened[i]).toEqual(messages[i]);
		}
	});
});
