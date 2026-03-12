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
 * SerpentStreamPool unit tests — parallel chunked authenticated encryption
 */
import '@vitest/web-worker';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init, SerpentStream, bytesToHex } from '../../../src/ts/index.js';
import { SerpentStreamPool } from '../../../src/ts/serpent/stream-pool.js';

const randomBytes = (n: number) => {
	const buf = new Uint8Array(n);
	for (let off = 0; off < n; off += 65536)
		crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, n)));
	return buf;
};

let pool: SerpentStreamPool;
let stream: SerpentStream;

beforeAll(async () => {
	await init(['serpent', 'sha2']);
	pool = await SerpentStreamPool.create({ workers: 2 });
	stream = new SerpentStream();
}, 30_000);

afterAll(() => {
	pool?.dispose();
	stream?.dispose();
});

describe('SerpentStreamPool', () => {
	// ── Correctness ────────────────────────────────────────────────────────────

	// GATE
	it('gate — pool.seal() output decryptable by SerpentStream.open()', async () => {
		const key = randomBytes(32);
		const pt = randomBytes(3 * 1024);
		const ct = await pool.seal(key, pt, 1024);
		const recovered = stream.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});

	it('SerpentStream.seal() output decryptable by pool.open()', async () => {
		const key = randomBytes(32);
		const pt = randomBytes(3 * 1024);
		const ct = stream.seal(key, pt, 1024);
		const recovered = await pool.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});

	it('pool.seal() → pool.open() round-trip', async () => {
		const key = randomBytes(32);
		const pt = randomBytes(4 * 1024);
		const ct = await pool.seal(key, pt, 1024);
		const recovered = await pool.open(key, ct);
		expect(bytesToHex(recovered)).toBe(bytesToHex(pt));
	});

	it('plaintext identity after round-trip', async () => {
		const key = randomBytes(32);
		const pt = new Uint8Array(256);
		for (let i = 0; i < 256; i++) pt[i] = i & 0xff;
		const ct = await pool.seal(key, pt, 1024);
		const recovered = await pool.open(key, ct);
		expect(Array.from(recovered)).toEqual(Array.from(pt));
	});

	it('empty plaintext round-trips', async () => {
		const key = randomBytes(32);
		const pt = new Uint8Array(0);
		const ct = await pool.seal(key, pt);
		const recovered = await pool.open(key, ct);
		expect(recovered.length).toBe(0);
	});

	// ── Parallel correctness ──────────────────────────────────────────────────

	it('8 concurrent seal() calls all succeed and produce decryptable output', async () => {
		const jobs = Array.from({ length: 8 }, () => ({
			key: randomBytes(32),
			pt: randomBytes(2 * 1024),
		}));

		const cts = await Promise.all(
			jobs.map(j => pool.seal(j.key, j.pt, 1024)),
		);

		for (let i = 0; i < 8; i++) {
			const recovered = stream.open(jobs[i].key, cts[i]);
			expect(bytesToHex(recovered)).toBe(bytesToHex(jobs[i].pt));
		}
	});

	it('8 concurrent open() calls on independently sealed inputs all succeed', async () => {
		const jobs = Array.from({ length: 8 }, () => {
			const key = randomBytes(32);
			const pt = randomBytes(2 * 1024);
			const ct = stream.seal(key, pt, 1024);
			return { key, pt, ct };
		});

		const results = await Promise.all(
			jobs.map(j => pool.open(j.key, j.ct)),
		);

		for (let i = 0; i < 8; i++) {
			expect(bytesToHex(results[i])).toBe(bytesToHex(jobs[i].pt));
		}
	});

	// ── Authentication ────────────────────────────────────────────────────────

	it('tampered chunk body — pool.open() rejects', async () => {
		const key = randomBytes(32);
		const pt = randomBytes(2 * 1024);
		const ct = stream.seal(key, pt, 1024).slice();
		ct[30] ^= 0x01;
		await expect(pool.open(key, ct)).rejects.toThrow('SerpentStream: authentication failed');
	});

	it('tampered tag — pool.open() rejects', async () => {
		const key = randomBytes(32);
		const pt = randomBytes(2 * 1024);
		const ct = stream.seal(key, pt, 1024).slice();
		ct[ct.length - 1] ^= 0x01;
		await expect(pool.open(key, ct)).rejects.toThrow('SerpentStream: authentication failed');
	});

	it('wrong key — pool.open() rejects', async () => {
		const key1 = randomBytes(32);
		const key2 = randomBytes(32);
		const pt = randomBytes(2 * 1024);
		const ct = stream.seal(key1, pt, 1024);
		await expect(pool.open(key2, ct)).rejects.toThrow('SerpentStream: authentication failed');
	});

	it('MAC failure does not leak partial plaintext', async () => {
		const key = randomBytes(32);
		const pt = randomBytes(3 * 1024);
		const ct = stream.seal(key, pt, 1024).slice();
		// Tamper with second chunk (after header + first chunk wire)
		const secondChunkStart = 28 + 1024 + 32;
		ct[secondChunkStart + 10] ^= 0x01;
		try {
			await pool.open(key, ct);
			expect.unreachable('should have thrown');
		} catch (err) {
			expect((err as Error).message).toContain('authentication failed');
		}
	});

	// ── Pool lifecycle ────────────────────────────────────────────────────────

	it('pool.size equals worker count passed to create()', () => {
		expect(pool.size).toBe(2);
	});

	it('pool.queueDepth is 0 when idle', () => {
		expect(pool.queueDepth).toBe(0);
	});

	it('dispose() causes subsequent seal() to reject', async () => {
		const p = await SerpentStreamPool.create({ workers: 1 });
		p.dispose();
		await expect(p.seal(randomBytes(32), randomBytes(64))).rejects.toThrow('pool is disposed');
	});

	it('dispose() does not throw if called twice', async () => {
		const p = await SerpentStreamPool.create({ workers: 1 });
		p.dispose();
		expect(() => p.dispose()).not.toThrow();
	});
});
