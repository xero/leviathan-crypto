import '@vitest/web-worker';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { init, XChaCha20Poly1305, _resetForTesting } from '../../../src/ts/index.js';
import { XChaCha20Poly1305Pool } from '../../../src/ts/chacha20/pool.js';

const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const toHex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

let pool: XChaCha20Poly1305Pool;

beforeAll(async () => {
	await init('chacha20');
	pool = await XChaCha20Poly1305Pool.create({ workers: 2 });
}, 30_000);

afterAll(() => {
	pool?.dispose();
});

// ── Gate: basic correctness ──────────────────────────────────────────────────
// GATE — pool encrypt output must be byte-identical to single-instance output

describe('XChaCha20Poly1305Pool', () => {

	it('gate — pool encrypt matches single-instance XChaCha20Poly1305', async () => {
		const key       = randomBytes(32);
		const nonce     = randomBytes(24);
		const plaintext = randomBytes(64);
		const aad       = randomBytes(12);

		const single = new XChaCha20Poly1305();
		const expected = single.encrypt(key, nonce, plaintext, aad);
		single.dispose();

		const keyCopy   = key.slice();
		const nonceCopy = nonce.slice();
		const ptCopy    = plaintext.slice();
		const aadCopy   = aad.slice();

		const poolResult = await pool.encrypt(keyCopy, nonceCopy, ptCopy, aadCopy);
		expect(toHex(poolResult)).toBe(toHex(expected));
	});

	// ── Correctness ────────────────────────────────────────────────────────────

	it('pool encrypt → pool decrypt round-trips correctly', async () => {
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const pt    = randomBytes(128);

		const ct        = await pool.encrypt(key.slice(), nonce.slice(), pt.slice());
		const recovered = await pool.decrypt(key.slice(), nonce.slice(), ct);
		expect(toHex(recovered)).toBe(toHex(pt));
	});

	it('pool decrypt matches single-instance decrypt', async () => {
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const pt    = randomBytes(48);

		const single = new XChaCha20Poly1305();
		const ct = single.encrypt(key, nonce, pt);
		single.dispose();

		const decrypted = await pool.decrypt(key.slice(), nonce.slice(), ct);
		expect(toHex(decrypted)).toBe(toHex(pt));
	});

	it('authentication failure propagates — tampered byte rejects', async () => {
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const pt    = randomBytes(32);

		const ct = await pool.encrypt(key.slice(), nonce.slice(), pt.slice());
		ct[0] ^= 0x01;
		await expect(pool.decrypt(key.slice(), nonce.slice(), ct)).rejects.toThrow('authentication failed');
	});

	it('empty AAD works', async () => {
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const pt    = randomBytes(16);

		const ct        = await pool.encrypt(key.slice(), nonce.slice(), pt.slice());
		const recovered = await pool.decrypt(key.slice(), nonce.slice(), ct);
		expect(toHex(recovered)).toBe(toHex(pt));
	});

	it('explicit AAD works', async () => {
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const pt    = randomBytes(16);
		const aad   = randomBytes(32);

		const ct        = await pool.encrypt(key.slice(), nonce.slice(), pt.slice(), aad.slice());
		const recovered = await pool.decrypt(key.slice(), nonce.slice(), ct, aad.slice());
		expect(toHex(recovered)).toBe(toHex(pt));
	});

	it('empty plaintext works (output is 16-byte tag only)', async () => {
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const pt    = new Uint8Array(0);

		const ct = await pool.encrypt(key.slice(), nonce.slice(), pt.slice());
		expect(ct.length).toBe(16);
		const recovered = await pool.decrypt(key.slice(), nonce.slice(), ct);
		expect(recovered.length).toBe(0);
	});

	// ── Concurrency ────────────────────────────────────────────────────────────

	it('dispatches n*4 jobs simultaneously — all complete correctly', async () => {
		const n = pool.size * 4;
		const jobs = Array.from({ length: n }, (_, i) => {
			const key   = randomBytes(32);
			const nonce = randomBytes(24);
			const pt    = randomBytes(32 + i);
			return { key, nonce, pt };
		});

		const results = await Promise.all(
			jobs.map(j => pool.encrypt(j.key.slice(), j.nonce.slice(), j.pt.slice())),
		);

		// Verify each result decrypts correctly
		const single = new XChaCha20Poly1305();
		for (let i = 0; i < n; i++) {
			const expected = single.encrypt(jobs[i].key, jobs[i].nonce, jobs[i].pt);
			expect(toHex(results[i])).toBe(toHex(expected));
		}
		single.dispose();
	});

	// ── Validation ─────────────────────────────────────────────────────────────

	it('create() before init throws correct message', async () => {
		const { _resetForTesting: reset } = await import('../../../src/ts/init.js');
		reset();
		await expect(XChaCha20Poly1305Pool.create()).rejects.toThrow(
			'call init([\'chacha20\']) before using XChaCha20Poly1305Pool',
		);
		await init('chacha20');
	});

	it('encrypt() with wrong key length rejects with RangeError', async () => {
		await expect(pool.encrypt(randomBytes(16), randomBytes(24), randomBytes(1))).rejects.toThrow(RangeError);
	});

	it('encrypt() with wrong nonce length rejects with RangeError', async () => {
		await expect(pool.encrypt(randomBytes(32), randomBytes(12), randomBytes(1))).rejects.toThrow(RangeError);
	});

	it('decrypt() with ciphertext shorter than 16 bytes rejects with RangeError', async () => {
		await expect(pool.decrypt(randomBytes(32), randomBytes(24), randomBytes(8))).rejects.toThrow(RangeError);
	});

	it('encrypt() after dispose() rejects with correct message', async () => {
		const p = await XChaCha20Poly1305Pool.create({ workers: 1 });
		p.dispose();
		await expect(p.encrypt(randomBytes(32), randomBytes(24), randomBytes(1))).rejects.toThrow('pool is disposed');
	});

	it('decrypt() after dispose() rejects with correct message', async () => {
		const p = await XChaCha20Poly1305Pool.create({ workers: 1 });
		p.dispose();
		await expect(p.decrypt(randomBytes(32), randomBytes(24), randomBytes(16))).rejects.toThrow('pool is disposed');
	});

	// ── Lifecycle ──────────────────────────────────────────────────────────────

	it('size returns configured worker count', async () => {
		const p = await XChaCha20Poly1305Pool.create({ workers: 3 });
		expect(p.size).toBe(3);
		p.dispose();
	});

	it('queueDepth returns 0 when pool is idle', () => {
		expect(pool.queueDepth).toBe(0);
	});

	it('dispose() is idempotent — calling twice does not throw', async () => {
		const p = await XChaCha20Poly1305Pool.create({ workers: 1 });
		p.dispose();
		expect(() => p.dispose()).not.toThrow();
	});

	it('dispose prevents new jobs after termination', async () => {
		const p = await XChaCha20Poly1305Pool.create({ workers: 1 });
		// Complete one job first to prove the pool works
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const ct = await p.encrypt(key, nonce, randomBytes(16));
		expect(ct.length).toBe(32); // 16 plaintext + 16 tag
		// Now dispose and verify no more jobs are accepted
		p.dispose();
		await expect(p.encrypt(randomBytes(32), randomBytes(24), randomBytes(1))).rejects.toThrow('pool is disposed');
	});

	// ── Worker count ───────────────────────────────────────────────────────────

	it('create({ workers: 1 }) works correctly', async () => {
		const p = await XChaCha20Poly1305Pool.create({ workers: 1 });
		expect(p.size).toBe(1);
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const pt    = randomBytes(16);

		const ct        = await p.encrypt(key.slice(), nonce.slice(), pt.slice());
		const recovered = await p.decrypt(key.slice(), nonce.slice(), ct);
		expect(toHex(recovered)).toBe(toHex(pt));
		p.dispose();
	});

	it('create({ workers: 8 }) works correctly', async () => {
		const p = await XChaCha20Poly1305Pool.create({ workers: 8 });
		expect(p.size).toBe(8);
		p.dispose();
	});

	// ── Buffer transfer ────────────────────────────────────────────────────────
	// Input buffers are transferred (neutered) after dispatch — this is intentional.

	it('input buffers are neutered after encrypt()', async () => {
		const key   = randomBytes(32);
		const nonce = randomBytes(24);
		const pt    = randomBytes(32);

		const promise = pool.encrypt(key, nonce, pt);
		await promise;
		// After transfer, the original ArrayBuffers are detached
		expect(key.byteLength).toBe(0);
		expect(nonce.byteLength).toBe(0);
		expect(pt.byteLength).toBe(0);
	});
});
