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
 * SealStreamPool tests — parallel batch encryption/decryption.
 */
import '@vitest/web-worker';
import { describe, it, expect, beforeAll } from 'vitest';
import { init, _resetForTesting, randomBytes } from '../../../src/ts/index.js';
import { SealStreamPool, OpenStream, SealStream } from '../../../src/ts/stream/index.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { SerpentCipher } from '../../../src/ts/serpent/cipher-suite.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import type { CipherSuite } from '../../../src/ts/stream/types.js';
import type { WasmSource } from '../../../src/ts/wasm-source.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, serpent: serpentWasm, sha2: sha2Wasm });
});

// ── Per-cipher test suites ──────────────────────────────────────────────────

interface CipherTestConfig {
	name: string;
	cipher: CipherSuite;
	wasm: WasmSource | Record<string, WasmSource>;
	keyLen: number;
}

const configs: CipherTestConfig[] = [
	{
		name: 'XChaCha20',
		cipher: XChaCha20Cipher,
		wasm: chacha20Wasm,
		keyLen: 32,
	},
	{
		name: 'Serpent',
		cipher: SerpentCipher,
		wasm: { serpent: serpentWasm, sha2: sha2Wasm },
		keyLen: 32,
	},
];

for (const cfg of configs) {
	describe(`SealStreamPool — ${cfg.name}`, () => {
		const key = randomBytes(cfg.keyLen);

		// ── Round-trip ──────────────────────────────────────────────────

		describe('round-trip', () => {
			it('seal via pool, open via pool', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const pt = randomBytes(2048);
				const ct = await pool.seal(pt);
				const dec = await pool.open(ct);
				expect(dec).toEqual(pt);
				pool.destroy();
			});

			it('cross-instance: seal pool A, open pool B (same key)', async () => {
				// Proves pool.open() re-derives keys from the ciphertext header nonce
				// rather than using the pool's own construction-time keys.
				const poolA = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const pt = randomBytes(2048);
				const ct = await poolA.seal(pt);
				poolA.destroy();

				const poolB = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const dec = await poolB.open(ct);
				expect(dec).toEqual(pt);
				poolB.destroy();
			});

			it('SealStream seal → pool open', async () => {
				// Proves pool.open() correctly handles externally-produced ciphertext.
				const sealer = new SealStream(cfg.cipher, key, { chunkSize: 1024 });
				const pt = randomBytes(512);
				const body = sealer.finalize(pt);
				const ct = new Uint8Array(sealer.preamble.length + body.length);
				ct.set(sealer.preamble);
				ct.set(body, sealer.preamble.length);

				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const dec = await pool.open(ct);
				expect(dec).toEqual(pt);
				pool.destroy();
			});

			it('seal via pool, open via OpenStream', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const pt = randomBytes(500);
				const ct = await pool.seal(pt);
				const opener = new OpenStream(cfg.cipher, key, pool.header);
				const dec = opener.finalize(ct.subarray(20));
				expect(dec).toEqual(pt);
				pool.destroy();
			});

			it('empty plaintext', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const ct = await pool.seal(new Uint8Array(0));
				const dec = await pool.open(ct);
				expect(dec).toEqual(new Uint8Array(0));
				pool.destroy();
			});

			it('single chunk (plaintext < chunkSize)', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 2, chunkSize: 4096,
				});
				const pt = randomBytes(100);
				const ct = await pool.seal(pt);
				const dec = await pool.open(ct);
				expect(dec).toEqual(pt);
				pool.destroy();
			});

			it('exact multiple of chunkSize', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const pt = randomBytes(3072); // exactly 3 chunks
				const ct = await pool.seal(pt);
				const dec = await pool.open(ct);
				expect(dec).toEqual(pt);
				pool.destroy();
			});

			it('non-multiple of chunkSize (partial final chunk)', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const pt = randomBytes(2500);
				const ct = await pool.seal(pt);
				const dec = await pool.open(ct);
				expect(dec).toEqual(pt);
				pool.destroy();
			});
		});

		// ── Auth failure ────────────────────────────────────────────────

		describe('auth failure', () => {
			it('tampered ciphertext → AuthenticationError, pool dead', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const ct = await pool.seal(randomBytes(500));
				// Tamper a byte in the body (past the 20-byte header)
				ct[20] ^= 0xff;
				await expect(pool.open(ct)).rejects.toThrow();
				expect(pool.dead).toBe(true);
			});
		});

		// ── Worker lifecycle ────────────────────────────────────────────

		describe('lifecycle', () => {
			it('double destroy — no throw', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				pool.destroy();
				pool.destroy(); // no-op
				expect(pool.dead).toBe(true);
			});

			it('seal after destroy → throws', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				pool.destroy();
				await expect(pool.seal(randomBytes(100))).rejects.toThrow(/dead/);
			});

			it('open after destroy → throws', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				const ct = await pool.seal(randomBytes(100));
				pool.destroy();
				await expect(pool.open(ct)).rejects.toThrow(/dead/);
			});

			it('seal() twice → throws (nonce reuse prevention)', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				await pool.seal(randomBytes(100));
				await expect(pool.seal(randomBytes(100)))
					.rejects.toThrow(/seal\(\) already called/);
				pool.destroy();
			});
		});

		// ── Key material ────────────────────────────────────────────────

		describe('key material', () => {
			it('derived key bytes zeroed after destroy', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const keys = (pool as any)._keys;
				expect(keys).not.toBeNull();
				// Prove buffer has real key material before destroy
				expect(keys.bytes.some((b: number) => b !== 0)).toBe(true);
				// Keep reference to the underlying buffer
				const bytesRef = keys.bytes;
				pool.destroy();
				// Reference is nulled
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				expect((pool as any)._keys).toBeNull();
				// Actual buffer bytes are zeroed (wipe was called in-place)
				expect(bytesRef.every((b: number) => b === 0)).toBe(true);
			});

			it('master key bytes zeroed after destroy', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: 1024,
				});
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const masterRef = (pool as any)._masterKey;
				expect(masterRef).not.toBeNull();
				expect(masterRef.some((b: number) => b !== 0)).toBe(true);
				pool.destroy();
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				expect((pool as any)._masterKey).toBeNull();
				expect(masterRef.every((b: number) => b === 0)).toBe(true);
			});
		});

		// ── WASM wipe on destroy ────────────────────────────────────────

		it('destroy sends wipe message (WASM buffers cleared)', async () => {
			const pool = await SealStreamPool.create(cfg.cipher, key, {
				wasm: cfg.wasm, workers: 1, chunkSize: 1024,
			});
			// Prove pool works before destroy
			const pt = randomBytes(100);
			const ct = await pool.seal(pt);
			const dec = await pool.open(ct);
			expect(dec).toEqual(pt);
			// Destroy should send wipe to worker — no throw
			pool.destroy();
			expect(pool.dead).toBe(true);
		});

		// ── Multi-worker parallel ────────────────────────────────────

		describe('multi-worker parallel', () => {
			it('round-trip with 4 workers and many chunks', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 4, chunkSize: 1024,
				});
				const pt = randomBytes(8192); // 8 chunks across 4 workers
				const ct = await pool.seal(pt);
				const dec = await pool.open(ct);
				expect(dec).toEqual(pt);
				pool.destroy();
			});

			it('large chunks with multiple workers (transfer path)', async () => {
				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 2, chunkSize: 16384,
				});
				const pt = randomBytes(49152); // 3 × 16KB chunks
				const ct = await pool.seal(pt);
				const dec = await pool.open(ct);
				expect(dec).toEqual(pt);
				pool.destroy();
			});
		});

		// ── Pool size ───────────────────────────────────────────────────

		it('pool.size equals opts.workers', async () => {
			const pool = await SealStreamPool.create(cfg.cipher, key, {
				wasm: cfg.wasm, workers: 2, chunkSize: 1024,
			});
			expect(pool.size).toBe(2);
			pool.destroy();
		});
	});
}

// ── WASM loading variants ───────────────────────────────────────────────────

describe('WASM loading', () => {
	const key = randomBytes(32);

	it('XChaCha20 pool with single WasmSource (not a Record)', async () => {
		const pool = await SealStreamPool.create(XChaCha20Cipher, key, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		});
		const ct = await pool.seal(randomBytes(100));
		const dec = await pool.open(ct);
		expect(dec.length).toBe(100);
		pool.destroy();
	});

	it('Serpent pool with Record wasm', async () => {
		const pool = await SealStreamPool.create(SerpentCipher, key, {
			wasm: { serpent: serpentWasm, sha2: sha2Wasm }, workers: 1, chunkSize: 1024,
		});
		const ct = await pool.seal(randomBytes(100));
		const dec = await pool.open(ct);
		expect(dec.length).toBe(100);
		pool.destroy();
	});

	it('SealStreamPool without sha2 → clear error', async () => {
		_resetForTesting();
		await init({ chacha20: chacha20Wasm });
		await expect(SealStreamPool.create(XChaCha20Cipher, randomBytes(32), {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		})).rejects.toThrow(/sha2/);
		// Restore
		await init({ chacha20: chacha20Wasm, serpent: serpentWasm, sha2: sha2Wasm });
	});

	it('Serpent pool with missing sha2 key → clear error', async () => {
		await expect(SealStreamPool.create(SerpentCipher, key, {
			wasm: { serpent: serpentWasm } as Record<string, WasmSource>,
			workers: 1, chunkSize: 1024,
		})).rejects.toThrow(/sha2/);
	});
});

// ── Header validation (C-1) ──────────────────────────────────────────────────

describe('SealStreamPool.open() — header validation', () => {
	const xcKey = randomBytes(32);
	const serpKey = randomBytes(32);

	it('rejects XChaCha20 ciphertext in a Serpent pool', async () => {
		const xcPool = await SealStreamPool.create(XChaCha20Cipher, xcKey, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		});
		const pt = randomBytes(512);
		const ct = await xcPool.seal(pt);
		xcPool.destroy();

		const serpPool = await SealStreamPool.create(SerpentCipher, serpKey, {
			wasm: { serpent: serpentWasm, sha2: sha2Wasm }, workers: 1, chunkSize: 1024,
		});
		await expect(serpPool.open(ct)).rejects.toThrow(/format/);
		serpPool.destroy();
	});

	it('rejects ciphertext with mismatched chunkSize', async () => {
		const pool1 = await SealStreamPool.create(XChaCha20Cipher, xcKey, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		});
		const pt = randomBytes(2048);
		const ct = await pool1.seal(pt);
		pool1.destroy();

		const pool2 = await SealStreamPool.create(XChaCha20Cipher, xcKey, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 2048,
		});
		await expect(pool2.open(ct)).rejects.toThrow(/chunkSize/);
		pool2.destroy();
	});

	it('rejects ciphertext shorter than HEADER_SIZE', async () => {
		const pool = await SealStreamPool.create(XChaCha20Cipher, xcKey, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		});
		const tiny = new Uint8Array(10);
		await expect(pool.open(tiny)).rejects.toThrow(RangeError);
		pool.destroy();
	});

	it('rejects ciphertext with mismatched framing', async () => {
		// Seal with framed=false (default), open with framed=true pool
		const sealPool = await SealStreamPool.create(XChaCha20Cipher, xcKey, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024, framed: false,
		});
		const ct = await sealPool.seal(randomBytes(512));
		sealPool.destroy();

		const openPool = await SealStreamPool.create(XChaCha20Cipher, xcKey, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024, framed: true,
		});
		await expect(openPool.open(ct)).rejects.toThrow(/framing/);
		openPool.destroy();
	});
});

// ── KEM rejection ────────────────────────────────────────────────────────────

describe('SealStreamPool.create() — KEM rejection', () => {
	it('rejects KEM-enabled cipher suite with clear error', async () => {
		// A minimal CipherSuite stub with kemCtSize > 0 is sufficient to
		// trigger the guard — no real KEM WASM needed.
		const kemStub = { ...XChaCha20Cipher, kemCtSize: 1088 };
		await expect(SealStreamPool.create(kemStub as CipherSuite, randomBytes(32), {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		})).rejects.toThrow(/KEM/);
	});
});
