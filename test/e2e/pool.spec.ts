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
import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:1337';

test.beforeEach(async ({ page }) => {
	await page.goto(BASE);
});

test.describe('SealStreamPool — e2e', () => {
	test('XChaCha20 pool round-trip (2 workers)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			lib._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			const pool = await lib.SealStreamPool.create(lib.XChaCha20Cipher, key, {
				wasm: chacha20Wasm, workers: 2, chunkSize: 1024,
			});
			const pt = lib.randomBytes(4096);
			const ct = await pool.seal(pt);
			const dec = await pool.open(ct);
			pool.destroy();
			return dec.length === pt.length
				&& (dec as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('Serpent pool round-trip (2 workers)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			lib._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			const pool = await lib.SealStreamPool.create(lib.SerpentCipher, key, {
				wasm: { serpent: serpentWasm, sha2: sha2Wasm }, workers: 2, chunkSize: 1024,
			});
			const pt = lib.randomBytes(4096);
			const ct = await pool.seal(pt);
			const dec = await pool.open(ct);
			pool.destroy();
			return dec.length === pt.length
				&& (dec as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	// pool.header is read before destroy(); chunkSize=2048 with 2048-byte payload
	// produces one chunk, so opener.finalize(ct) handles the full ciphertext.
	test('pool seal → OpenStream open (XChaCha20)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			lib._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			const pool = await lib.SealStreamPool.create(lib.XChaCha20Cipher, key, {
				wasm: chacha20Wasm, workers: 2, chunkSize: 2048,
			});
			const pt = lib.randomBytes(2048);
			const ct = await pool.seal(pt);
			const header = pool.header;
			pool.destroy();
			const opener = new lib.OpenStream(lib.XChaCha20Cipher, key, header);
			const dec = opener.finalize(ct);
			return dec.length === pt.length
				&& (dec as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('large payload multi-worker (XChaCha20)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			lib._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			const pool = await lib.SealStreamPool.create(lib.XChaCha20Cipher, key, {
				wasm: chacha20Wasm, workers: 4, chunkSize: 4096,
			});
			const pt = lib.randomBytes(32768);
			const ct = await pool.seal(pt);
			const dec = await pool.open(ct);
			pool.destroy();
			return dec.length === pt.length
				&& (dec as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});
});
