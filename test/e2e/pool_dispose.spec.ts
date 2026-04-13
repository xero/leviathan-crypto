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

test('explicit destroy during in-flight seal settles cleanly', async ({ page }) => {
	const result = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
		const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });

		const key = lib.randomBytes(32);
		const pool = await lib.SealStreamPool.create(lib.XChaCha20Cipher, key, {
			wasm: chacha20Wasm, workers: 2, chunkSize: 1024,
		});
		const pt = lib.randomBytes(32 * 1024);

		const sealPromise = pool.seal(pt);
		pool.destroy();

		const settled = await Promise.race([
			sealPromise.then(() => 'resolved').catch((e: Error) => `rejected:${e.message}`),
			new Promise<string>(r => setTimeout(() => r('timeout'), 2000)),
		]);

		let postSealErr = '';
		try {
			await pool.seal(lib.randomBytes(16));
		} catch (e) {
			postSealErr = (e as Error).message;
		}

		let secondDestroyErr = '';
		try {
			pool.destroy();
		} catch (e) {
			secondDestroyErr = (e as Error).message;
		}

		return { settled, postSealErr, secondDestroyErr };
	}, BASE);

	expect(result.settled, 'in-flight seal must settle, not hang').not.toBe('timeout');
	expect(result.postSealErr).toMatch(/pool is dead|pool destroyed|disposed/i);
	expect(result.secondDestroyErr).toBe('');
});

test('explicit destroy during in-flight open settles cleanly', async ({ page }) => {
	const result = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
		const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });

		const key = lib.randomBytes(32);
		const poolA = await lib.SealStreamPool.create(lib.XChaCha20Cipher, key, {
			wasm: chacha20Wasm, workers: 2, chunkSize: 1024,
		});
		const pt = lib.randomBytes(32 * 1024);
		const ct = await poolA.seal(pt);
		poolA.destroy();

		const poolB = await lib.SealStreamPool.create(lib.XChaCha20Cipher, key, {
			wasm: chacha20Wasm, workers: 2, chunkSize: 1024,
		});
		const openPromise = poolB.open(ct);
		poolB.destroy();

		const settled = await Promise.race([
			openPromise.then(() => 'resolved').catch((e: Error) => `rejected:${e.message}`),
			new Promise<string>(r => setTimeout(() => r('timeout'), 2000)),
		]);
		return { settled };
	}, BASE);

	expect(result.settled, 'in-flight open must settle, not hang').not.toBe('timeout');
});
