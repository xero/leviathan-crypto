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
import { sha256Vectors } from '../vectors/sha2.js';

const BASE = 'http://localhost:1337';

test.beforeEach(async ({ page }) => {
	await page.goto(BASE);
});

async function runInWorker(page: import('@playwright/test').Page, workerSrc: string): Promise<unknown> {
	return page.evaluate(async (src) => {
		const blob = new Blob([src], { type: 'application/javascript' });
		const url = URL.createObjectURL(blob);
		const w = new Worker(url, { type: 'module' });
		const result = await new Promise((resolve, reject) => {
			w.onmessage = e => resolve(e.data);
			w.onerror = e => reject(new Error(e.message));
		});
		w.terminate();
		URL.revokeObjectURL(url);
		return result;
	}, workerSrc);
}

test('SHA-256 "abc" inside a Web Worker', async ({ page }) => {
	const expected = sha256Vectors.find(v => v.inputText === 'abc')!.expected;
	const digest = await runInWorker(page, `
		import('${BASE}/dist/index.js').then(async lib => {
			const { sha2Wasm } = await import('${BASE}/dist/sha2/embedded.js');
			await lib.init({ sha2: sha2Wasm });
			const h = new lib.SHA256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			postMessage(Array.from(out).map(b => b.toString(16).padStart(2, '0')).join(''));
		}).catch(e => { throw e; });
	`);
	expect(digest).toBe(expected);
});

test('Seal round-trip inside a Web Worker', async ({ page }) => {
	const ok = await runInWorker(page, `
		import('${BASE}/dist/index.js').then(async lib => {
			const { chacha20Wasm } = await import('${BASE}/dist/chacha20/embedded.js');
			const { sha2Wasm }    = await import('${BASE}/dist/sha2/embedded.js');
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			const pt  = lib.randomBytes(256);
			const blob = lib.Seal.encrypt(lib.XChaCha20Cipher, key, pt);
			const out  = lib.Seal.decrypt(lib.XChaCha20Cipher, key, blob);
			postMessage(out.length === pt.length && out.every((b, i) => b === pt[i]));
		}).catch(e => { throw e; });
	`);
	expect(ok).toBe(true);
});

test('Fortuna with external entropy inside a Web Worker', async ({ page }) => {
	const result = await runInWorker(page, `
		import('${BASE}/dist/index.js').then(async lib => {
			const { serpentWasm } = await import('${BASE}/dist/serpent/embedded.js');
			const { sha2Wasm }    = await import('${BASE}/dist/sha2/embedded.js');
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const fortuna = await lib.Fortuna.create({
				generator: lib.SerpentGenerator,
				hash: lib.SHA256Hash,
				entropy: new Uint8Array(64).fill(0x42),
			});
			const out = fortuna.get(32);
			fortuna.stop();
			postMessage({ length: out.length, hasNonZero: out.some(b => b !== 0) });
		}).catch(e => { postMessage({ error: e.message }); });
	`);
	expect(result).toEqual({ length: 32, hasNonZero: true });
});
