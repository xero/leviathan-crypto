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

// Shared envelope: workers post the result directly on success, or
// `{ __workerError: '<message>' }` on failure. The runner inspects the
// shape and rejects on errors so test assertions surface real causes.
async function runInWorker(page: import('@playwright/test').Page, workerSrc: string): Promise<unknown> {
	return page.evaluate(async (src) => {
		const blob = new Blob([src], { type: 'application/javascript' });
		const url  = URL.createObjectURL(blob);
		const w    = new Worker(url, { type: 'module' });
		try {
			return await new Promise((resolve, reject) => {
				w.onmessage = e => {
					const d = e.data as unknown;
					if (d && typeof d === 'object' && '__workerError' in d) {
						reject(new Error(String((d as { __workerError: unknown }).__workerError)));
					} else {
						resolve(d);
					}
				};
				w.onerror        = e  => reject(new Error(e.message || 'worker error event'));
				w.onmessageerror = () => reject(new Error('worker message clone failed'));
			});
		} finally {
			// Cleanup must run on both success and failure paths so a
			// rejecting test cannot leak a Worker + object URL.
			w.terminate();
			URL.revokeObjectURL(url);
		}
	}, workerSrc);
}

// Wrap a worker body with consistent error reporting. Catches sync/async
// throws and posts the error envelope; an `unhandledrejection` listener
// is a safety net for promises that escape the user code.
function workerBody(body: string): string {
	return `
		self.addEventListener('unhandledrejection', e => {
			postMessage({ __workerError: 'unhandledrejection: ' + (e.reason && e.reason.message || String(e.reason)) });
		});
		(async () => {
			try {
				${body}
			} catch (e) {
				postMessage({ __workerError: e && e.message || String(e) });
			}
		})();
	`;
}

test('SHA-256 "abc" inside a Web Worker', async ({ page }) => {
	const expected = sha256Vectors.find(v => v.inputText === 'abc')!.expected;
	const digest = await runInWorker(page, workerBody(`
		const lib = await import('${BASE}/dist/index.js');
		const { sha2Wasm } = await import('${BASE}/dist/sha2/embedded.js');
		await lib.init({ sha2: sha2Wasm });
		const h = new lib.SHA256();
		const out = h.hash(new TextEncoder().encode('abc'));
		h.dispose();
		postMessage(Array.from(out).map(b => b.toString(16).padStart(2, '0')).join(''));
	`));
	expect(digest).toBe(expected);
});

test('Seal round-trip inside a Web Worker', async ({ page }) => {
	const ok = await runInWorker(page, workerBody(`
		const lib = await import('${BASE}/dist/index.js');
		const { chacha20Wasm } = await import('${BASE}/dist/chacha20/embedded.js');
		const { sha2Wasm }    = await import('${BASE}/dist/sha2/embedded.js');
		await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
		const key = lib.randomBytes(32);
		const pt  = lib.randomBytes(256);
		const blob = lib.Seal.encrypt(lib.XChaCha20Cipher, key, pt);
		const out  = lib.Seal.decrypt(lib.XChaCha20Cipher, key, blob);
		postMessage(out.length === pt.length && out.every((b, i) => b === pt[i]));
	`));
	expect(ok).toBe(true);
});

test('Fortuna with external entropy inside a Web Worker', async ({ page }) => {
	const result = await runInWorker(page, workerBody(`
		const lib = await import('${BASE}/dist/index.js');
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
	`));
	expect(result).toEqual({ length: 32, hasNonZero: true });
});
