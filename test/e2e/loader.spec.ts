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
import { sha3_256Vectors } from '../vectors/sha3.js';

const BASE = 'http://localhost:1337';
const SHA3_256_ABC = sha3_256Vectors.find(v => v.inputText === 'abc')!.expected;

test.beforeEach(async ({ page }) => {
	await page.goto(BASE);
});

test.describe('WasmSource loader — all source types', () => {
	test('embedded string (gzip+base64)', async ({ page }) => {
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { sha3Wasm } = await import(`${base}/dist/sha3/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ sha3: sha3Wasm });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});

	test('URL', async ({ page }) => {
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ sha3: new URL(`${base}/dist/sha3.wasm`) });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});

	test('ArrayBuffer', async ({ page }) => {
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			const buf = await fetch(`${base}/dist/sha3.wasm`).then(r => r.arrayBuffer());
			await lib.init({ sha3: buf });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});

	test('Uint8Array', async ({ page }) => {
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			const buf = await fetch(`${base}/dist/sha3.wasm`).then(r => r.arrayBuffer());
			await lib.init({ sha3: new Uint8Array(buf) });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});

	test('WebAssembly.Module (pre-compiled)', async ({ page }) => {
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			const mod = await WebAssembly.compileStreaming(fetch(`${base}/dist/sha3.wasm`));
			await lib.init({ sha3: mod });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});

	test('Response', async ({ page }) => {
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			const res = await fetch(`${base}/dist/sha3.wasm`);
			await lib.init({ sha3: res });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});

	test('Promise<Response>', async ({ page }) => {
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ sha3: fetch(`${base}/dist/sha3.wasm`) });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});

	test('nested Promise.resolve(Promise.resolve(Promise.resolve(Response))) loads cleanly', async ({ page }) => {
		// Per Promises/A+ §2.3.3.3 and ECMAScript's PromiseResolveThenableJob,
		// `Promise.resolve(Promise.resolve(x))` flattens to a single
		// `Promise.resolve(x)` — each layer collapses during await. The loader
		// sees one thenable resolving to a Response, not three. This test
		// guards against a future change that would count Promise-wrapper
		// depth statically and incorrectly trip the guard.
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			const wrapped = Promise.resolve(Promise.resolve(Promise.resolve(fetch(`${base}/dist/sha3.wasm`))));
			await lib.init({ sha3: wrapped });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});
});
