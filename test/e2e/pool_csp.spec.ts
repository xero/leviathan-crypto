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
import type { Page } from '@playwright/test';

const BASE = 'http://localhost:1337';

// SealStreamPool adds a second CSP axis on top of WASM compilation: it spawns
// Web Workers. The default cipher factories spawn a classic worker from a
// `blob:` URL (createPoolWorker in src/ts/<cipher>/cipher-suite.ts), so the
// page must admit blob workers. The main thread also compiles the WASM modules
// (SealStreamPool.create -> compileWasm) before posting them to the workers, so
// 'wasm-unsafe-eval' is required regardless of the worker strategy. The blob
// worker inherits the document CSP, so its in-worker WebAssembly.instantiate is
// covered by the same 'wasm-unsafe-eval' grant.
//
// worker-src governs the worker; WebKit lacks worker-src and falls back to
// child-src, which is why a production policy lists both. These tests run on
// chromium/firefox/webkit so the engine differences are exercised.
//
// Verified engine split for the default blob: factory under this policy:
//   - Chromium / Firefox: the blob worker loads and the pool round-trips.
//   - WebKit/Safari: refuses the blob: worker resource under a restrictive CSP
//     even with worker-src/child-src blob: (it works fine with no CSP), so the
//     pool cannot start. WebKit must use the same-origin worker override below.
const CSP_BLOB = 'default-src \'self\'; script-src \'self\' \'wasm-unsafe-eval\'; '
	+ 'worker-src blob:; child-src blob:; object-src \'none\'';

// Same policy with the blob worker sources removed. worker-src/child-src fall
// back to default-src 'self', so a blob: worker is refused and the pool cannot
// start.
const CSP_NO_BLOB = 'default-src \'self\'; script-src \'self\' \'wasm-unsafe-eval\'; object-src \'none\'';

// Strict policy that forbids blob: entirely but allows same-origin workers. The
// createPoolWorker override (documented in ciphersuite.md) spawns the shipped
// dist/<cipher>/pool-worker.js as a same-origin module worker instead of a blob.
const CSP_SELF_WORKER = 'default-src \'self\'; script-src \'self\' \'wasm-unsafe-eval\'; '
	+ 'worker-src \'self\'; object-src \'none\'';

async function gotoWithCsp(page: Page, csp: string) {
	await page.route(`${BASE}/`, async route => {
		const r = await route.fetch();
		const headers = { ...r.headers(), 'content-security-policy': csp };
		await route.fulfill({ response: r, headers });
	});
	await page.goto(BASE);
}

test.describe('SealStreamPool under CSP with blob: workers', () => {
	test.beforeEach(async ({ page }) => {
		await gotoWithCsp(page, CSP_BLOB);
	});

	// Returns true on a successful round-trip, or throws if the worker cannot
	// start. Assertion branches on engine: Chromium/Firefox admit the blob
	// worker; WebKit refuses it under CSP (pin the override path below).
	test('XChaCha20 pool round-trip (blob worker)', async ({ page, browserName }) => {
		const res = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			try {
				const pool = await lib.SealStreamPool.create(lib.XChaCha20Cipher, key, {
					wasm: chacha20Wasm, workers: 2, chunkSize: 1024,
				});
				const pt = lib.randomBytes(4096);
				const ct = await pool.seal(pt);
				const dec = await pool.open(ct);
				pool.destroy();
				const ok = dec.length === pt.length && (dec as Uint8Array).every((b: number, i: number) => b === pt[i]);
				return { threw: false, ok };
			} catch (e) {
				return { threw: true, ok: false, msg: (e as Error).message };
			}
		}, BASE);
		if (browserName === 'webkit') expect(res.threw).toBe(true);
		else expect(res.ok).toBe(true);
	});

	test('Serpent pool round-trip (blob worker)', async ({ page, browserName }) => {
		const res = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			try {
				const pool = await lib.SealStreamPool.create(lib.SerpentCipher, key, {
					wasm: { serpent: serpentWasm, sha2: sha2Wasm }, workers: 2, chunkSize: 1024,
				});
				const pt = lib.randomBytes(4096);
				const ct = await pool.seal(pt);
				const dec = await pool.open(ct);
				pool.destroy();
				const ok = dec.length === pt.length && (dec as Uint8Array).every((b: number, i: number) => b === pt[i]);
				return { threw: false, ok };
			} catch (e) {
				return { threw: true, ok: false, msg: (e as Error).message };
			}
		}, BASE);
		if (browserName === 'webkit') expect(res.threw).toBe(true);
		else expect(res.ok).toBe(true);
	});
});

test.describe('SealStreamPool under CSP without blob:', () => {
	test.beforeEach(async ({ page }) => {
		await gotoWithCsp(page, CSP_NO_BLOB);
	});

	// No blob: source -> worker spawn is refused. create() surfaces the failure
	// as a worker init error and rejects. Asserts the pool cannot start, which is
	// what makes worker-src/child-src blob: a hard requirement for the default
	// factory.
	test('blob worker is refused, pool cannot start', async ({ page }) => {
		const res = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			try {
				const pool = await lib.SealStreamPool.create(lib.XChaCha20Cipher, key, {
					wasm: chacha20Wasm, workers: 2, chunkSize: 1024,
				});
				await pool.seal(lib.randomBytes(64));
				pool.destroy();
				return { threw: false, msg: '' };
			} catch (e) {
				return { threw: true, msg: (e as Error).message };
			}
		}, BASE);
		expect(res.threw).toBe(true);
	});
});

test.describe('SealStreamPool under strict CSP via createPoolWorker override', () => {
	test.beforeEach(async ({ page }) => {
		await gotoWithCsp(page, CSP_SELF_WORKER);
	});

	// worker-src 'self', no blob:. Override createPoolWorker to spawn the shipped
	// pool-worker.js as a same-origin module worker. The main thread still
	// compiles the modules (needs wasm-unsafe-eval) and posts them; the worker
	// receives pre-compiled Modules and instantiates them. Proves the documented
	// escape hatch for environments that forbid blob:.
	test('same-origin module worker round-trips (XChaCha20)', async ({ page }) => {
		const ok = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const cipher = {
				...lib.XChaCha20Cipher,
				createPoolWorker: () => new Worker(
					new URL(`${base}/dist/chacha20/pool-worker.js`),
					{ type: 'module' },
				),
			};
			const key = lib.randomBytes(32);
			const pool = await lib.SealStreamPool.create(cipher, key, {
				wasm: chacha20Wasm, workers: 2, chunkSize: 1024,
			});
			const pt = lib.randomBytes(4096);
			const ct = await pool.seal(pt);
			const dec = await pool.open(ct);
			pool.destroy();
			return dec.length === pt.length && (dec as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(ok).toBe(true);
	});
});
