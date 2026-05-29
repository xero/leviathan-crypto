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

// Companion to loader_csp.spec.ts. That file proves every WasmSource works
// UNDER a CSP that grants 'wasm-unsafe-eval'. This file proves that grant is
// REQUIRED: with the directive absent (script-src falls back to default-src
// 'self', no eval-family token), the library cannot initialize on any engine.
// Together they pin 'wasm-unsafe-eval' as a hard requirement, not a copied-in
// habit.
//
// Engines trip the gate at different steps (verified across the three projects):
//   - Chromium / Firefox gate compilation: WebAssembly.compile,
//     compileStreaming, and instantiate(bytes) all reject.
//   - WebKit does NOT gate compile/compileStreaming, but DOES gate
//     instantiation ("Refused to create a WebAssembly object"); loadWasm()
//     calls WebAssembly.instantiate(mod) (loader.ts), so it trips there.
// Either way init() fails, so each case below asserts end-to-end failure rather
// than a specific step, keeping the assertion engine-robust.
const CSP_NO_WASM = 'default-src \'self\'; object-src \'none\'';

test.beforeEach(async ({ page }) => {
	await page.route(`${BASE}/`, async route => {
		const r = await route.fetch();
		const headers = { ...r.headers(), 'content-security-policy': CSP_NO_WASM };
		await route.fulfill({ response: r, headers });
	});
	await page.goto(BASE);
});

// Each case loads the lib, resets init state, and attempts the compile path for
// one WasmSource type. Returns whether it threw plus the message, so a run also
// records the per-engine rejection text (CompileError vs CSP violation wording).
test('no wasm-unsafe-eval: embedded string (gzip+base64) is blocked', async ({ page }) => {
	const res = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		const { sha3Wasm } = await import(`${base}/dist/sha3/embedded.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		try {
			await lib.init({ sha3: sha3Wasm }); return { threw: false, msg: '' };
		} catch (e) {
			return { threw: true, msg: (e as Error).message };
		}
	}, BASE);
	expect(res.threw).toBe(true);
});

test('no wasm-unsafe-eval: URL is blocked', async ({ page }) => {
	const res = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		try {
			await lib.init({ sha3: new URL(`${base}/dist/sha3.wasm`) }); return { threw: false, msg: '' };
		} catch (e) {
			return { threw: true, msg: (e as Error).message };
		}
	}, BASE);
	expect(res.threw).toBe(true);
});

test('no wasm-unsafe-eval: ArrayBuffer is blocked', async ({ page }) => {
	const res = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		const buf = await fetch(`${base}/dist/sha3.wasm`).then(r => r.arrayBuffer());
		try {
			await lib.init({ sha3: buf }); return { threw: false, msg: '' };
		} catch (e) {
			return { threw: true, msg: (e as Error).message };
		}
	}, BASE);
	expect(res.threw).toBe(true);
});

test('no wasm-unsafe-eval: Uint8Array is blocked', async ({ page }) => {
	const res = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		const buf = await fetch(`${base}/dist/sha3.wasm`).then(r => r.arrayBuffer());
		try {
			await lib.init({ sha3: new Uint8Array(buf) }); return { threw: false, msg: '' };
		} catch (e) {
			return { threw: true, msg: (e as Error).message };
		}
	}, BASE);
	expect(res.threw).toBe(true);
});

// The pre-compiled WebAssembly.Module source is the one place engines diverge:
// Chromium/Firefox reject the in-page compileStreaming step, while WebKit lets
// it compile but rejects the subsequent instantiate inside init(). Asserting the
// whole compile+init chain throws captures both without branching on engine.
test('no wasm-unsafe-eval: WebAssembly.Module source cannot initialize the library', async ({ page }) => {
	const res = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		try {
			const mod = await WebAssembly.compileStreaming(fetch(`${base}/dist/sha3.wasm`));
			await lib.init({ sha3: mod });
			return { threw: false, msg: '' };
		} catch (e) {
			return { threw: true, msg: (e as Error).message };
		}
	}, BASE);
	expect(res.threw).toBe(true);
});

test('no wasm-unsafe-eval: Response is blocked', async ({ page }) => {
	const res = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		const r = await fetch(`${base}/dist/sha3.wasm`);
		try {
			await lib.init({ sha3: r }); return { threw: false, msg: '' };
		} catch (e) {
			return { threw: true, msg: (e as Error).message };
		}
	}, BASE);
	expect(res.threw).toBe(true);
});

test('no wasm-unsafe-eval: Promise<Response> is blocked', async ({ page }) => {
	const res = await page.evaluate(async (base) => {
		const lib = await import(`${base}/dist/index.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		try {
			await lib.init({ sha3: fetch(`${base}/dist/sha3.wasm`) }); return { threw: false, msg: '' };
		} catch (e) {
			return { threw: true, msg: (e as Error).message };
		}
	}, BASE);
	expect(res.threw).toBe(true);
});
