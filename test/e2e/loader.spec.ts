import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:1337';
const SHA3_256_ABC = '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532';

test.beforeEach(async ({ page }) => {
	await page.goto(BASE);
});

test.describe('WasmSource loader — all source types', () => {
	test('embedded string (gzip+base64)', async ({ page }) => {
		const digest = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { sha3Wasm } = await import(`${base}/dist/sha3/embedded.js`);
			lib._resetForTesting();
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
			lib._resetForTesting();
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
			lib._resetForTesting();
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
			lib._resetForTesting();
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
			lib._resetForTesting();
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
			lib._resetForTesting();
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
			lib._resetForTesting();
			await lib.init({ sha3: fetch(`${base}/dist/sha3.wasm`) });
			const h = new lib.SHA3_256();
			const out = h.hash(new TextEncoder().encode('abc'));
			h.dispose();
			return Array.from(out as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
		}, BASE);
		expect(digest).toBe(SHA3_256_ABC);
	});
});
