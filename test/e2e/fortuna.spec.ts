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

test.describe('Fortuna — e2e', () => {
	// T1 — All four (generator, hash) pair combinations smoke-test on real
	// browser SIMD. Each pair requires only its own WASM modules:
	//   SerpentGenerator + SHA256Hash   → serpent + sha2
	//   SerpentGenerator + SHA3_256Hash → serpent + sha3
	//   ChaCha20Generator + SHA256Hash  → chacha20 + sha2
	//   ChaCha20Generator + SHA3_256Hash → chacha20 + sha3
	test('four (generator, hash) pair smoke', async ({ page }) => {
		const results = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm }  = await import(`${base}/dist/serpent/embedded.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm }     = await import(`${base}/dist/sha2/embedded.js`);
			const { sha3Wasm }     = await import(`${base}/dist/sha3/embedded.js`);
			const initApi          = await import(`${base}/dist/init.js`);

			const pairs: { name: string; gen: unknown; hash: unknown; modules: Record<string, unknown> }[] = [
				{ name: 'Serpent+SHA256',  gen: lib.SerpentGenerator,  hash: lib.SHA256Hash,   modules: { serpent: serpentWasm,  sha2: sha2Wasm } },
				{ name: 'Serpent+SHA3',    gen: lib.SerpentGenerator,  hash: lib.SHA3_256Hash, modules: { serpent: serpentWasm,  sha3: sha3Wasm } },
				{ name: 'ChaCha20+SHA256', gen: lib.ChaCha20Generator, hash: lib.SHA256Hash,   modules: { chacha20: chacha20Wasm, sha2: sha2Wasm } },
				{ name: 'ChaCha20+SHA3',   gen: lib.ChaCha20Generator, hash: lib.SHA3_256Hash, modules: { chacha20: chacha20Wasm, sha3: sha3Wasm } },
			];

			const out: { name: string; length: number; hasNonZero: boolean }[] = [];
			for (const { name, gen, hash, modules } of pairs) {
				initApi._resetForTesting();
				await lib.init(modules);
				const fortuna = await lib.Fortuna.create({ generator: gen, hash });
				const bytes   = fortuna.get(32) as Uint8Array;
				out.push({ name, length: bytes.length, hasNonZero: bytes.some((b: number) => b !== 0) });
				fortuna.stop();
			}
			return out;
		}, BASE);

		expect(results).toHaveLength(4);
		for (const r of results) {
			expect(r.length, `${r.name} length`).toBe(32);
			expect(r.hasNonZero, `${r.name} hasNonZero`).toBe(true);
		}
	});

	// T2 — DOM entropy collectors actually fire on real browser events.
	// Stash the Fortuna instance on window so synthetic events between
	// page.evaluate calls feed the same instance.
	test('DOM entropy collectors increase getEntropy()', async ({ page }) => {
		const baseline = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const fortuna = await lib.Fortuna.create({
				generator: lib.SerpentGenerator,
				hash: lib.SHA256Hash,
				msPerReseed: 0,
			});
			(window as unknown as { __fortuna: { getEntropy(): number; stop(): void } }).__fortuna = fortuna;
			return fortuna.getEntropy();
		}, BASE);

		// Synthesize DOM events via Playwright. Mouse moves go through the
		// page's mousemove listener; keypresses go through keydown.
		for (let i = 0; i < 50; i++) {
			await page.mouse.move(100 + i * 7, 100 + i * 11);
		}
		for (const k of 'abcdefghijklmnopqrstuvwxyz') {
			await page.keyboard.press(k);
		}

		const after = await page.evaluate(() => {
			const f = (window as unknown as { __fortuna: { getEntropy(): number; stop(): void } }).__fortuna;
			const e = f.getEntropy();
			f.stop();
			delete (window as unknown as Record<string, unknown>).__fortuna;
			return e;
		});

		expect(after).toBeGreaterThan(baseline);
	});

	// T3 — stop() actually detaches listeners. We can't directly count
	// listeners from page.evaluate, so we verify via the disposed-error
	// contract: any post-stop method call throws.
	test('stop() removes listeners (post-stop methods throw disposed error)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const fortuna = await lib.Fortuna.create({
				generator: lib.SerpentGenerator,
				hash: lib.SHA256Hash,
				msPerReseed: 0,
			});
			fortuna.stop();
			const errs: string[] = [];
			try {
				fortuna.get(1);
			} catch (e) {
				errs.push((e as Error).message);
			}
			try {
				fortuna.addEntropy(new Uint8Array(8));
			} catch (e) {
				errs.push((e as Error).message);
			}
			try {
				fortuna.getEntropy();
			} catch (e) {
				errs.push((e as Error).message);
			}
			try {
				fortuna.stop();
			} catch (e) {
				errs.push((e as Error).message);
			}
			return errs;
		}, BASE);

		expect(result).toHaveLength(4);
		for (const msg of result) expect(msg).toMatch(/Fortuna instance has been disposed/);
	});

	// T4 — Coexistence with SerpentCtr. Browser replay of the unit-test
	// scenario: a live SerpentCtr blocks Fortuna.get() via the exclusivity
	// guard; disposing the ctr restores normal operation. Validates the
	// guard works under real-browser SIMD.
	test('Fortuna.get() throws cleanly when SerpentCtr holds the serpent module', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const fortuna = await lib.Fortuna.create({
				generator: lib.SerpentGenerator,
				hash: lib.SHA256Hash,
				entropy: new Uint8Array(32).fill(0x42),
			});
			const ctr = new lib.SerpentCtr({ dangerUnauthenticated: true });
			let didThrow = false, msg = '';
			try {
				fortuna.get(32);
			} catch (e) {
				didThrow = true; msg = (e as Error).message;
			}
			ctr.dispose();
			const after = fortuna.get(32) as Uint8Array;
			fortuna.stop();
			return { didThrow, msgMatches: /stateful instance is using/.test(msg), afterLen: after.length };
		}, BASE);

		expect(result.didThrow).toBe(true);
		expect(result.msgMatches).toBe(true);
		expect(result.afterLen).toBe(32);
	});

	// T5 — Optional `entropy` argument is plumbed through the dist build.
	test('external entropy seed argument', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const fortuna = await lib.Fortuna.create({
				generator: lib.SerpentGenerator,
				hash: lib.SHA256Hash,
				entropy: new Uint8Array(64).fill(0xab),
			});
			const out1 = fortuna.get(32) as Uint8Array;
			const out2 = fortuna.get(32) as Uint8Array;
			fortuna.stop();
			let differs = false;
			for (let i = 0; i < 32; i++) if (out1[i] !== out2[i]) {
				differs = true; break;
			}
			return { len1: out1.length, len2: out2.length, differs };
		}, BASE);

		expect(result.len1).toBe(32);
		expect(result.len2).toBe(32);
		expect(result.differs).toBe(true);
	});
});
