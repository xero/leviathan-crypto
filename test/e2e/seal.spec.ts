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

test.describe('Seal — e2e', () => {
	test('XChaCha20 Seal round-trip', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			lib._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			const pt  = lib.randomBytes(256);
			const blob = lib.Seal.encrypt(lib.XChaCha20Cipher, key, pt);
			const out  = lib.Seal.decrypt(lib.XChaCha20Cipher, key, blob);
			return out.length === pt.length
				&& (out as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('Serpent Seal round-trip', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			lib._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			const pt  = lib.randomBytes(256);
			const blob = lib.Seal.encrypt(lib.SerpentCipher, key, pt);
			const out  = lib.Seal.decrypt(lib.SerpentCipher, key, blob);
			return out.length === pt.length
				&& (out as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('Seal.encrypt → OpenStream.finalize (unified wire format, XChaCha20)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			lib._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
			const key  = lib.randomBytes(32);
			const pt   = lib.randomBytes(256);
			const blob = lib.Seal.encrypt(lib.XChaCha20Cipher, key, pt);
			const opener = new lib.OpenStream(lib.XChaCha20Cipher, key, blob.subarray(0, 20));
			const out  = opener.finalize(blob.subarray(20));
			return out.length === pt.length
				&& (out as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('Seal.encrypt → OpenStream.finalize (unified wire format, Serpent)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			lib._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const key  = lib.randomBytes(32);
			const pt   = lib.randomBytes(256);
			const blob = lib.Seal.encrypt(lib.SerpentCipher, key, pt);
			const opener = new lib.OpenStream(lib.SerpentCipher, key, blob.subarray(0, 20));
			const out  = opener.finalize(blob.subarray(20));
			return out.length === pt.length
				&& (out as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});
});
