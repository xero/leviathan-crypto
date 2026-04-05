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

test.describe('KyberSuite — e2e (MlKem768 + XChaCha20)', () => {
	test('Seal one-shot round-trip (encrypt with ek, decrypt with dk)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			const { sha3Wasm }    = await import(`${base}/dist/sha3/embedded.js`);
			const { kyberWasm }   = await import(`${base}/dist/kyber/embedded.js`);
			lib._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm, kyber: kyberWasm });
			const kem = new lib.MlKem768();
			const suite = lib.KyberSuite(kem, lib.XChaCha20Cipher);
			const { encapsulationKey, decapsulationKey } = suite.keygen();
			const pt   = lib.randomBytes(256);
			const blob = lib.Seal.encrypt(suite, encapsulationKey, pt);
			const out  = lib.Seal.decrypt(suite, decapsulationKey, blob);
			return out.length === pt.length
				&& (out as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('SealStream / OpenStream streaming round-trip (push × 2 + finalize)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			const { sha3Wasm }    = await import(`${base}/dist/sha3/embedded.js`);
			const { kyberWasm }   = await import(`${base}/dist/kyber/embedded.js`);
			lib._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm, kyber: kyberWasm });
			const kem = new lib.MlKem768();
			const suite = lib.KyberSuite(kem, lib.XChaCha20Cipher);
			const { encapsulationKey, decapsulationKey } = suite.keygen();
			const chunk0 = lib.randomBytes(256);
			const chunk1 = lib.randomBytes(256);
			const chunk2 = lib.randomBytes(256);
			const sealer = new lib.SealStream(suite, encapsulationKey);
			const preamble = sealer.preamble;
			const ct0    = sealer.push(chunk0);
			const ct1    = sealer.push(chunk1);
			const ctFinal = sealer.finalize(chunk2);
			const opener = new lib.OpenStream(suite, decapsulationKey, preamble);
			const pt0    = opener.pull(ct0);
			const pt1    = opener.pull(ct1);
			const ptFinal = opener.finalize(ctFinal);
			return (pt0 as Uint8Array).every((b: number, i: number) => b === chunk0[i])
				&& (pt1 as Uint8Array).every((b: number, i: number) => b === chunk1[i])
				&& (ptFinal as Uint8Array).every((b: number, i: number) => b === chunk2[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('preamble is HEADER_SIZE + 1088 bytes', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { chacha20Wasm } = await import(`${base}/dist/chacha20/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			const { sha3Wasm }    = await import(`${base}/dist/sha3/embedded.js`);
			const { kyberWasm }   = await import(`${base}/dist/kyber/embedded.js`);
			lib._resetForTesting();
			await lib.init({ chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm, kyber: kyberWasm });
			const kem = new lib.MlKem768();
			const suite = lib.KyberSuite(kem, lib.XChaCha20Cipher);
			const { encapsulationKey } = suite.keygen();
			const sealer = new lib.SealStream(suite, encapsulationKey);
			const len = sealer.preamble.length;
			sealer.dispose();
			return len === 20 + 1088;
		}, BASE);
		expect(result).toBe(true);
	});
});
