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

test.describe('SealStreamPool — Serpent large-chunk e2e', () => {

	// 256 KB (4 full chunks at chunkSize=65536)
	test('seal → open roundtrip at chunkSize: 65536, 256 KB (4 full chunks)', async ({ page }) => {
		test.setTimeout(60_000);
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });
			const key = lib.randomBytes(32);
			const pool = await lib.SealStreamPool.create(lib.SerpentCipher, key, {
				wasm: { serpent: serpentWasm, sha2: sha2Wasm },
				workers: 2,
				chunkSize: 65536,
			});
			// counter pattern avoids crypto.getRandomValues 65536-byte limit
			const pt = new Uint8Array(4 * 65536);
			for (let i = 0; i < pt.length; i++) pt[i] = i & 0xff;
			const ct = await pool.seal(pt);
			const dec = await pool.open(ct);
			pool.destroy();
			return dec.length === pt.length
				&& (dec as Uint8Array).every((b: number, i: number) => b === pt[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	// 5 MB — compare SHA-256 hashes to avoid byte-for-byte comparison overhead
	test('seal → open roundtrip at chunkSize: 65536, 5 MB (hash comparison)', async ({ page }) => {
		test.setTimeout(120_000);
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });

			// Deterministic pseudorandom plaintext — LCG seeded at 0xdeadbeef
			const N = 80 * 65536 + 23587; // 5266467 bytes
			const pt = new Uint8Array(N);
			let s = 0xdeadbeef >>> 0;
			for (let i = 0; i < N; i++) {
				s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
				pt[i] = s & 0xff;
			}

			const key = lib.randomBytes(32);
			const pool = await lib.SealStreamPool.create(lib.SerpentCipher, key, {
				wasm: { serpent: serpentWasm, sha2: sha2Wasm },
				workers: 4,
				chunkSize: 65536,
			});
			const ct = await pool.seal(pt);
			const dec = await pool.open(ct);
			pool.destroy();

			const sha = new lib.SHA256();
			const hashPt  = lib.bytesToHex(sha.hash(pt));
			sha.dispose();
			const sha2b = new lib.SHA256();
			const hashDec = lib.bytesToHex(sha2b.hash(dec as Uint8Array));
			sha2b.dispose();
			return hashPt === hashDec;
		}, BASE);
		expect(result).toBe(true);
	});

	// Regression test for the pre-fix corruption: only the trailing partial chunk
	// was correct; all full 65536-byte chunks decrypted to zeros.
	test('all full chunks decrypt correctly, not just the trailing partial', async ({ page }) => {
		test.setTimeout(60_000);
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm });

			// 3 × 65536 = 196608 bytes — counter-byte pattern (0x00..0xFF repeating)
			const N = 3 * 65536;
			const pt = new Uint8Array(N);
			for (let i = 0; i < N; i++) pt[i] = i & 0xff;

			const key = lib.randomBytes(32);
			const pool = await lib.SealStreamPool.create(lib.SerpentCipher, key, {
				wasm: { serpent: serpentWasm, sha2: sha2Wasm },
				workers: 2,
				chunkSize: 65536,
			});
			const ct = await pool.seal(pt);
			const dec = await pool.open(ct);
			pool.destroy();

			const d = dec as Uint8Array;
			if (d.length !== N) return `length mismatch: ${d.length} !== ${N}`;

			// Check first and last 32 bytes of each 65536-byte chunk
			for (let chunk = 0; chunk < 3; chunk++) {
				const chunkBase = chunk * 65536;
				// First 32 bytes of this chunk
				for (let j = 0; j < 32; j++) {
					const expected = (chunkBase + j) & 0xff;
					if (d[chunkBase + j] !== expected)
						return `chunk ${chunk} byte ${j}: got ${d[chunkBase + j]}, want ${expected}`;
				}
				// Last 32 bytes of this chunk
				for (let j = 65536 - 32; j < 65536; j++) {
					const expected = (chunkBase + j) & 0xff;
					if (d[chunkBase + j] !== expected)
						return `chunk ${chunk} tail byte ${j}: got ${d[chunkBase + j]}, want ${expected}`;
				}
			}
			return true;
		}, BASE);
		expect(result).toBe(true);
	});

});
