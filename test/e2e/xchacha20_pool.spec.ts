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

const INIT = `
window.loadLib = async function() {
  const lib = await import('http://localhost:1337/dist/index.js');
  await lib.init(['chacha20']);
  return lib;
};
window.toHex   = function(b)   { return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('') };
window.fromHex = function(h)   { return Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16))) };
`;

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(INIT);
});

// GATE — pool.encrypt() decryptable by XChaCha20Poly1305.decrypt()
test('XChaCha20Poly1305Pool GATE — pool.encrypt() → XChaCha20Poly1305.decrypt()', async ({ page }) => {
	const match = await page.evaluate(async () => {
		const lib   = await loadLib();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const pt    = crypto.getRandomValues(new Uint8Array(64));
		const pool  = await lib.XChaCha20Poly1305Pool.create({ workers: 2 });
		const ct    = await pool.encrypt(
			Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(pt),
		);
		pool.dispose();
		const xc        = new lib.XChaCha20Poly1305();
		const recovered = xc.decrypt(key, nonce, ct);
		xc.dispose();
		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});

// XChaCha20Poly1305.encrypt() decryptable by pool.decrypt()
test('XChaCha20Poly1305.encrypt() → pool.decrypt()', async ({ page }) => {
	const match = await page.evaluate(async () => {
		const lib   = await loadLib();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const pt    = crypto.getRandomValues(new Uint8Array(64));
		const xc    = new lib.XChaCha20Poly1305();
		const ct    = xc.encrypt(key, nonce, pt);
		xc.dispose();
		const pool      = await lib.XChaCha20Poly1305Pool.create({ workers: 2 });
		const recovered = await pool.decrypt(
			Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(ct),
		);
		pool.dispose();
		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});

// pool.encrypt() → pool.decrypt() round-trip
test('pool.encrypt() → pool.decrypt() round-trip', async ({ page }) => {
	const match = await page.evaluate(async () => {
		const lib   = await loadLib();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const pt    = crypto.getRandomValues(new Uint8Array(64));
		const pool  = await lib.XChaCha20Poly1305Pool.create({ workers: 2 });
		const ct    = await pool.encrypt(
			Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(pt),
		);
		const recovered = await pool.decrypt(
			Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(ct),
		);
		pool.dispose();
		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});

// tampered ciphertext → pool.decrypt() rejects
test('tampered ciphertext byte → pool.decrypt() rejects', async ({ page }) => {
	const result = await page.evaluate(async () => {
		const lib   = await loadLib();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const pt    = crypto.getRandomValues(new Uint8Array(64));
		const pool  = await lib.XChaCha20Poly1305Pool.create({ workers: 2 });
		const ct    = await pool.encrypt(
			Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(pt),
		);
		ct[0] ^= 0xff;
		try {
			await pool.decrypt(
				Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(ct),
			);
			pool.dispose();
			return 'no error';
		} catch (e) {
			pool.dispose();
			return e.message;
		}
	});
	expect(result).toMatch(/authentication|tag/i);
});

// pool.size equals opts.workers
test('pool.size equals opts.workers', async ({ page }) => {
	const size = await page.evaluate(async () => {
		const lib  = await loadLib();
		const pool = await lib.XChaCha20Poly1305Pool.create({ workers: 3 });
		const s    = pool.size;
		pool.dispose();
		return s;
	});
	expect(size).toBe(3);
});
