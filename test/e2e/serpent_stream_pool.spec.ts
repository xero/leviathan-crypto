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

// Import submodule paths directly — avoids dist/index.js which pulls in
// argon2id's bare npm specifier ('argon2id/lib/setup.js'), unresolvable
// in a browser context without an import map.
const INIT = `
window.loadLib = async function() {
  const serpentMod = await import('http://localhost:1337/dist/serpent/index.js');
  const sha2Mod    = await import('http://localhost:1337/dist/sha2/index.js');
  const poolMod    = await import('http://localhost:1337/dist/serpent/stream-pool.js');
  await serpentMod.init();
  await sha2Mod.init();
  return { ...serpentMod, ...poolMod };
};
window.toHex   = function(b)   { return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('') };
window.fromHex = function(h)   { return Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16))) };
`;

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(INIT);
});

// GATE — pool.seal() decryptable by SerpentStream.open()
test('SerpentStreamPool GATE — pool.seal() → SerpentStream.open()', async ({ page }) => {
	const match = await page.evaluate(async () => {
		const lib  = await loadLib();
		const key  = crypto.getRandomValues(new Uint8Array(32));
		const pt   = crypto.getRandomValues(new Uint8Array(3 * 1024));
		const pool = await lib.SerpentStreamPool.create({ workers: 2 });
		const ct   = await pool.seal(key, pt, 1024);
		pool.dispose();
		const stream    = new lib.SerpentStream();
		const recovered = stream.open(key, ct);
		stream.dispose();
		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});

// SerpentStream.seal() decryptable by pool.open()
test('SerpentStream.seal() → pool.open()', async ({ page }) => {
	const match = await page.evaluate(async () => {
		const lib    = await loadLib();
		const key    = crypto.getRandomValues(new Uint8Array(32));
		const pt     = crypto.getRandomValues(new Uint8Array(3 * 1024));
		const stream = new lib.SerpentStream();
		const ct     = stream.seal(key, pt, 1024);
		stream.dispose();
		const pool      = await lib.SerpentStreamPool.create({ workers: 2 });
		const recovered = await pool.open(key, ct);
		pool.dispose();
		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});

// pool.seal() → pool.open() round-trip
test('pool.seal() → pool.open() round-trip', async ({ page }) => {
	const match = await page.evaluate(async () => {
		const lib       = await loadLib();
		const key       = crypto.getRandomValues(new Uint8Array(32));
		const pt        = crypto.getRandomValues(new Uint8Array(3 * 1024));
		const pool      = await lib.SerpentStreamPool.create({ workers: 2 });
		const ct        = await pool.seal(key, pt, 1024);
		const recovered = await pool.open(key, ct);
		pool.dispose();
		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});

// tampered ciphertext → pool.open() rejects
test('tampered ciphertext byte → pool.open() rejects', async ({ page }) => {
	const result = await page.evaluate(async () => {
		const lib  = await loadLib();
		const key  = crypto.getRandomValues(new Uint8Array(32));
		const pt   = crypto.getRandomValues(new Uint8Array(3 * 1024));
		const pool = await lib.SerpentStreamPool.create({ workers: 2 });
		const ct   = await pool.seal(key, pt, 1024);
		ct[30] ^= 0xff;
		try {
			await pool.open(key, ct);
			pool.dispose();
			return 'no error';
		} catch (e) {
			pool.dispose();
			return e.message;
		}
	});
	expect(result).toContain('authentication failed');
});

// pool.size equals opts.workers
test('pool.size equals opts.workers', async ({ page }) => {
	const size = await page.evaluate(async () => {
		const lib  = await loadLib();
		const pool = await lib.SerpentStreamPool.create({ workers: 3 });
		const s    = pool.size;
		pool.dispose();
		return s;
	});
	expect(size).toBe(3);
});
