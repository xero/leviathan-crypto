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
// SIMD CBC decrypt e2e — round-trip through scalar encrypt + SIMD decrypt in browser.
import { test, expect } from '@playwright/test';

const JS_URL = 'http://localhost:1337/build/serpent.js';

const INIT = `
var __wasmCache = null;
async function loadWasm() {
  if (__wasmCache) return __wasmCache;
  __wasmCache = await import('${JS_URL}');
  return __wasmCache;
}
function fromHex(h) { return Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16))) }
function toHex(b)   { return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('') }
`;

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(INIT);
});

test('SIMD CBC decrypt round-trip — 128 bytes (8 blocks)', async ({ page }) => {
	const result = await page.evaluate(async () => {
		const wasm = await loadWasm();
		const mem  = new Uint8Array(wasm.memory.buffer);
		const ptOff = wasm.getChunkPtOffset();
		const ctOff = wasm.getChunkCtOffset();
		const ivOff = wasm.getCbcIvOffset();
		const keyOff = wasm.getKeyOffset();

		// Key + IV
		const key = new Uint8Array(32);
		for (let i = 0; i < 32; i++) key[i] = i;
		const iv = new Uint8Array(16);
		for (let i = 0; i < 16; i++) iv[i] = 0xF0 + i;

		// Plaintext: 128 bytes
		const pt = new Uint8Array(128);
		for (let i = 0; i < 128; i++) pt[i] = (i * 7 + 3) & 0xFF;

		// Encrypt (scalar)
		mem.set(key, keyOff);
		wasm.loadKey(32);
		mem.set(iv, ivOff);
		mem.set(pt, ptOff);
		wasm.cbcEncryptChunk(128);
		const ct = new Uint8Array(wasm.memory.buffer).slice(ctOff, ctOff + 128);

		// Decrypt with SIMD
		mem.set(key, keyOff);
		wasm.loadKey(32);
		mem.set(iv, ivOff);
		mem.set(ct, ctOff);
		wasm.cbcDecryptChunk_simd(128);
		const recovered = new Uint8Array(wasm.memory.buffer).slice(ptOff, ptOff + 128);

		return toHex(recovered) === toHex(pt) ? 'PASS' : 'FAIL';
	});
	expect(result).toBe('PASS');
});

test('SIMD CBC decrypt round-trip — 80 bytes (5 blocks, SIMD+tail)', async ({ page }) => {
	const result = await page.evaluate(async () => {
		const wasm = await loadWasm();
		const mem  = new Uint8Array(wasm.memory.buffer);
		const ptOff = wasm.getChunkPtOffset();
		const ctOff = wasm.getChunkCtOffset();
		const ivOff = wasm.getCbcIvOffset();
		const keyOff = wasm.getKeyOffset();

		const key = new Uint8Array(16).fill(0xAA);
		const iv  = new Uint8Array(16).fill(0xBB);
		const pt  = new Uint8Array(80);
		for (let i = 0; i < 80; i++) pt[i] = (i * 11 + 5) & 0xFF;

		// Encrypt
		mem.set(key, keyOff);
		wasm.loadKey(16);
		mem.set(iv, ivOff);
		mem.set(pt, ptOff);
		wasm.cbcEncryptChunk(80);
		const ct = new Uint8Array(wasm.memory.buffer).slice(ctOff, ctOff + 80);

		// SIMD decrypt
		mem.set(key, keyOff);
		wasm.loadKey(16);
		mem.set(iv, ivOff);
		mem.set(ct, ctOff);
		wasm.cbcDecryptChunk_simd(80);
		const recovered = new Uint8Array(wasm.memory.buffer).slice(ptOff, ptOff + 80);

		return toHex(recovered) === toHex(pt) ? 'PASS' : 'FAIL';
	});
	expect(result).toBe('PASS');
});
