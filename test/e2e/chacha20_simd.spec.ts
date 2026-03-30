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
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▄          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
//
// ChaCha20 SIMD e2e — 4-wide inter-block SIMD in browser WASM runtimes.
// Verifies chachaEncryptChunk_simd produces byte-identical output to the
// scalar chachaEncryptChunk for three representative input sizes:
//   - 114 bytes: scalar tail only (RFC 8439 §2.4.2 plaintext length)
//   - 256 bytes: exactly 1 SIMD group
//   - 320 bytes: 1 SIMD group + 1 scalar tail block
import { test, expect } from '@playwright/test';

const JS_URL = 'http://localhost:1337/build/chacha20.js';

const INIT = `
var __wasmCache = null;
async function loadWasm() {
  if (__wasmCache) return __wasmCache;
  __wasmCache = await import('${JS_URL}');
  return __wasmCache;
}
function fromHex(h) { return Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16))) }
function toHex(b)   { return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('') }

// Set up WASM for encryption: key, nonce, counter=1, loadKey, write plaintext.
async function setup(key, nonce, pt) {
  const wasm = await loadWasm();
  const mem  = new Uint8Array(wasm.memory.buffer);
  mem.set(fromHex(key),   wasm.getKeyOffset());
  mem.set(fromHex(nonce), wasm.getChachaNonceOffset());
  wasm.chachaSetCounter(1);
  wasm.chachaLoadKey();
  mem.set(pt, wasm.getChunkPtOffset());
  return wasm;
}

function readCT(wasm, len) {
  return new Uint8Array(wasm.memory.buffer).slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + len);
}
`;

// RFC 8439 §2.4.2 key and nonce
const KEY   = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const NONCE = '000000000000004a00000000';

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(INIT);
});

// 114 bytes — scalar tail only (< 256)
test('SIMD ChaCha20 — 114 bytes: SIMD === scalar', async ({ page }) => {
	const result = await page.evaluate(async ({ key, nonce }) => {
		const pt = new Uint8Array(114).fill(0x41);
		const scalar = (async () => {
			const w = await setup(key, nonce, pt);
			w.chachaEncryptChunk(114);
			return toHex(readCT(w, 114));
		});
		const simd = (async () => {
			const w = await setup(key, nonce, pt);
			w.chachaEncryptChunk_simd(114);
			return toHex(readCT(w, 114));
		});
		return { scalar: await scalar(), simd: await simd() };
	}, { key: KEY, nonce: NONCE });
	expect(result.simd).toBe(result.scalar);
});

// 256 bytes — exactly 1 SIMD group
test('SIMD ChaCha20 — 256 bytes: SIMD === scalar', async ({ page }) => {
	const result = await page.evaluate(async ({ key, nonce }) => {
		const pt = new Uint8Array(256).fill(0x5a);
		const scalar = async () => {
			const w = await setup(key, nonce, pt);
			w.chachaEncryptChunk(256);
			return toHex(readCT(w, 256));
		};
		const simd = async () => {
			const w = await setup(key, nonce, pt);
			w.chachaEncryptChunk_simd(256);
			return toHex(readCT(w, 256));
		};
		return { scalar: await scalar(), simd: await simd() };
	}, { key: KEY, nonce: NONCE });
	expect(result.simd).toBe(result.scalar);
});

// 320 bytes — 1 SIMD group + 1 scalar tail block
test('SIMD ChaCha20 — 320 bytes: SIMD === scalar', async ({ page }) => {
	const result = await page.evaluate(async ({ key, nonce }) => {
		const pt = new Uint8Array(320).fill(0x7f);
		const scalar = async () => {
			const w = await setup(key, nonce, pt);
			w.chachaEncryptChunk(320);
			return toHex(readCT(w, 320));
		};
		const simd = async () => {
			const w = await setup(key, nonce, pt);
			w.chachaEncryptChunk_simd(320);
			return toHex(readCT(w, 320));
		};
		return { scalar: await scalar(), simd: await simd() };
	}, { key: KEY, nonce: NONCE });
	expect(result.simd).toBe(result.scalar);
});
