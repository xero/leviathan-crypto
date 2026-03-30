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
import { poly1305Vectors } from '../vectors/chacha20';

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
`;

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(INIT);
});

// RFC 8439 §2.5.2 gate vector
test('Poly1305 RFC 8439 §2.5.2 — 34-byte message', async ({ page }) => {
	const v = poly1305Vectors[0];
	const result: string = await page.evaluate(async (vec) => {
		const wasm = await loadWasm();
		const mem  = () => new Uint8Array(wasm.memory.buffer);
		const key = fromHex(vec.key);
		const msg = new TextEncoder().encode(vec.msgText);

		mem().set(key, wasm.getPolyKeyOffset());
		wasm.polyInit();

		let offset = 0;
		const msgOff = wasm.getPolyMsgOffset();
		while (offset < msg.length) {
			const chunk = msg.slice(offset, Math.min(offset + 64, msg.length));
			mem().set(chunk, msgOff);
			wasm.polyUpdate(chunk.length);
			offset += chunk.length;
		}
		wasm.polyFinal();

		return toHex(mem().slice(wasm.getPolyTagOffset(), wasm.getPolyTagOffset() + 16));
	}, { key: v.key, msgText: v.msgText! });
	expect(result).toBe(v.tag);
});

// wipeBuffers zeroes Poly1305 key and tag
test('Poly1305 wipeBuffers zeroes key and tag', async ({ page }) => {
	const v = poly1305Vectors[0];
	const allZeroed: boolean = await page.evaluate(async (vec) => {
		const wasm = await loadWasm();
		const mem  = () => new Uint8Array(wasm.memory.buffer);
		const key = fromHex(vec.key);
		mem().set(key, wasm.getPolyKeyOffset());
		wasm.polyInit();
		wasm.wipeBuffers();

		const keySlice = mem().slice(wasm.getPolyKeyOffset(), wasm.getPolyKeyOffset() + 32);
		const tagSlice = mem().slice(wasm.getPolyTagOffset(), wasm.getPolyTagOffset() + 16);
		return keySlice.every(b => b === 0) && tagSlice.every(b => b === 0);
	}, { key: v.key });
	expect(allZeroed).toBe(true);
});
