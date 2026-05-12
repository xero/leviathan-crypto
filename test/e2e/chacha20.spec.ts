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
/**
 * ChaCha20 Known-Answer Tests (cross-browser), RFC 8439
 *
 * Source: RFC 8439, ChaCha20 and Poly1305 for IETF Protocols, §2.4.2
 * Files:  vectors/chacha20.ts (chacha20EncryptionVectors)
 */
import { test, expect } from '@playwright/test';
import { chacha20EncryptionVectors } from '../vectors/chacha20';

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

// RFC 8439 §2.4.2, encryption vector (114 bytes)
test('ChaCha20 RFC 8439 §2.4.2, 114-byte encryption', async ({ page }) => {
	const v = chacha20EncryptionVectors[0];
	const result: string = await page.evaluate(async (vec) => {
		const wasm = await loadWasm();
		const mem  = new Uint8Array(wasm.memory.buffer);
		const key   = fromHex(vec.key);
		const nonce = fromHex(vec.nonce);
		const pt    = new TextEncoder().encode(vec.ptText);
		mem.set(key, wasm.getKeyOffset());
		mem.set(nonce, wasm.getChachaNonceOffset());
		mem.set(pt, wasm.getChunkPtOffset());
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		wasm.chachaEncryptChunk(pt.length);
		return toHex(new Uint8Array(wasm.memory.buffer).slice(
			wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + pt.length
		));
	}, { key: v.key, nonce: v.nonce, ptText: v.ptText! });
	expect(result).toBe(v.ct);
});

// Round-trip: encrypt then decrypt
test('ChaCha20 128-byte round-trip', async ({ page }) => {
	const match: boolean = await page.evaluate(async () => {
		const wasm = await loadWasm();
		const mem  = () => new Uint8Array(wasm.memory.buffer);
		const key   = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
		const nonce = fromHex('000000090000004a00000000');
		const pt    = crypto.getRandomValues(new Uint8Array(128));

		mem().set(key, wasm.getKeyOffset());
		mem().set(nonce, wasm.getChachaNonceOffset());
		mem().set(pt, wasm.getChunkPtOffset());
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		wasm.chachaEncryptChunk(128);
		const ct = mem().slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + 128).slice();

		mem().set(key, wasm.getKeyOffset());
		mem().set(nonce, wasm.getChachaNonceOffset());
		mem().set(ct, wasm.getChunkPtOffset());
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		wasm.chachaEncryptChunk(128);
		const recovered = mem().slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + 128);

		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});
