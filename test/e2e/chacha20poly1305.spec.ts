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
 * ChaCha20-Poly1305 AEAD Known-Answer Tests (cross-browser) — RFC 8439
 *
 * Source: RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols, §2.8.2
 * Files:  vectors/chacha20.ts (chacha20Poly1305Vectors)
 */
import { test, expect } from '@playwright/test';
import { chacha20Poly1305Vectors } from '../vectors/chacha20';

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

function polyFeed(wasm, data) {
  const mem    = () => new Uint8Array(wasm.memory.buffer);
  const msgOff = wasm.getPolyMsgOffset();
  let pos = 0;
  while (pos < data.length) {
    const chunk = Math.min(64, data.length - pos);
    mem().set(data.subarray(pos, pos + chunk), msgOff);
    wasm.polyUpdate(chunk);
    pos += chunk;
  }
}

function lenBlock(aadLen, ctLen) {
  const b = new Uint8Array(16);
  let n = aadLen;
  for (let i = 0; i < 4; i++) { b[i] = n & 0xff; n >>>= 8; }
  n = ctLen;
  for (let i = 0; i < 4; i++) { b[8 + i] = n & 0xff; n >>>= 8; }
  return b;
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
`;

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(INIT);
});

// RFC 8439 §2.8.2 sunscreen vector
test('ChaCha20-Poly1305 RFC 8439 §2.8.2 — sunscreen AEAD', async ({ page }) => {
	const v = chacha20Poly1305Vectors[0];
	const result = await page.evaluate(async (vec) => {
		const wasm = await loadWasm();
		const mem  = () => new Uint8Array(wasm.memory.buffer);
		const key   = fromHex(vec.key);
		const nonce = fromHex(vec.nonce);
		const aad   = fromHex(vec.aad);
		const pt    = new TextEncoder().encode(vec.ptText);

		// Gen poly key
		mem().set(key, wasm.getKeyOffset());
		mem().set(nonce, wasm.getChachaNonceOffset());
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		wasm.chachaGenPolyKey();

		wasm.polyInit();

		// MAC AAD + pad
		polyFeed(wasm, aad);
		const aadPad = (16 - aad.length % 16) % 16;
		if (aadPad > 0) polyFeed(wasm, new Uint8Array(aadPad));

		// Encrypt
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		mem().set(pt, wasm.getChunkPtOffset());
		wasm.chachaEncryptChunk(pt.length);
		const ctOff = wasm.getChunkCtOffset();
		const ct = new Uint8Array(wasm.memory.buffer).slice(ctOff, ctOff + pt.length);

		// MAC CT + pad
		polyFeed(wasm, ct);
		const ctPad = (16 - pt.length % 16) % 16;
		if (ctPad > 0) polyFeed(wasm, new Uint8Array(ctPad));

		// MAC lengths
		polyFeed(wasm, lenBlock(aad.length, pt.length));

		wasm.polyFinal();
		const tagOff = wasm.getPolyTagOffset();
		const tag = new Uint8Array(wasm.memory.buffer).slice(tagOff, tagOff + 16);

		return { ct: toHex(ct), tag: toHex(tag) };
	}, { key: v.key, nonce: v.nonce, aad: v.aad, ptText: v.ptText! });

	expect(result.ct).toBe(v.ct);
	expect(result.tag).toBe(v.tag);
});

// Round-trip with AAD
test('ChaCha20-Poly1305 round-trip 64B with AAD', async ({ page }) => {
	const match: boolean = await page.evaluate(async () => {
		const wasm = await loadWasm();
		const mem  = () => new Uint8Array(wasm.memory.buffer);
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const aad   = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		function aeadEncrypt(k: Uint8Array, n: Uint8Array, plaintext: Uint8Array, aad: Uint8Array) {
			mem().set(k, wasm.getKeyOffset());
			mem().set(n, wasm.getChachaNonceOffset());
			wasm.chachaSetCounter(1); wasm.chachaLoadKey(); wasm.chachaGenPolyKey();
			wasm.polyInit();
			polyFeed(wasm, aad);
			const aadPad = (16 - aad.length % 16) % 16;
			if (aadPad > 0) polyFeed(wasm, new Uint8Array(aadPad));
			wasm.chachaSetCounter(1); wasm.chachaLoadKey();
			mem().set(plaintext, wasm.getChunkPtOffset());
			wasm.chachaEncryptChunk(plaintext.length);
			const ct = new Uint8Array(wasm.memory.buffer).slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + plaintext.length);
			polyFeed(wasm, ct);
			const ctPad = (16 - plaintext.length % 16) % 16;
			if (ctPad > 0) polyFeed(wasm, new Uint8Array(ctPad));
			polyFeed(wasm, lenBlock(aad.length, plaintext.length));
			wasm.polyFinal();
			const tag = new Uint8Array(wasm.memory.buffer).slice(wasm.getPolyTagOffset(), wasm.getPolyTagOffset() + 16);
			return { ct, tag };
		}

		const { ct, tag } = aeadEncrypt(key, nonce, pt, aad);

		// Verify tag then decrypt
		mem().set(key, wasm.getKeyOffset());
		mem().set(nonce, wasm.getChachaNonceOffset());
		wasm.chachaSetCounter(1); wasm.chachaLoadKey(); wasm.chachaGenPolyKey();
		wasm.polyInit();
		polyFeed(wasm, aad);
		const aadPad = (16 - aad.length % 16) % 16;
		if (aadPad > 0) polyFeed(wasm, new Uint8Array(aadPad));
		polyFeed(wasm, ct);
		const ctPad = (16 - ct.length % 16) % 16;
		if (ctPad > 0) polyFeed(wasm, new Uint8Array(ctPad));
		polyFeed(wasm, lenBlock(aad.length, ct.length));
		wasm.polyFinal();
		const expectedTag = new Uint8Array(wasm.memory.buffer).slice(wasm.getPolyTagOffset(), wasm.getPolyTagOffset() + 16);

		if (!constantTimeEqual(expectedTag, tag)) return false;

		wasm.chachaSetCounter(1); wasm.chachaLoadKey();
		mem().set(ct, wasm.getChunkPtOffset());
		wasm.chachaEncryptChunk(ct.length);
		const recovered = new Uint8Array(wasm.memory.buffer).slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + ct.length);

		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});
