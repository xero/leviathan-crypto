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
import { xchacha20Poly1305Vectors } from '../vectors/chacha20';

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

// Full XChaCha20-Poly1305 encrypt in browser (pure WASM calls)
function xchachaEncrypt(wasm, key, nonce24, pt, aad) {
  const mem = () => new Uint8Array(wasm.memory.buffer);
  // HChaCha20: derive subkey from key + nonce[0..16]
  mem().set(key, wasm.getKeyOffset());
  mem().set(nonce24.subarray(0, 16), wasm.getXChaChaNonceOffset());
  wasm.hchacha20();
  const subkey = new Uint8Array(wasm.memory.buffer).slice(
    wasm.getXChaChaSubkeyOffset(), wasm.getXChaChaSubkeyOffset() + 32
  );
  // Inner nonce: 00 00 00 00 || nonce24[16..24]
  const innerNonce = new Uint8Array(12);
  innerNonce.set(nonce24.subarray(16, 24), 4);

  // AEAD encrypt with subkey + innerNonce
  mem().set(subkey, wasm.getKeyOffset());
  mem().set(innerNonce, wasm.getChachaNonceOffset());
  wasm.chachaSetCounter(1); wasm.chachaLoadKey(); wasm.chachaGenPolyKey();
  wasm.polyInit();
  polyFeed(wasm, aad);
  const aadPad = (16 - aad.length % 16) % 16;
  if (aadPad > 0) polyFeed(wasm, new Uint8Array(aadPad));
  wasm.chachaSetCounter(1); wasm.chachaLoadKey();
  mem().set(pt, wasm.getChunkPtOffset());
  wasm.chachaEncryptChunk(pt.length);
  const ct = new Uint8Array(wasm.memory.buffer).slice(
    wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + pt.length
  );
  polyFeed(wasm, ct);
  const ctPad = (16 - pt.length % 16) % 16;
  if (ctPad > 0) polyFeed(wasm, new Uint8Array(ctPad));
  polyFeed(wasm, lenBlock(aad.length, pt.length));
  wasm.polyFinal();
  const tag = new Uint8Array(wasm.memory.buffer).slice(
    wasm.getPolyTagOffset(), wasm.getPolyTagOffset() + 16
  );
  const result = new Uint8Array(ct.length + 16);
  result.set(ct);
  result.set(tag, ct.length);
  return result;
}
`;

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(INIT);
});

// IETF draft §A.3.2 — XChaCha20-Poly1305 AEAD vector
test('XChaCha20-Poly1305 draft §A.3.2 — AEAD vector', async ({ page }) => {
	const v = xchacha20Poly1305Vectors[0];
	const result = await page.evaluate(async (vec) => {
		const wasm = await loadWasm();
		const key   = fromHex(vec.key);
		const nonce = fromHex(vec.nonce);
		const aad   = fromHex(vec.aad);
		const pt    = new TextEncoder().encode(vec.ptText);

		const combined = xchachaEncrypt(wasm, key, nonce, pt, aad);
		return {
			ct: toHex(combined.slice(0, -16)),
			tag: toHex(combined.slice(-16)),
		};
	}, { key: v.key, nonce: v.nonce, aad: v.aad, ptText: v.ptText! });

	expect(result.ct).toBe(v.ct);
	expect(result.tag).toBe(v.tag);
});

// Round-trip
test('XChaCha20-Poly1305 round-trip 64B', async ({ page }) => {
	const match: boolean = await page.evaluate(async () => {
		const wasm = await loadWasm();
		const mem  = () => new Uint8Array(wasm.memory.buffer);
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const aad   = crypto.getRandomValues(new Uint8Array(8));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const combined = xchachaEncrypt(wasm, key, nonce, pt, aad);
		const ct  = combined.subarray(0, combined.length - 16);
		const tag = combined.subarray(combined.length - 16);

		// Decrypt: derive subkey again
		mem().set(key, wasm.getKeyOffset());
		mem().set(nonce.subarray(0, 16), wasm.getXChaChaNonceOffset());
		wasm.hchacha20();
		const subkey = new Uint8Array(wasm.memory.buffer).slice(
			wasm.getXChaChaSubkeyOffset(), wasm.getXChaChaSubkeyOffset() + 32
		);
		const innerNonce = new Uint8Array(12);
		innerNonce.set(nonce.subarray(16, 24), 4);

		// Verify tag
		mem().set(subkey, wasm.getKeyOffset());
		mem().set(innerNonce, wasm.getChachaNonceOffset());
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
		const expectedTag = new Uint8Array(wasm.memory.buffer).slice(
			wasm.getPolyTagOffset(), wasm.getPolyTagOffset() + 16
		);
		if (!constantTimeEqual(expectedTag, tag)) return false;

		// Decrypt
		wasm.chachaSetCounter(1); wasm.chachaLoadKey();
		mem().set(ct, wasm.getChunkPtOffset());
		wasm.chachaEncryptChunk(ct.length);
		const recovered = new Uint8Array(wasm.memory.buffer).slice(
			wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + ct.length
		);
		return toHex(recovered) === toHex(pt);
	});
	expect(match).toBe(true);
});
