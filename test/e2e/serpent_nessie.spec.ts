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

const JS_URL = 'http://localhost:1337/build/serpent.js';
const SERVER_BASE = 'http://localhost:1337';

const INIT = `
var __wasmCache = null;
async function loadWasm() {
  if (__wasmCache) return __wasmCache;
  __wasmCache = await import('${JS_URL}');
  return __wasmCache;
}
function fromHex(h) { return Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16))) }
function toHex(b)   { return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('') }
function nessieBytes(hex) { return hex.match(/.{2}/g).reverse().join('').toLowerCase() }
function parseNessie(text) {
  var vecs = [], key = '', keyPart1 = '', awaitKey2 = false
  var pt = '', ct = '', hasPt = false, hasCt = false
  var lines = text.split('\\n')
  for (var i = 0; i < lines.length; i++) {
    var t = lines[i].trim()
    if (t.startsWith('key=')) {
      keyPart1 = t.slice(4).replace(/\\s/g,'').toUpperCase()
      awaitKey2 = true; pt = ''; ct = ''; hasPt = false; hasCt = false; continue
    }
    if (awaitKey2) {
      var stripped = t.replace(/\\s/g,'')
      key = /^[0-9A-Fa-f]+$/.test(stripped) && stripped.length > 0
        ? keyPart1 + stripped.toUpperCase() : keyPart1
      awaitKey2 = false
      if (!t.startsWith('plain=') && !t.startsWith('cipher=')) continue
    }
    if (t.startsWith('plain='))  { pt = t.slice(6).trim(); hasPt = true }
    if (t.startsWith('cipher=')) { ct = t.slice(7).trim(); hasCt = true }
    if (hasPt && hasCt) { vecs.push({ key: key, pt: pt, ct: ct }); hasPt = false; hasCt = false }
  }
  return vecs
}
`;

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(INIT);
});

test('NESSIE 256-bit — all 1284 vectors', async ({ page }) => {
	const url = `${SERVER_BASE}/test/vectors/serpent_nessie-256.txt`;
	const errors: string[] = await page.evaluate(async (vecUrl) => {
		const text = await fetch(vecUrl).then(r => r.text());
		const raw  = parseNessie(text);
		const wasm = await loadWasm();
		const errs: string[] = [];
		for (const v of raw) {
			const k  = fromHex(nessieBytes(v.key));
			const ct = nessieBytes(v.ct);
			new Uint8Array(wasm.memory.buffer).set(k, wasm.getKeyOffset());
			if (wasm.loadKey(k.length) !== 0) {
				errs.push('loadKey failed'); continue;
			}
			new Uint8Array(wasm.memory.buffer).set(fromHex(nessieBytes(v.pt)), wasm.getBlockPtOffset());
			wasm.encryptBlock();
			const got = toHex(new Uint8Array(wasm.memory.buffer).slice(wasm.getBlockCtOffset(), wasm.getBlockCtOffset() + 16));
			if (got !== ct) errs.push(`exp=${ct} got=${got}`);
		}
		return errs;
	}, url);
	expect(errors, errors.join('\n')).toEqual([]);
});

test('NESSIE 128-bit — all 1028 vectors', async ({ page }) => {
	const url = `${SERVER_BASE}/test/vectors/serpent_nessie-128.txt`;
	const errors: string[] = await page.evaluate(async (vecUrl) => {
		const text = await fetch(vecUrl).then(r => r.text());
		const raw  = parseNessie(text);
		const wasm = await loadWasm();
		const errs: string[] = [];
		for (const v of raw) {
			const k  = fromHex(nessieBytes(v.key));
			const ct = nessieBytes(v.ct);
			new Uint8Array(wasm.memory.buffer).set(k, wasm.getKeyOffset());
			if (wasm.loadKey(k.length) !== 0) {
				errs.push('loadKey failed'); continue;
			}
			new Uint8Array(wasm.memory.buffer).set(fromHex(nessieBytes(v.pt)), wasm.getBlockPtOffset());
			wasm.encryptBlock();
			const got = toHex(new Uint8Array(wasm.memory.buffer).slice(wasm.getBlockCtOffset(), wasm.getBlockCtOffset() + 16));
			if (got !== ct) errs.push(`exp=${ct} got=${got}`);
		}
		return errs;
	}, url);
	expect(errors, errors.join('\n')).toEqual([]);
});
