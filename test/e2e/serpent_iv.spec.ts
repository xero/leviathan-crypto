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
 * Serpent IV/intermediate-value Known-Answer Tests (cross-browser)
 *
 * Source: AES candidate submission, Ross Anderson / Eli Biham / Lars Knudsen
 * Files:  vectors/serpent_ecb_iv.txt
 */
import { test, expect } from '@playwright/test';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC_DIR = resolve(__dirname, '../../test/vectors');
const JS_URL = 'http://localhost:1337/build/serpent.js';

function readVec(name: string) {
	return readFileSync(resolve(VEC_DIR, name), 'utf8');
}

interface IvCase { key: string; pt: string; ct: string }

function parseIvCt(text: string): IvCase[] {
	const cases: IvCase[] = [];
	let key = '', pt = '', ct = '';
	for (const raw of text.split('\n')) {
		const t = raw.trim();
		if (t.startsWith('KEY=') && !t.startsWith('KEYSIZE=')) {
			if (key && pt && ct) cases.push({ key, pt, ct });
			key = t.slice(4).toLowerCase(); pt = ''; ct = '';
		} else if (t.startsWith('PT=') && !pt) {
			pt = t.slice(3).toLowerCase();
		} else if (t.startsWith('CT=') && !ct) {
			ct = t.slice(3).toLowerCase();
		}
	}
	if (key && pt && ct) cases.push({ key, pt, ct });
	return cases;
}

const ivCases = parseIvCt(readVec('serpent_ecb_iv.txt'));

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

test('Intermediate values — final CT for all 3 key sizes', async ({ page }) => {
	const errors: string[] = await page.evaluate(async (cases) => {
		const wasm = await loadWasm();
		const errs: string[] = [];
		for (const { key, pt, ct } of cases) {
			const k = fromHex(key);
			new Uint8Array(wasm.memory.buffer).set(k, wasm.getKeyOffset());
			if (wasm.loadKey(k.length) !== 0) {
				errs.push(`loadKey failed len=${k.length}`); continue;
			}
			new Uint8Array(wasm.memory.buffer).set(fromHex(pt), wasm.getBlockPtOffset());
			wasm.encryptBlock();
			const got = toHex(new Uint8Array(wasm.memory.buffer).slice(wasm.getBlockCtOffset(), wasm.getBlockCtOffset() + 16));
			if (got !== ct) errs.push(`key=${key.slice(0, 8)}... exp=${ct} got=${got}`);
		}
		return errs;
	}, ivCases);
	expect(errors, errors.join('\n')).toEqual([]);
});
