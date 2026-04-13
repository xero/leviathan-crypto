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
 * Known-Answer Tests (KAT) — Serpent AES submission (cross-browser)
 *
 * Source: AES candidate submission, Ross Anderson / Eli Biham / Lars Knudsen
 * Files:  vectors/serpent_ecb_vt.txt (variable-text), vectors/serpent_ecb_vk.txt (variable-key)
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

interface KatVec { key: string; pt: string; ct: string }

function parseKat(text: string): KatVec[] {
	const vecs: KatVec[] = [];
	let key = '', pt = '';
	for (const raw of text.split('\n')) {
		const t = raw.trim();
		if (t.startsWith('KEY='))    key = t.slice(4).toLowerCase();
		else if (t.startsWith('PT=')) pt  = t.slice(3).toLowerCase();
		else if (t.startsWith('CT=')) vecs.push({ key, pt, ct: t.slice(3).toLowerCase() });
	}
	return vecs;
}

const vtVecs  = parseKat(readVec('serpent_ecb_vt.txt'));
const vkVecs  = parseKat(readVec('serpent_ecb_vk.txt'));
const tblVecs = parseKat(readVec('serpent_ecb_tbl.txt'));

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

test('KAT variable-text — all 384 vectors', async ({ page }) => {
	const errors: string[] = await page.evaluate(async (vecs) => {
		const wasm = await loadWasm();
		const errs: string[] = [];
		for (const { key, pt, ct } of vecs) {
			const k = fromHex(key);
			new Uint8Array(wasm.memory.buffer).set(k, wasm.getKeyOffset());
			if (wasm.loadKey(k.length) !== 0) {
				errs.push('loadKey failed'); continue;
			}
			new Uint8Array(wasm.memory.buffer).set(fromHex(pt), wasm.getBlockPtOffset());
			wasm.encryptBlock();
			const got = toHex(new Uint8Array(wasm.memory.buffer).slice(wasm.getBlockCtOffset(), wasm.getBlockCtOffset() + 16));
			if (got !== ct) errs.push(`pt=${pt} exp=${ct} got=${got}`);
		}
		return errs;
	}, vtVecs);
	expect(errors, errors.join('\n')).toEqual([]);
});

test('KAT variable-key — all 576 vectors', async ({ page }) => {
	const errors: string[] = await page.evaluate(async (vecs) => {
		const wasm = await loadWasm();
		const errs: string[] = [];
		for (const { key, pt, ct } of vecs) {
			const k = fromHex(key);
			new Uint8Array(wasm.memory.buffer).set(k, wasm.getKeyOffset());
			if (wasm.loadKey(k.length) !== 0) {
				errs.push('loadKey failed'); continue;
			}
			new Uint8Array(wasm.memory.buffer).set(fromHex(pt), wasm.getBlockPtOffset());
			wasm.encryptBlock();
			const got = toHex(new Uint8Array(wasm.memory.buffer).slice(wasm.getBlockCtOffset(), wasm.getBlockCtOffset() + 16));
			if (got !== ct) errs.push(`key=${key.slice(0, 8)}... exp=${ct} got=${got}`);
		}
		return errs;
	}, vkVecs);
	expect(errors, errors.join('\n')).toEqual([]);
});

test('KAT decrypt — all 384 vt vectors', async ({ page }) => {
	const errors: string[] = await page.evaluate(async (vecs) => {
		const wasm = await loadWasm();
		const errs: string[] = [];
		for (const { key, pt, ct } of vecs) {
			const k = fromHex(key);
			new Uint8Array(wasm.memory.buffer).set(k, wasm.getKeyOffset());
			if (wasm.loadKey(k.length) !== 0) {
				errs.push('loadKey failed'); continue;
			}
			new Uint8Array(wasm.memory.buffer).set(fromHex(ct), wasm.getBlockCtOffset());
			wasm.decryptBlock();
			const got = toHex(new Uint8Array(wasm.memory.buffer).slice(wasm.getBlockPtOffset(), wasm.getBlockPtOffset() + 16));
			if (got !== pt) errs.push(`ct=${ct} exp=${pt} got=${got}`);
		}
		return errs;
	}, vtVecs);
	expect(errors, errors.join('\n')).toEqual([]);
});

test('S-box table entry — all 1536 vectors', async ({ page }) => {
	const errors: string[] = await page.evaluate(async (vecs) => {
		const wasm = await loadWasm();
		const errs: string[] = [];
		for (const { key, pt, ct } of vecs) {
			const k = fromHex(key);
			new Uint8Array(wasm.memory.buffer).set(k, wasm.getKeyOffset());
			if (wasm.loadKey(k.length) !== 0) {
				errs.push('loadKey failed'); continue;
			}
			new Uint8Array(wasm.memory.buffer).set(fromHex(pt), wasm.getBlockPtOffset());
			wasm.encryptBlock();
			const got = toHex(new Uint8Array(wasm.memory.buffer).slice(wasm.getBlockCtOffset(), wasm.getBlockCtOffset() + 16));
			if (got !== ct) errs.push(`pt=${pt} exp=${ct} got=${got}`);
		}
		return errs;
	}, tblVecs);
	expect(errors, errors.join('\n')).toEqual([]);
});
