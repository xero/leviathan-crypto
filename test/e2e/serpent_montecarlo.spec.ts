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
 * Monte Carlo cross-browser tests — Serpent ECB + CBC
 *
 * Reduced: 50 outer × 10,000 inner (vs 1,200 in Vitest).
 * A correct 50-iteration result is strong evidence of correct 1,200-iteration
 * behavior — Monte Carlo errors compound within the first few iterations.
 */
import { test, expect } from '@playwright/test';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC_DIR = resolve(__dirname, '../../test/vectors');
const JS_URL  = 'http://localhost:1337/build/serpent.js';

function readVec(name: string) {
	return readFileSync(resolve(VEC_DIR, name), 'utf8');
}

interface McVec    { keysize: number; key: string; pt: string; ct: string }
interface CbcMcVec { keysize: number; key: string; iv: string; pt: string; ct: string }

function parseMcEncrypt(text: string): McVec[] {
	const vecs: McVec[] = [];
	const lines = text.split('\n').map(l => l.trim());
	let ks = 0;
	for (let i = 0; i < lines.length; i++) {
		if (lines[i].startsWith('KEYSIZE=')) {
			ks = parseInt(lines[i].slice(8)); continue;
		}
		if (!lines[i].startsWith('I=')) continue;
		const fs: string[] = [];
		for (let j = i + 1; j < lines.length && fs.length < 3; j++) {
			if (lines[j]) fs.push(lines[j]);
		}
		if (fs.length === 3 && fs[0].startsWith('KEY=') && fs[1].startsWith('PT=') && fs[2].startsWith('CT='))
			vecs.push({ keysize: ks, key: fs[0].slice(4).toLowerCase(), pt: fs[1].slice(3).toLowerCase(), ct: fs[2].slice(3).toLowerCase() });
	}
	return vecs;
}

function parseMcCbcEncrypt(text: string): CbcMcVec[] {
	const vecs: CbcMcVec[] = [];
	const lines = text.split('\n').map(l => l.trim());
	let ks = 0;
	for (let i = 0; i < lines.length; i++) {
		if (lines[i].startsWith('KEYSIZE=')) {
			ks = parseInt(lines[i].slice(8)); continue;
		}
		if (!lines[i].startsWith('I=')) continue;
		const fs: string[] = [];
		for (let j = i + 1; j < lines.length && fs.length < 4; j++) {
			if (lines[j]) fs.push(lines[j]);
		}
		if (fs.length === 4 && fs[0].startsWith('KEY=') && fs[1].startsWith('IV=') &&
			fs[2].startsWith('PT=') && fs[3].startsWith('CT='))
			vecs.push({ keysize: ks, key: fs[0].slice(4).toLowerCase(), iv: fs[1].slice(3).toLowerCase(),
				pt: fs[2].slice(3).toLowerCase(), ct: fs[3].slice(3).toLowerCase() });
	}
	return vecs;
}

function parseMcCbcDecrypt(text: string): CbcMcVec[] {
	const vecs: CbcMcVec[] = [];
	const lines = text.split('\n').map(l => l.trim());
	let ks = 0;
	for (let i = 0; i < lines.length; i++) {
		if (lines[i].startsWith('KEYSIZE=')) {
			ks = parseInt(lines[i].slice(8)); continue;
		}
		if (!lines[i].startsWith('I=')) continue;
		const fs: string[] = [];
		for (let j = i + 1; j < lines.length && fs.length < 4; j++) {
			if (lines[j]) fs.push(lines[j]);
		}
		if (fs.length === 4 && fs[0].startsWith('KEY=') && fs[1].startsWith('IV=') &&
			fs[2].startsWith('CT=') && fs[3].startsWith('PT='))
			vecs.push({ keysize: ks, key: fs[0].slice(4).toLowerCase(), iv: fs[1].slice(3).toLowerCase(),
				pt: fs[3].slice(3).toLowerCase(), ct: fs[2].slice(3).toLowerCase() });
	}
	return vecs;
}

const BROWSER_MC_OUTER = 50;

// ~17 per key size × 3 key sizes ≈ 50 outer total
const mcVecs = parseMcEncrypt(readVec('serpent_ecb_e_m.txt'))
	.filter((_, i) => i % 400 < Math.ceil(BROWSER_MC_OUTER / 3));

const mcCbcEncVecs = parseMcCbcEncrypt(readVec('serpent_cbc_e_m.txt'))
	.filter((_, i) => i % 400 < Math.ceil(BROWSER_MC_OUTER / 3));
const mcCbcDecVecs = parseMcCbcDecrypt(readVec('serpent_cbc_d_m.txt'))
	.filter((_, i) => i % 400 < Math.ceil(BROWSER_MC_OUTER / 3));

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

test(`Monte Carlo ECB encrypt — ${mcVecs.length} vectors × 10000 inner`, async ({ page }) => {
	const errors: string[] = await page.evaluate(async (vecs) => {
		const wasm  = await loadWasm();
		const ptOff = wasm.getBlockPtOffset();
		const ctOff = wasm.getBlockCtOffset();
		const errs: string[] = [];
		for (const v of vecs) {
			const key = fromHex(v.key);
			new Uint8Array(wasm.memory.buffer).set(key, wasm.getKeyOffset());
			wasm.loadKey(key.length);
			new Uint8Array(wasm.memory.buffer).set(fromHex(v.pt), ptOff);
			for (let j = 0; j < 10000; j++) {
				wasm.encryptBlock();
				new Uint8Array(wasm.memory.buffer).set(
					new Uint8Array(wasm.memory.buffer).subarray(ctOff, ctOff + 16), ptOff);
			}
			const got = toHex(new Uint8Array(wasm.memory.buffer).slice(ptOff, ptOff + 16));
			if (got !== v.ct) errs.push(`ks=${v.keysize} exp=${v.ct} got=${got}`);
		}
		return errs;
	}, mcVecs);
	expect(errors, errors.join('\n')).toEqual([]);
});

test(`Monte Carlo CBC encrypt — ${mcCbcEncVecs.length} vectors × 10000 inner`, async ({ page }) => {
	const errors: string[] = await page.evaluate(async (vecs) => {
		const wasm  = await loadWasm();
		const ptOff = wasm.getBlockPtOffset();
		const ctOff = wasm.getBlockCtOffset();
		const errs: string[] = [];
		for (const v of vecs) {
			const key = fromHex(v.key);
			new Uint8Array(wasm.memory.buffer).set(key, wasm.getKeyOffset());
			wasm.loadKey(key.length);
			let iv = fromHex(v.iv);
			let pt = fromHex(v.pt);
			let ct9999 = new Uint8Array(16);
			for (let j = 0; j < 10000; j++) {
				const cv = new Uint8Array(iv);
				const xored = new Uint8Array(16);
				for (let k = 0; k < 16; k++) xored[k] = pt[k] ^ iv[k];
				new Uint8Array(wasm.memory.buffer).set(xored, ptOff);
				wasm.encryptBlock();
				ct9999 = new Uint8Array(wasm.memory.buffer).slice(ctOff, ctOff + 16);
				pt = cv;
				iv = new Uint8Array(ct9999);
			}
			const got = toHex(ct9999);
			if (got !== v.ct) errs.push(`ks=${v.keysize} exp=${v.ct} got=${got}`);
		}
		return errs;
	}, mcCbcEncVecs);
	expect(errors, errors.join('\n')).toEqual([]);
});

test(`Monte Carlo CBC decrypt — ${mcCbcDecVecs.length} vectors × 10000 inner`, async ({ page }) => {
	const errors: string[] = await page.evaluate(async (vecs) => {
		const wasm  = await loadWasm();
		const ptOff = wasm.getBlockPtOffset();
		const ctOff = wasm.getBlockCtOffset();
		const errs: string[] = [];
		for (const v of vecs) {
			const key = fromHex(v.key);
			new Uint8Array(wasm.memory.buffer).set(key, wasm.getKeyOffset());
			wasm.loadKey(key.length);
			let iv = fromHex(v.iv);
			let ct = fromHex(v.ct);
			let pt9999 = new Uint8Array(16);
			for (let j = 0; j < 10000; j++) {
				new Uint8Array(wasm.memory.buffer).set(ct, ctOff);
				wasm.decryptBlock();
				const decrypted = new Uint8Array(wasm.memory.buffer).slice(ptOff, ptOff + 16);
				const pt = new Uint8Array(16);
				for (let k = 0; k < 16; k++) pt[k] = decrypted[k] ^ iv[k];
				pt9999 = new Uint8Array(pt);
				iv = new Uint8Array(ct);
				ct = new Uint8Array(pt);
			}
			const got = toHex(pt9999);
			if (got !== v.pt) errs.push(`ks=${v.keysize} exp=${v.pt} got=${got}`);
		}
		return errs;
	}, mcCbcDecVecs);
	expect(errors, errors.join('\n')).toEqual([]);
});
