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
import {
	sha3_256Vectors, sha3_512Vectors, shake128Vectors,
} from '../vectors/sha3.js';

const SERVER_BASE = 'http://localhost:1337';

const INIT = `
window.__wasmCache = window.__wasmCache || null;
window.loadWasm = async function() {
	if (window.__wasmCache) return window.__wasmCache;
	const mod = await import('${SERVER_BASE}/build/sha3.js');
	window.__wasmCache = mod;
	return mod;
};
window.fromHex = function(hex) {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
	return bytes;
};
window.toHex = function(bytes) {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
};
`;

test.beforeEach(async ({ page }) => {
	await page.goto(SERVER_BASE);
	await page.evaluate(INIT);
});

// ── Gate 7: SHA3-256 empty message ──────────────────────────────────────────

test('Gate 7 — SHA3-256 empty message', async ({ page }) => {
	const expected = sha3_256Vectors[0].expected;
	const result = await page.evaluate(async (_exp) => {
		const wasm = await loadWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		wasm.sha3_256Init();
		wasm.keccakAbsorb(0);
		wasm.sha3_256Final();
		const out = mem.slice(wasm.getOutOffset(), wasm.getOutOffset() + 32);
		return toHex(out);
	}, expected);
	expect(result).toBe(expected);
});

// ── SHA3-512 "abc" ──────────────────────────────────────────────────────────

test('SHA3-512 "abc"', async ({ page }) => {
	const vec = sha3_512Vectors[1]; // "abc"
	const result = await page.evaluate(async (v) => {
		const wasm = await loadWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		const input = fromHex(v.input);
		wasm.sha3_512Init();
		mem.set(input, wasm.getInputOffset());
		wasm.keccakAbsorb(input.length);
		wasm.sha3_512Final();
		const out = mem.slice(wasm.getOutOffset(), wasm.getOutOffset() + 64);
		return toHex(out);
	}, vec);
	expect(result).toBe(vec.expected);
});

// ── SHAKE128 empty, 32-byte output ──────────────────────────────────────────

test('SHAKE128 empty, 32-byte output', async ({ page }) => {
	const vec = shake128Vectors[0];
	const result = await page.evaluate(async (v) => {
		const wasm = await loadWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		wasm.shake128Init();
		wasm.keccakAbsorb(0);
		wasm.shakeFinal(v.outputLength);
		const out = mem.slice(wasm.getOutOffset(), wasm.getOutOffset() + v.outputLength);
		return toHex(out);
	}, vec);
	expect(result).toBe(vec.expected);
});
