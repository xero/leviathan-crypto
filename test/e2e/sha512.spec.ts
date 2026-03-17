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
import { sha512Vectors, sha384Vectors } from '../vectors/sha2.js';

const SERVER_BASE = 'http://localhost:1337';

const INIT = `
window.__wasmCache = window.__wasmCache || null;
window.loadWasm = async function() {
	if (window.__wasmCache) return window.__wasmCache;
	const mod = await import('${SERVER_BASE}/build/sha2.js');
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

// ── Gate 4: SHA-512 "abc" ──────────────────────────────────────────────────

test('Gate 4 — SHA-512 "abc"', async ({ page }) => {
	const vec = sha512Vectors[1]; // "abc"
	const result = await page.evaluate(async (v) => {
		const wasm = await loadWasm();
		const input = fromHex(v.input);
		wasm.sha512Init();
		let mem = new Uint8Array(wasm.memory.buffer);
		mem.set(input, wasm.getSha512InputOffset());
		wasm.sha512Update(input.length);
		wasm.sha512Final();
		mem = new Uint8Array(wasm.memory.buffer);
		const out = mem.slice(wasm.getSha512OutOffset(), wasm.getSha512OutOffset() + 64);
		return toHex(out);
	}, vec);
	expect(result).toBe(vec.expected);
});

// ── SHA-384 "abc" ──────────────────────────────────────────────────────────

test('SHA-384 "abc"', async ({ page }) => {
	const vec = sha384Vectors[1]; // "abc"
	const result = await page.evaluate(async (v) => {
		const wasm = await loadWasm();
		const input = fromHex(v.input);
		wasm.sha384Init();
		let mem = new Uint8Array(wasm.memory.buffer);
		mem.set(input, wasm.getSha512InputOffset());
		wasm.sha512Update(input.length);
		wasm.sha384Final();
		mem = new Uint8Array(wasm.memory.buffer);
		const out = mem.slice(wasm.getSha512OutOffset(), wasm.getSha512OutOffset() + 48);
		return toHex(out);
	}, vec);
	expect(result).toBe(vec.expected);
});

// ── SHA-512 streaming (4 × 128-byte chunks) ───────────────────────────────

test('SHA-512 streaming 512 bytes in 4 chunks', async ({ page }) => {
	const result = await page.evaluate(async () => {
		const wasm = await loadWasm();
		const input = new Uint8Array(512);
		for (let i = 0; i < 512; i++) input[i] = i & 0xff;

		wasm.sha512Init();
		for (let pos = 0; pos < 512; pos += 128) {
			const mem = new Uint8Array(wasm.memory.buffer);
			mem.set(input.subarray(pos, pos + 128), wasm.getSha512InputOffset());
			wasm.sha512Update(128);
		}
		wasm.sha512Final();
		const mem = new Uint8Array(wasm.memory.buffer);
		return toHex(mem.slice(wasm.getSha512OutOffset(), wasm.getSha512OutOffset() + 64));
	});
	expect(typeof result).toBe('string');
	expect(result.length).toBe(128);
});
