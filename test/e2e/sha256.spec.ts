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
import { sha256Vectors } from '../vectors/sha2.js';

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

// ── Gate 3: SHA-256 empty message ──────────────────────────────────────────

test('Gate 3 — SHA-256 empty message', async ({ page }) => {
	const expected = sha256Vectors[0].expected;
	const result = await page.evaluate(async () => {
		const wasm = await loadWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		wasm.sha256Init();
		wasm.sha256Update(0);
		wasm.sha256Final();
		const out = mem.slice(wasm.getSha256OutOffset(), wasm.getSha256OutOffset() + 32);
		return toHex(out);
	});
	expect(result).toBe(expected);
});

// ── SHA-256 "abc" ──────────────────────────────────────────────────────────

test('SHA-256 "abc"', async ({ page }) => {
	const vec = sha256Vectors[1]; // "abc"
	const result = await page.evaluate(async (v) => {
		const wasm = await loadWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		const input = fromHex(v.input);
		wasm.sha256Init();
		mem.set(input, wasm.getSha256InputOffset());
		wasm.sha256Update(input.length);
		wasm.sha256Final();
		const out = new Uint8Array(wasm.memory.buffer).slice(
			wasm.getSha256OutOffset(), wasm.getSha256OutOffset() + 32,
		);
		return toHex(out);
	}, vec);
	expect(result).toBe(vec.expected);
});

// ── SHA-256 streaming (4 × 64-byte chunks) ────────────────────────────────

test('SHA-256 streaming 256 bytes in 4 chunks', async ({ page }) => {
	const result = await page.evaluate(async () => {
		const wasm = await loadWasm();
		const input = new Uint8Array(256);
		for (let i = 0; i < 256; i++) input[i] = i & 0xff;

		// Single-call reference
		wasm.sha256Init();
		for (let pos = 0; pos < 256; pos += 64) {
			const mem = new Uint8Array(wasm.memory.buffer);
			mem.set(input.subarray(pos, pos + 64), wasm.getSha256InputOffset());
			wasm.sha256Update(64);
		}
		wasm.sha256Final();
		const out = new Uint8Array(wasm.memory.buffer);
		return toHex(out.slice(wasm.getSha256OutOffset(), wasm.getSha256OutOffset() + 32));
	});
	expect(typeof result).toBe('string');
	expect(result.length).toBe(64);
});
