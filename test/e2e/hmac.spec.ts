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
 * HMAC-SHA-256 and HMAC-SHA-512 Known-Answer Tests (cross-browser) — RFC 4231
 *
 * Source: RFC 4231 — HMAC-SHA Identifiers and Test Vectors
 * Files:  vectors/sha2.ts (hmacSha256Vectors, hmacSha512Vectors)
 */
import { test, expect } from '@playwright/test';
import { hmacSha256Vectors, hmacSha512Vectors } from '../vectors/sha2.js';

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

// ── Gate 5: HMAC-SHA256 TC1 ────────────────────────────────────────────────

test('Gate 5 — HMAC-SHA256 TC1', async ({ page }) => {
	const vec = hmacSha256Vectors[0];
	const result = await page.evaluate(async (v) => {
		const wasm = await loadWasm();
		const key = fromHex(v.key);
		const msg = fromHex(v.input);
		let mem = new Uint8Array(wasm.memory.buffer);
		mem.set(key, wasm.getSha256InputOffset());
		wasm.hmac256Init(key.length);
		mem = new Uint8Array(wasm.memory.buffer);
		mem.set(msg, wasm.getSha256InputOffset());
		wasm.hmac256Update(msg.length);
		wasm.hmac256Final();
		mem = new Uint8Array(wasm.memory.buffer);
		const out = mem.slice(wasm.getSha256OutOffset(), wasm.getSha256OutOffset() + 32);
		return toHex(out);
	}, vec);
	expect(result).toBe(vec.expected);
});

// ── Gate 6: HMAC-SHA512 TC6 (131-byte key) ────────────────────────────────

test('Gate 6 — HMAC-SHA512 TC6 (key > block size)', async ({ page }) => {
	const vec = hmacSha512Vectors[2]; // TC6 — 131-byte key
	const result = await page.evaluate(async (v) => {
		const wasm = await loadWasm();
		const key = fromHex(v.key);
		const msg = fromHex(v.input);
		// Pre-hash key > 128 bytes with SHA-512
		wasm.sha512Init();
		let mem = new Uint8Array(wasm.memory.buffer);
		mem.set(key.subarray(0, 128), wasm.getSha512InputOffset());
		wasm.sha512Update(128);
		mem = new Uint8Array(wasm.memory.buffer);
		mem.set(key.subarray(128), wasm.getSha512InputOffset());
		wasm.sha512Update(key.length - 128);
		wasm.sha512Final();
		mem = new Uint8Array(wasm.memory.buffer);
		const hashedKey = mem.slice(wasm.getSha512OutOffset(), wasm.getSha512OutOffset() + 64);
		// HMAC with pre-hashed key
		mem = new Uint8Array(wasm.memory.buffer);
		mem.set(hashedKey, wasm.getSha512InputOffset());
		wasm.hmac512Init(hashedKey.length);
		mem = new Uint8Array(wasm.memory.buffer);
		mem.set(msg, wasm.getSha512InputOffset());
		wasm.hmac512Update(msg.length);
		wasm.hmac512Final();
		mem = new Uint8Array(wasm.memory.buffer);
		const out = mem.slice(wasm.getSha512OutOffset(), wasm.getSha512OutOffset() + 64);
		return toHex(out);
	}, vec);
	expect(result).toBe(vec.expected);
});

// ── HMAC-SHA256 TC2 ("Jefe") ──────────────────────────────────────────────

test('HMAC-SHA256 TC2 ("Jefe")', async ({ page }) => {
	const vec = hmacSha256Vectors[1];
	const result = await page.evaluate(async (v) => {
		const wasm = await loadWasm();
		const key = fromHex(v.key);
		const msg = fromHex(v.input);
		let mem = new Uint8Array(wasm.memory.buffer);
		mem.set(key, wasm.getSha256InputOffset());
		wasm.hmac256Init(key.length);
		mem = new Uint8Array(wasm.memory.buffer);
		mem.set(msg, wasm.getSha256InputOffset());
		wasm.hmac256Update(msg.length);
		wasm.hmac256Final();
		mem = new Uint8Array(wasm.memory.buffer);
		const out = mem.slice(wasm.getSha256OutOffset(), wasm.getSha256OutOffset() + 32);
		return toHex(out);
	}, vec);
	expect(result).toBe(vec.expected);
});
