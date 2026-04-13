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
// test/unit/loader/wasm_source.test.ts
//
// WasmSource loader tests — all seven source types, invalid inputs, and double-init.
// Uses the sha3 module (smallest WASM) for all tests.
// Every valid-source test crosses the WASM boundary: hash a known input and
// assert the digest matches the FIPS 202 SHA3-256("abc") vector.

import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'http';
import { sha3Init, SHA3_256 } from '../../../src/ts/sha3/index.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { loadWasm } from '../../../src/ts/loader.js';
import type { WasmSource } from '../../../src/ts/wasm-source.js';
import { getInstance, _resetForTesting } from '../../../src/ts/init.js';

// ── Helpers ─────────────────────────────────────────────────────────────────

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// FIPS 202 §A.1 — SHA3-256 of UTF-8 "abc"
const SHA3_256_ABC = '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532';

/**
 * Init sha3 from the given source, hash UTF-8 "abc" with SHA3-256,
 * assert the FIPS 202 digest, then dispose and verify wipeBuffers() zeroed
 * the output buffer in WASM memory.
 */
async function runCryptoCheck(source: WasmSource): Promise<void> {
	await sha3Init(source);
	const h = new SHA3_256();
	const out = h.hash(new TextEncoder().encode('abc'));
	expect(toHex(out)).toBe(SHA3_256_ABC);
	h.dispose(); // calls wipeBuffers()
	// Verify output buffer in WASM memory is zeroed after wipe
	const inst = getInstance('sha3');
	const mem = new Uint8Array((inst.exports as { memory: WebAssembly.Memory }).memory.buffer);
	const outOff = (inst.exports as { getOutOffset(): number }).getOutOffset();
	const afterWipe = mem.slice(outOff, outOff + 32);
	expect(Array.from(afterWipe).every(b => b === 0)).toBe(true);
}

// ── Fixtures ────────────────────────────────────────────────────────────────

// Raw WASM bytes — loaded once, reused across tests
let wasmArrayBuf: ArrayBuffer;
let server: import('http').Server;
let sha3Url: URL;

beforeAll(async () => {
	const { readFileSync } = await import('fs');
	const { resolve, dirname } = await import('path');
	const { fileURLToPath } = await import('url');
	const dir = dirname(fileURLToPath(import.meta.url));
	const nodeBuf = readFileSync(resolve(dir, '../../../build/sha3.wasm'));
	// Convert Node Buffer to a proper ArrayBuffer (Buffer's .buffer may cover more than the data)
	wasmArrayBuf = nodeBuf.buffer.slice(nodeBuf.byteOffset, nodeBuf.byteOffset + nodeBuf.byteLength) as ArrayBuffer;

	// Spin up a minimal HTTP server for the URL source type test.
	// Port 0 lets the OS assign a free port — avoids CI conflicts.
	// WebAssembly.instantiateStreaming requires HTTP with Content-Type: application/wasm.
	const wasmBytes = new Uint8Array(wasmArrayBuf);
	server = http.createServer((_, res) => {
		res.writeHead(200, { 'Content-Type': 'application/wasm' });
		res.end(wasmBytes);
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const addr = server.address() as { port: number };
	sha3Url = new URL(`http://127.0.0.1:${addr.port}/sha3.wasm`);
});

afterAll(() => {
	server?.close();
});

beforeEach(() => {
	_resetForTesting();
});

// ── Valid source types ──────────────────────────────────────────────────────

describe('WasmSource — valid types', () => {
	test('string (gzip+base64 embedded blob)', async () => {
		await runCryptoCheck(sha3Wasm);
	});

	test('URL (fetch + instantiateStreaming)', async () => {
		await runCryptoCheck(sha3Url);
	});

	test('ArrayBuffer (raw WASM bytes)', async () => {
		await runCryptoCheck(wasmArrayBuf);
	});

	test('Uint8Array (raw WASM bytes)', async () => {
		await runCryptoCheck(new Uint8Array(wasmArrayBuf));
	});

	test('WebAssembly.Module (pre-compiled)', async () => {
		const mod = await WebAssembly.compile(wasmArrayBuf);
		await runCryptoCheck(mod);
	});

	test('Response (streaming instantiation)', async () => {
		const response = new Response(new Uint8Array(wasmArrayBuf), {
			headers: { 'Content-Type': 'application/wasm' },
		});
		await runCryptoCheck(response);
	});

	test('Promise<Response> (deferred streaming instantiation)', async () => {
		const deferred = Promise.resolve(
			new Response(new Uint8Array(wasmArrayBuf), {
				headers: { 'Content-Type': 'application/wasm' },
			}),
		);
		await runCryptoCheck(deferred);
	});
});

// ── Invalid inputs ──────────────────────────────────────────────────────────

describe('WasmSource — invalid inputs', () => {
	test('null throws TypeError', async () => {
		await expect(
			loadWasm(null as unknown as WasmSource),
		).rejects.toThrow(/leviathan-crypto: invalid WasmSource/);
	});

	test('number throws TypeError', async () => {
		await expect(
			loadWasm(42 as unknown as WasmSource),
		).rejects.toThrow(/leviathan-crypto: invalid WasmSource/);
	});

	test('empty string throws TypeError', async () => {
		await expect(
			loadWasm('' as WasmSource),
		).rejects.toThrow(/leviathan-crypto: invalid WasmSource — empty string/);
	});

	test('corrupt base64 string throws', async () => {
		await expect(
			loadWasm('not-valid-base64-and-not-gzip!!!!' as WasmSource),
		).rejects.toThrow();
	});

	test('truncated ArrayBuffer throws', async () => {
		await expect(
			loadWasm(new ArrayBuffer(4)),
		).rejects.toThrow();
	});
});

// ── Double-init (idempotency) ───────────────────────────────────────────────

describe('WasmSource — double init', () => {
	test('second init with same source is a no-op', async () => {
		await sha3Init(sha3Wasm);
		const inst1 = getInstance('sha3');
		await sha3Init(sha3Wasm);
		const inst2 = getInstance('sha3');
		expect(inst1).toBe(inst2);
	});

	test('second init with different source type is a no-op', async () => {
		await sha3Init(sha3Wasm); // string source
		const inst1 = getInstance('sha3');
		await sha3Init(wasmArrayBuf); // ArrayBuffer source — should be ignored
		const inst2 = getInstance('sha3');
		expect(inst1).toBe(inst2);
	});
});
