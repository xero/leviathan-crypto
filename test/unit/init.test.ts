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
import { describe, test, expect, beforeEach } from 'vitest';
import { init, _serpentReady, _chachaReady, _sha2Ready, _sha3Ready } from '../../src/ts/index.js';
import { getInstance, isInitialized, _resetForTesting } from '../../src/ts/init.js';
import { keccakInit } from '../../src/ts/keccak/index.js';
import { serpentWasm } from '../../src/ts/serpent/embedded.js';
import { chacha20Wasm } from '../../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../../src/ts/sha2/embedded.js';
import { sha3Wasm } from '../../src/ts/sha3/embedded.js';
import { keccakWasm } from '../../src/ts/keccak/embedded.js';

beforeEach(() => {
	_resetForTesting();
});

describe('init()', () => {
	test('error before init — serpent', () => {
		expect(() => getInstance('serpent')).toThrow(
			'leviathan-crypto: call init({ serpent: ... }) before using this class',
		);
	});

	test('error before init — sha3', () => {
		expect(() => getInstance('sha3')).toThrow(
			'leviathan-crypto: call init({ sha3: ... }) before using this class',
		);
	});

	test('unknown module key → throws Error', async () => {
		// @ts-expect-error — testing runtime guard for invalid keys
		await expect(init({ bogus: serpentWasm })).rejects.toThrow(/unknown module "bogus"/);
	});

	test('embedded mode — single module', async () => {
		await init({ serpent: serpentWasm });
		expect(_serpentReady()).toBe(true);
		expect(_chachaReady()).toBe(false);
	});

	test('embedded mode — multiple modules', async () => {
		await init({ serpent: serpentWasm, sha3: sha3Wasm });
		expect(_serpentReady()).toBe(true);
		expect(_sha3Ready()).toBe(true);
		expect(_chachaReady()).toBe(false);
		expect(_sha2Ready()).toBe(false);
	});

	test('embedded mode — all four modules', async () => {
		await init({ serpent: serpentWasm, chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm });
		expect(_serpentReady()).toBe(true);
		expect(_chachaReady()).toBe(true);
		expect(_sha2Ready()).toBe(true);
		expect(_sha3Ready()).toBe(true);
	});

	test('idempotent — second init is a no-op', async () => {
		await init({ serpent: serpentWasm });
		const inst1 = getInstance('serpent');
		await init({ serpent: serpentWasm });
		const inst2 = getInstance('serpent');
		expect(inst1).toBe(inst2);
	});

	test('partial init — loading serpent does not make sha3 available', async () => {
		await init({ serpent: serpentWasm });
		expect(_serpentReady()).toBe(true);
		expect(() => getInstance('sha3')).toThrow();
	});

	test('ArrayBuffer source — accepts raw WASM bytes', async () => {
		const { readFileSync } = await import('fs');
		const { resolve, dirname } = await import('path');
		const { fileURLToPath } = await import('url');
		const __dirname = dirname(fileURLToPath(import.meta.url));
		const wasmPath = resolve(__dirname, '../../build/serpent.wasm');
		const buf = readFileSync(wasmPath);
		// Ensure we pass a proper ArrayBuffer (not a Node Buffer's backing store)
		const arrayBuf = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
		await init({ serpent: arrayBuf });
		expect(_serpentReady()).toBe(true);
	});

	// ── keccak alias ─────────────────────────────────────────────────────────

	test('error before init — keccak', () => {
		expect(() => getInstance('keccak')).toThrow(
			'leviathan-crypto: call init({ keccak: ... }) before using this class',
		);
	});

	test('init with keccak name loads sha3 instance', async () => {
		await init({ keccak: sha3Wasm });
		expect(_sha3Ready()).toBe(true);
		expect(isInitialized('sha3')).toBe(true);
		expect(isInitialized('keccak')).toBe(true);
	});

	test('init with sha3 name makes keccak available', async () => {
		await init({ sha3: sha3Wasm });
		expect(isInitialized('keccak')).toBe(true);
	});

	test('getInstance("keccak") returns same instance as getInstance("sha3")', async () => {
		await init({ sha3: sha3Wasm });
		expect(getInstance('keccak')).toBe(getInstance('sha3'));
	});

	test('idempotent — sha3 then keccak is a no-op', async () => {
		await init({ sha3: sha3Wasm });
		const inst1 = getInstance('sha3');
		await init({ keccak: sha3Wasm });
		const inst2 = getInstance('sha3');
		expect(inst1).toBe(inst2);
	});

	test('both names in one call does not error', async () => {
		await init({ sha3: sha3Wasm, keccak: sha3Wasm });
		expect(isInitialized('sha3')).toBe(true);
	});

	test('keccak subpath init works standalone', async () => {
		await keccakInit(sha3Wasm);
		expect(isInitialized('keccak')).toBe(true);
		expect(isInitialized('sha3')).toBe(true);
	});

	test('keccak embedded re-export is the same blob', () => {
		expect(keccakWasm).toBe(sha3Wasm);
	});

	// ── end keccak alias ──────────────────────────────────────────────────────

	test('WASM instance exports getModuleId', async () => {
		await init({ serpent: serpentWasm, chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm });
		const serpent = getInstance('serpent').exports as { getModuleId: () => number };
		const chacha = getInstance('chacha20').exports as { getModuleId: () => number };
		const sha2 = getInstance('sha2').exports as { getModuleId: () => number };
		const sha3 = getInstance('sha3').exports as { getModuleId: () => number };

		expect(serpent.getModuleId()).toBe(0);
		expect(chacha.getModuleId()).toBe(1);
		expect(sha2.getModuleId()).toBe(2);
		expect(sha3.getModuleId()).toBe(3);
	});
});
