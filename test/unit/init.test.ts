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
import { getInstance, _resetForTesting } from '../../src/ts/init.js';

beforeEach(() => {
	_resetForTesting();
});

describe('init()', () => {
	test('error before init — serpent', () => {
		expect(() => getInstance('serpent')).toThrow(
			'leviathan-crypto: call init([\'serpent\']) before using this class',
		);
	});

	test('error before init — sha3', () => {
		expect(() => getInstance('sha3')).toThrow(
			'leviathan-crypto: call init([\'sha3\']) before using this class',
		);
	});

	test('embedded mode — single module', async () => {
		await init('serpent');
		expect(_serpentReady()).toBe(true);
		expect(_chachaReady()).toBe(false);
	});

	test('embedded mode — multiple modules', async () => {
		await init(['serpent', 'sha3']);
		expect(_serpentReady()).toBe(true);
		expect(_sha3Ready()).toBe(true);
		expect(_chachaReady()).toBe(false);
		expect(_sha2Ready()).toBe(false);
	});

	test('embedded mode — all four modules', async () => {
		await init(['serpent', 'chacha20', 'sha2', 'sha3']);
		expect(_serpentReady()).toBe(true);
		expect(_chachaReady()).toBe(true);
		expect(_sha2Ready()).toBe(true);
		expect(_sha3Ready()).toBe(true);
	});

	test('idempotent — second init is a no-op', async () => {
		await init('serpent');
		const inst1 = getInstance('serpent');
		await init('serpent');
		const inst2 = getInstance('serpent');
		expect(inst1).toBe(inst2);
	});

	test('partial init — loading serpent does not make sha3 available', async () => {
		await init(['serpent']);
		expect(_serpentReady()).toBe(true);
		expect(() => getInstance('sha3')).toThrow();
	});

	test('manual mode — accepts ArrayBuffer', async () => {
		const { readFileSync } = await import('fs');
		const { resolve, dirname } = await import('path');
		const { fileURLToPath } = await import('url');
		const __dirname = dirname(fileURLToPath(import.meta.url));
		const wasmPath = resolve(__dirname, '../../build/serpent.wasm');
		const binary = readFileSync(wasmPath);

		const bytes = new Uint8Array(binary);
		await init(['serpent'], 'manual', {
			wasmBinary: { serpent: bytes },
		});
		expect(_serpentReady()).toBe(true);
	});

	test('WASM instance exports getModuleId', async () => {
		await init(['serpent', 'chacha20', 'sha2', 'sha3']);
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
