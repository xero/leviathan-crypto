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
// test/unit/init/init-race.test.ts
//
// Two concurrent initModule calls for the same module must coalesce: share a
// single in-flight promise, resolve to the same WebAssembly.Instance, and
// leak no extra compiled instances. _resetForTesting must clear instances,
// pending, and the exclusivity owners map.

import { describe, test, expect, beforeEach, vi } from 'vitest';
import {
	SHAKE128, init,
} from '../../../src/ts/index.js';
import {
	initModule, getInstance, isInitialized, _resetForTesting, _isModuleBusy,
} from '../../../src/ts/init.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';

beforeEach(() => {
	_resetForTesting();
});

describe('concurrent init coalescing', () => {
	test('two concurrent initModule calls for same module resolve to same instance', async () => {
		const real = WebAssembly.instantiate.bind(WebAssembly) as typeof WebAssembly.instantiate;
		const spy = vi.spyOn(WebAssembly, 'instantiate').mockImplementation(real);
		try {
			const [a, b] = await Promise.all([
				initModule('serpent', serpentWasm),
				initModule('serpent', serpentWasm),
			]);
			expect(a).toBeUndefined();
			expect(b).toBeUndefined();
			expect(isInitialized('serpent')).toBe(true);
			expect(spy).toHaveBeenCalledTimes(1);
		} finally {
			spy.mockRestore();
		}
	});

	test('concurrent inits return reference-equal instance (single compile)', async () => {
		const real = WebAssembly.instantiate.bind(WebAssembly) as typeof WebAssembly.instantiate;
		const spy = vi.spyOn(WebAssembly, 'instantiate').mockImplementation(real);
		try {
			await Promise.all([
				initModule('sha3', sha3Wasm),
				initModule('sha3', sha3Wasm),
				initModule('sha3', sha3Wasm),
			]);
			expect(isInitialized('sha3')).toBe(true);
			expect(spy).toHaveBeenCalledTimes(1);
		} finally {
			spy.mockRestore();
		}
	});

	test('sequential init after concurrent init is a no-op', async () => {
		await Promise.all([
			initModule('serpent', serpentWasm),
			initModule('serpent', serpentWasm),
		]);
		const first = getInstance('serpent');
		await initModule('serpent', serpentWasm);
		expect(getInstance('serpent')).toBe(first);
	});
});

describe('_resetForTesting clears all state', () => {
	test('clears instances map', async () => {
		await init({ serpent: serpentWasm });
		expect(isInitialized('serpent')).toBe(true);
		_resetForTesting();
		expect(isInitialized('serpent')).toBe(false);
		expect(() => getInstance('serpent')).toThrow(/call init/);
	});

	test('clears owners map (exclusivity registry)', async () => {
		await init({ sha3: sha3Wasm });
		const h = new SHAKE128();
		expect(_isModuleBusy('sha3')).toBe(true);
		_resetForTesting();
		expect(_isModuleBusy('sha3')).toBe(false);
		// h is now a zombie reference — do not call methods on it.
		// Re-init and re-use succeeds cleanly.
		await init({ sha3: sha3Wasm });
		const h2 = new SHAKE128();
		h2.dispose();
		// Deliberately avoid touching `h` — its token points to a reset registry.
		void h;
	});

	test('clears pending map — subsequent init re-populates', async () => {
		const p = initModule('serpent', serpentWasm);
		// If pending is leaked past reset, a subsequent init while the promise
		// is still unresolved would be a silent no-op. Wait for resolution
		// then reset and re-init to confirm the full cycle.
		await p;
		_resetForTesting();
		expect(isInitialized('serpent')).toBe(false);
		await initModule('serpent', serpentWasm);
		expect(isInitialized('serpent')).toBe(true);
	});
});
