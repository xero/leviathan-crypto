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
import { describe, test, expect, beforeAll, afterEach } from 'vitest';
import { init, Fortuna, SerpentCtr } from '../../src/ts/index.js';
import { SerpentGenerator } from '../../src/ts/serpent/index.js';
import { SHA256Hash } from '../../src/ts/sha2/index.js';
import { _resetForTesting } from '../../src/ts/init.js';
import { serpentWasm } from '../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm });
});

describe('Fortuna', () => {
	let fortuna: Fortuna;

	afterEach(() => {
		try {
			if (fortuna) fortuna.stop();
		} catch { /* already disposed */ }
	});

	test('Fortuna.create() returns a Fortuna instance', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash });
		expect(fortuna).toBeInstanceOf(Fortuna);
	});

	test('Fortuna.create() before init throws a clear error', async () => {
		_resetForTesting();
		await expect(Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash })).rejects.toThrow(
			/leviathan-crypto: call init\(\{.*\}\) before using Fortuna/,
		);
		// Restore init for remaining tests
		await init({ serpent: serpentWasm, sha2: sha2Wasm });
	});

	test('get(32) returns a 32-byte Uint8Array after seeding', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		const bytes = fortuna.get(32);
		expect(bytes).toBeInstanceOf(Uint8Array);
		expect(bytes.length).toBe(32);
	});

	test('get(1), get(64), get(128) return correct lengths', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		const b1 = fortuna.get(1);
		const b64 = fortuna.get(64);
		const b128 = fortuna.get(128);
		expect(b1.length).toBe(1);
		expect(b64.length).toBe(64);
		expect(b128.length).toBe(128);
	});

	test('two calls to get(32) return different values', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		const a = fortuna.get(32);
		const b = fortuna.get(32);
		expect(a).not.toEqual(b);
	});

	test('addEntropy() increases getEntropy() return value', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		const before = fortuna.getEntropy();
		fortuna.addEntropy(new Uint8Array(32));
		const after = fortuna.getEntropy();
		expect(after).toBeGreaterThan(before);
	});

	test('stop() disposes instance — all methods throw after stop()', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		const first = fortuna.get(32);
		expect(first).toBeInstanceOf(Uint8Array);

		fortuna.stop();

		expect(() => fortuna.get(32)).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.addEntropy(new Uint8Array(8))).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.getEntropy()).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.stop()).toThrow('Fortuna instance has been disposed');
	});

	test('msPerReseed option works — Fortuna.create({ msPerReseed: 0 }) allows immediate reseeds', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		// With msPerReseed: 0, reseed should trigger on first get()
		const result = fortuna.get(32);
		expect(result).toBeInstanceOf(Uint8Array);
		expect(fortuna._getReseedCnt()).toBeGreaterThan(0);
	});

	test('key replacement: genKey differs before and after get()', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		// Force initial reseed
		fortuna.get(16);

		const keyBefore = new Uint8Array(fortuna._getGenKey());
		fortuna.get(16);
		const keyAfter = new Uint8Array(fortuna._getGenKey());

		// Key must differ — key replacement is mandatory (spec §9.4)
		expect(keyBefore).not.toEqual(keyAfter);
	});

	test('Fortuna.get() throws cleanly when SerpentCtr holds the serpent module', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, entropy: new Uint8Array(32).fill(0x42) });
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		// Without the atomic-method `_assertNotOwned` guard, fortuna.get() would
		// silently overwrite KEY_BUFFER / SUBKEY_BUFFER from under the live ctr.
		expect(() => fortuna.get(32)).toThrow(/stateful instance is using/);
		ctr.dispose();
		// After dispose, Fortuna resumes normal operation.
		const bytes = fortuna.get(32);
		expect(bytes).toHaveLength(32);
	});

	test('Fortuna.stop() is exception-safe when SerpentCtr holds the serpent module', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash });
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		// stop() will throw because wipeBuffers on serpent throws — but disposed must be set,
		// key material wiped, and subsequent calls must refuse to run regardless.
		expect(() => fortuna.stop()).toThrow(/stateful instance is using/);
		expect(() => fortuna.get(32)).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.addEntropy(new Uint8Array(8))).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.getEntropy()).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.stop()).toThrow('Fortuna instance has been disposed');
		// genKey must be wiped even though wipeBuffers threw.
		const key = fortuna._getGenKey();
		expect(key.every(b => b === 0)).toBe(true);
		ctr.dispose();
	});
});
