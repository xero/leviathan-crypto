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
import { init, Fortuna } from '../../src/ts/index.js';
import { _resetForTesting } from '../../src/ts/init.js';

beforeAll(async () => {
	await init(['serpent', 'sha2']);
});

describe('Fortuna', () => {
	let fortuna: Fortuna;

	afterEach(() => {
		try {
			if (fortuna) fortuna.stop();
		} catch { /* already disposed */ }
	});

	test('Fortuna.create() returns a Fortuna instance', async () => {
		fortuna = await Fortuna.create();
		expect(fortuna).toBeInstanceOf(Fortuna);
	});

	test('Fortuna.create() before init throws a clear error', async () => {
		_resetForTesting();
		await expect(Fortuna.create()).rejects.toThrow(
			'leviathan-crypto: call init([\'serpent\', \'sha2\']) before using Fortuna',
		);
		// Restore init for remaining tests
		await init(['serpent', 'sha2']);
	});

	test('get(32) returns a 32-byte Uint8Array after seeding', async () => {
		fortuna = await Fortuna.create({ msPerReseed: 0 });
		const bytes = fortuna.get(32);
		expect(bytes).toBeInstanceOf(Uint8Array);
		expect(bytes.length).toBe(32);
	});

	test('get(1), get(64), get(128) return correct lengths', async () => {
		fortuna = await Fortuna.create({ msPerReseed: 0 });
		const b1 = fortuna.get(1);
		const b64 = fortuna.get(64);
		const b128 = fortuna.get(128);
		expect(b1.length).toBe(1);
		expect(b64.length).toBe(64);
		expect(b128.length).toBe(128);
	});

	test('two calls to get(32) return different values', async () => {
		fortuna = await Fortuna.create({ msPerReseed: 0 });
		const a = fortuna.get(32);
		const b = fortuna.get(32);
		expect(a).not.toEqual(b);
	});

	test('addEntropy() increases getEntropy() return value', async () => {
		fortuna = await Fortuna.create({ msPerReseed: 0 });
		const before = fortuna.getEntropy();
		fortuna.addEntropy(new Uint8Array(32));
		const after = fortuna.getEntropy();
		expect(after).toBeGreaterThan(before);
	});

	test('stop() disposes instance — all methods throw after stop()', async () => {
		fortuna = await Fortuna.create({ msPerReseed: 0 });
		const first = fortuna.get(32);
		expect(first).toBeInstanceOf(Uint8Array);

		fortuna.stop();

		expect(() => fortuna.get(32)).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.addEntropy(new Uint8Array(8))).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.getEntropy()).toThrow('Fortuna instance has been disposed');
		expect(() => fortuna.stop()).toThrow('Fortuna instance has been disposed');
	});

	test('msPerReseed option works — Fortuna.create({ msPerReseed: 0 }) allows immediate reseeds', async () => {
		fortuna = await Fortuna.create({ msPerReseed: 0 });
		// With msPerReseed: 0, reseed should trigger on first get()
		const result = fortuna.get(32);
		expect(result).toBeInstanceOf(Uint8Array);
		expect(fortuna._getReseedCnt()).toBeGreaterThan(0);
	});

	test('pool selection: P0 consumed every reseed, P1 every other', async () => {
		fortuna = await Fortuna.create({ msPerReseed: 0 });

		// After create(), reseedCnt is already 1 (forced reseed in create()).
		// Pool[0] was drained — refill it to trigger reseed #2.
		fortuna.addEntropy(new Uint8Array(64));
		fortuna.get(16);
		const reseed1 = fortuna._getReseedCnt();
		expect(reseed1).toBe(2); // binary: 10 — P1 consumed (reseed #2)
		expect(reseed1 & 1).toBe(0); // P0 NOT used on reseed #2
		expect(reseed1 & 2).toBe(2); // P1 used on reseed #2

		// Pool[0] still has entropy (not consumed on reseed #2).
		// Add more entropy and trigger reseed #3.
		fortuna.addEntropy(new Uint8Array(64));
		fortuna.get(16);
		const reseed2 = fortuna._getReseedCnt();
		expect(reseed2).toBe(3); // binary: 11 — P0 and P1 both consumed
		expect(reseed2 & 1).toBe(1); // P0 used on reseed #3
		expect(reseed2 & 2).toBe(2); // P1 used on reseed #3
	});

	test('key replacement: genKey differs before and after get()', async () => {
		fortuna = await Fortuna.create({ msPerReseed: 0 });
		// Force initial reseed
		fortuna.get(16);

		const keyBefore = new Uint8Array(fortuna._getGenKey());
		fortuna.get(16);
		const keyAfter = new Uint8Array(fortuna._getGenKey());

		// Key must differ — key replacement is mandatory (spec §9.4)
		expect(keyBefore).not.toEqual(keyAfter);
	});
});
