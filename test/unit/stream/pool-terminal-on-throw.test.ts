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
 * SealStreamPool terminal-on-throw. Both crypto-path and output-assembly
 * failures route through _killAll → dead + keys wiped + pending reject +
 * subsequent seal() throws "pool is dead". Crypto failure induced via
 * worker wipe; assembly failure via Proxy length MAX_SAFE_INTEGER.
 */
import '@vitest/web-worker';
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { SealStreamPool } from '../../../src/ts/stream/index.js';
import { TestXChaCha20Cipher as XChaCha20Cipher } from './_test-ciphers.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
});

describe('SealStreamPool, terminal on seal() throw', () => {
	async function makePool(): Promise<SealStreamPool> {
		const key = randomBytes(32);
		return SealStreamPool.create(XChaCha20Cipher, key, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		});
	}

	it('seal() rejection kills the pool, wipes keys, blocks further seal()', async () => {
		const pool = await makePool();

		// Sanity: keys populated before the induced failure.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const p = pool as any;
		expect(p._masterKey).not.toBeNull();
		expect(p._keys).not.toBeNull();
		expect(p._masterKey.some((b: number) => b !== 0)).toBe(true);

		// Induce a worker-side failure: wipe its internal state. Any subsequent
		// job the worker receives will reply with `worker not initialized`.
		const worker: Worker = p._workers[0];
		worker.postMessage({ type: 'wipe' });

		// Now seal() dispatches a job, worker errors → pool._killAll → reject → throw.
		let caught: unknown;
		try {
			await pool.seal(randomBytes(512));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(Error);
		expect((caught as Error).message).toMatch(/not initialized|pool/i);

		// Pool terminal state, regardless of which error bubbled.
		expect(pool.dead).toBe(true);

		// Subsequent seal() reports "pool is dead", NOT "already sealed".
		await expect(pool.seal(randomBytes(100))).rejects.toThrow(/pool is dead/);
		await expect(pool.seal(randomBytes(100))).rejects.not.toThrow(/already (sealed|called)/);

		// Key material nulled and the underlying buffers zeroed in place.
		expect(p._masterKey).toBeNull();
		expect(p._keys).toBeNull();
	});
});

describe('SealStreamPool, output-assembly RangeError also kills the pool', () => {
	async function makePool(): Promise<SealStreamPool> {
		const key = randomBytes(32);
		return SealStreamPool.create(XChaCha20Cipher, key, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		});
	}

	it('RangeError from combined output size kills the pool and wipes keys', async () => {
		const pool = await makePool();
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const p = pool as any;
		expect(p._masterKey).not.toBeNull();

		// Intercept _dispatch to return a Proxy that duck-types as a Uint8Array
		// but reports `.length = MAX_SAFE_INTEGER`. `new Uint8Array(totalLen)`
		// inside seal() rejects that as an invalid typed-array length, throwing
		// RangeError, after Promise.all has already resolved successfully.
		// The RangeError falls into the same catch as a crypto failure, which
		// routes through `_killAll` and kills the pool.
		p._dispatch = async (): Promise<Uint8Array> => {
			const real = new Uint8Array(16);
			return new Proxy(real, {
				get(t, k) {
					if (k === 'length') return Number.MAX_SAFE_INTEGER;
					return Reflect.get(t, k);
				},
			}) as unknown as Uint8Array;
		};

		await expect(pool.seal(randomBytes(100))).rejects.toThrow(RangeError);

		// Uniform terminal failure: pool dies, keys wiped.
		expect(pool.dead).toBe(true);
		expect(p._masterKey).toBeNull();
		expect(p._keys).toBeNull();

		// Subsequent seal reports "pool is dead", same as any other seal throw.
		await expect(pool.seal(randomBytes(100))).rejects.toThrow(/pool is dead/);
	});
});
