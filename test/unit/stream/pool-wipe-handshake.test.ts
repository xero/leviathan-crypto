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
 * SealStreamPool wipe-before-terminate ACK handshake.
 *
 * `_killAll` posts `{ type: 'wipe' }` to each worker and waits up to 100 ms
 * for a `{ type: 'wiped' }` reply before calling `terminate()`. On ACK the
 * terminate fires immediately; on timeout the terminate fires anyway.
 *
 * Two cases covered:
 *
 * 1. Happy path — the real pool worker zeros its key material and posts
 *    `{ type: 'wiped' }` back. The main thread observes the ACK and the
 *    worker stops receiving messages afterward.
 * 2. Timeout fallback — a worker stub whose wipe handler deliberately never
 *    replies. After 100 ms the fallback `terminate()` runs, the pool is
 *    dead, and no unhandled rejection escapes.
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

describe('SealStreamPool — wipe ACK handshake', () => {
	it('destroy() drives each worker through wipe → wiped → terminate', async () => {
		const key = randomBytes(32);
		const pool = await SealStreamPool.create(XChaCha20Cipher, key, {
			wasm: chacha20Wasm, workers: 2, chunkSize: 1024,
		});

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const p = pool as any;
		const workers: Worker[] = [...p._workers];
		expect(workers.length).toBe(2);

		// Instrument each worker to record {type:'wiped'} replies and the
		// order of send/receive relative to terminate. We snoop by wrapping
		// addEventListener so both the pool's own listener and our observer
		// see the reply.
		const observed: { worker: number; type: string }[] = [];
		for (let i = 0; i < workers.length; i++) {
			const w = workers[i];
			w.addEventListener('message', (e: MessageEvent) => {
				if (e.data && e.data.type === 'wiped')
					observed.push({ worker: i, type: 'wiped' });
			});
		}

		// Intercept terminate to record its call order relative to the ACK.
		const termOrder: number[] = [];
		for (let i = 0; i < workers.length; i++) {
			const w = workers[i];
			const real = w.terminate.bind(w);
			w.terminate = (): void => {
				termOrder.push(i);
				real();
			};
		}

		pool.destroy();

		// State transitions are synchronous from the caller's perspective.
		expect(pool.dead).toBe(true);
		expect(p._keys).toBeNull();
		expect(p._masterKey).toBeNull();

		// Give the event loop enough turns to deliver the 'wiped' message
		// (one microtask + a macrotask). 50 ms << the 100 ms ACK window,
		// so if the ACK path is working the observed list fills before the
		// fallback timer would fire.
		await new Promise(r => setTimeout(r, 50));

		// Every worker should have replied with {type:'wiped'}.
		expect(observed.filter(o => o.type === 'wiped').length).toBe(2);
		// And every worker should have been terminated.
		expect(termOrder.sort()).toEqual([0, 1]);
	});

	it('worker that ignores the wipe message is still terminated after the ACK timeout', async () => {
		const key = randomBytes(32);
		const pool = await SealStreamPool.create(XChaCha20Cipher, key, {
			wasm: chacha20Wasm, workers: 1, chunkSize: 1024,
		});

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const p = pool as any;
		const worker: Worker = p._workers[0];

		// Swap the worker for a stub that swallows the wipe message. The
		// pool still thinks it's a real Worker — all we replace are the
		// methods `_wipeThenTerminate` touches.
		worker.terminate(); // stop the real worker first

		let terminateCalled = false;
		let wipeReceived = false;
		const listeners: ((e: MessageEvent) => void)[] = [];
		const stub = {
			addEventListener: (_type: string, fn: (e: MessageEvent) => void): void => {
				listeners.push(fn);
			},
			removeEventListener: (_type: string, fn: (e: MessageEvent) => void): void => {
				const i = listeners.indexOf(fn);
				if (i >= 0) listeners.splice(i, 1);
			},
			postMessage: (msg: { type: string }): void => {
				if (msg.type === 'wipe') wipeReceived = true;
				// Deliberately never reply — force the timeout path.
			},
			terminate: (): void => {
				terminateCalled = true;
			},
		};
		p._workers = [stub];

		// Watch for unhandled rejections during the timeout window.
		const unhandled: unknown[] = [];
		const onUnhandled = (e: PromiseRejectionEvent): void => {
			unhandled.push(e.reason);
		};
		if (typeof addEventListener === 'function')
			addEventListener('unhandledrejection', onUnhandled);

		pool.destroy();

		// Synchronous transitions complete before destroy() returns.
		expect(pool.dead).toBe(true);
		expect(p._keys).toBeNull();
		expect(p._masterKey).toBeNull();
		expect(wipeReceived).toBe(true);
		// Before the 100 ms fallback fires, terminate has NOT been called.
		expect(terminateCalled).toBe(false);

		// Wait past the ACK window (100 ms) plus a small safety margin.
		await new Promise(r => setTimeout(r, 160));

		// Fallback fired, worker is terminated, no unhandled rejections.
		expect(terminateCalled).toBe(true);
		expect(unhandled).toEqual([]);

		if (typeof removeEventListener === 'function')
			removeEventListener('unhandledrejection', onUnhandled);
	});
});
