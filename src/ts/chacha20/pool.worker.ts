// / <reference lib="webworker" />
// src/ts/chacha20/pool.worker.ts
//
// Worker entry point for XChaCha20Poly1305Pool. Runs in a Web Worker or
// worker_threads context — no access to the main thread's module cache.
// Owns its own WebAssembly.Instance with its own linear memory.

import { xcEncrypt, xcDecrypt } from './ops.js';
import type { ChaChaExports } from './types.js';

let x: ChaChaExports | undefined;

self.onmessage = async (e: MessageEvent) => {
	const msg = e.data;

	if (msg.type === 'init') {
		try {
			const mem  = new WebAssembly.Memory({ initial: 3, maximum: 3 });
			const inst = await WebAssembly.instantiate(msg.module as WebAssembly.Module, { env: { memory: mem } });
			x = inst.exports as unknown as ChaChaExports;
			self.postMessage({ type: 'ready' });
		} catch (err) {
			self.postMessage({ type: 'error', id: -1, message: (err as Error).message });
		}
		return;
	}

	if (!x) {
		self.postMessage({ type: 'error', id: msg.id, message: 'worker not initialized' });
		return;
	}

	try {
		const { id, op, key, nonce, data, aad } = msg;
		const result = op === 'encrypt'
			? xcEncrypt(x, key, nonce, data, aad)
			: xcDecrypt(x, key, nonce, data, aad);
		self.postMessage({ type: 'result', id, data: result }, [result.buffer] as never);
	} catch (err) {
		self.postMessage({ type: 'error', id: msg.id, message: (err as Error).message });
	}
};
