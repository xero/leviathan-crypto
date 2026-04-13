// / <reference lib="webworker" />
// src/ts/chacha20/pool-worker.ts
//
// Worker for SealStreamPool with XChaCha20Cipher.
// Holds derived subkey and ChaCha20 WASM instance for the pool's lifetime.
// Per-job: ChaCha20-Poly1305 AEAD with 12-byte counter nonce.

import { aeadEncrypt, aeadDecrypt } from './ops.js';
import type { ChaChaExports } from './types.js';
import { AuthenticationError } from '../errors.js';

let x: ChaChaExports | undefined;
let subkey: Uint8Array | undefined;

/**
 * Message handler for the XChaCha20 pool worker.
 *
 * Accepts three message types:
 * - `'init'`  — instantiate the chacha20 WASM module and store the derived subkey
 * - `'wipe'`  — zero subkey and WASM buffers, then post `{ type: 'wiped' }`
 * - `{ op: 'seal' | 'open', ... }` — encrypt or decrypt one chunk
 *
 * Replies with `{ type: 'result', id, data }` on success or
 * `{ type: 'error', id, message, isAuthError }` on failure.
 */
self.onmessage = async (e: MessageEvent) => {
	const msg = e.data;

	if (msg.type === 'init') {
		try {
			const mem = new WebAssembly.Memory({ initial: 3, maximum: 3 });
			const mod = msg.modules.chacha20 as WebAssembly.Module;
			const inst = await WebAssembly.instantiate(mod, { env: { memory: mem } });
			x = inst.exports as unknown as ChaChaExports;
			subkey = new Uint8Array(msg.derivedKeyBytes);
			if (subkey.length !== 32)
				throw new Error(`expected 32 derived key bytes (got ${subkey.length})`);
			msg.derivedKeyBytes.fill(0);
			self.postMessage({ type: 'ready' });
		} catch (err) {
			self.postMessage({ type: 'error', id: -1, message: (err as Error).message, isAuthError: false });
		}
		return;
	}

	if (msg.type === 'wipe') {
		if (subkey) subkey.fill(0);
		subkey = undefined;
		if (x) x.wipeBuffers();
		x = undefined;
		self.postMessage({ type: 'wiped' });
		return;
	}

	if (!x || !subkey) {
		self.postMessage({ type: 'error', id: msg.id, message: 'worker not initialized', isAuthError: false });
		return;
	}

	try {
		const { id, op, counterNonce, data, aad } = msg;
		const aadBytes = aad ?? new Uint8Array(0);
		const jobKey = msg.derivedKeyBytes ?? subkey;
		let result: Uint8Array;
		if (op === 'seal') {
			const { ciphertext, tag } = aeadEncrypt(x, jobKey, counterNonce, data, aadBytes);
			result = new Uint8Array(ciphertext.length + 16);
			result.set(ciphertext);
			result.set(tag, ciphertext.length);
		} else {
			const ct = data.subarray(0, data.length - 16);
			const tag = data.subarray(data.length - 16);
			result = aeadDecrypt(x, jobKey, counterNonce, ct, tag, aadBytes, 'xchacha20-poly1305');
		}
		const transfer = result.buffer instanceof ArrayBuffer ? [result.buffer] : [];
		self.postMessage({ type: 'result', id, data: result }, { transfer });
	} catch (err) {
		const isAuth = err instanceof AuthenticationError;
		self.postMessage({
			type: 'error', id: msg.id,
			message: (err as Error).message,
			cipher: isAuth ? 'xchacha20-poly1305' : undefined,
			isAuthError: isAuth,
		});
	} finally {
		if (msg.derivedKeyBytes) msg.derivedKeyBytes.fill(0);
		if (x) x.wipeBuffers();
	}
};
