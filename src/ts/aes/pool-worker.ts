// / <reference lib="webworker" />
// src/ts/aes/pool-worker.ts
//
// Worker for SealStreamPool with AESGCMSIVCipher.
// Holds derived AES-256-GCM-SIV key and the AES WASM instance for the
// pool's lifetime. Per-job: AES-GCM-SIV AEAD with 12-byte counter nonce.

import { sivAeadEncrypt, sivAeadDecrypt } from './ops.js';
import type { AesExports } from './types.js';
import { AuthenticationError } from '../errors.js';

let x: AesExports | undefined;
let derivedKey: Uint8Array | undefined;

/**
 * Message handler for the AES pool worker.
 *
 * Accepts three message types:
 * - `'init'`  — instantiate the aes WASM module and store the derived AES key
 * - `'wipe'`  — zero key and WASM buffers, then post `{ type: 'wiped' }`
 * - `{ op: 'seal' | 'open', ... }` — encrypt or decrypt one chunk
 *
 * Replies with `{ type: 'result', id, data }` on success or
 * `{ type: 'error', id, message, isAuthError }` on failure.
 */
self.onmessage = async (e: MessageEvent) => {
	const msg = e.data;

	if (msg.type === 'init') {
		try {
			// AES module is 4 pages = 256 KiB; matches src/asm/aes/buffers.ts.
			const mem = new WebAssembly.Memory({ initial: 4, maximum: 4 });
			const mod = msg.modules.aes as WebAssembly.Module;
			const inst = await WebAssembly.instantiate(mod, { env: { memory: mem } });
			x = inst.exports as unknown as AesExports;
			derivedKey = new Uint8Array(msg.derivedKeyBytes);
			if (derivedKey.length !== 32)
				throw new Error(`expected 32 derived key bytes (got ${derivedKey.length})`);
			msg.derivedKeyBytes.fill(0);
			self.postMessage({ type: 'ready' });
		} catch (err) {
			self.postMessage({ type: 'error', id: -1, message: (err as Error).message, isAuthError: false });
		}
		return;
	}

	if (msg.type === 'wipe') {
		if (derivedKey) derivedKey.fill(0);
		derivedKey = undefined;
		if (x) x.wipeBuffers();
		x = undefined;
		self.postMessage({ type: 'wiped' });
		return;
	}

	if (!x || !derivedKey) {
		self.postMessage({ type: 'error', id: msg.id, message: 'worker not initialized', isAuthError: false });
		return;
	}

	try {
		const { id, op, counterNonce, data, aad } = msg;
		const aadBytes = aad ?? new Uint8Array(0);
		const jobKey = msg.derivedKeyBytes ?? derivedKey;
		let result: Uint8Array;
		if (op === 'seal') {
			const { ciphertext, tag } = sivAeadEncrypt(x, jobKey, counterNonce, data, aadBytes);
			result = new Uint8Array(ciphertext.length + 16);
			result.set(ciphertext);
			result.set(tag, ciphertext.length);
		} else {
			const ct  = data.subarray(0, data.length - 16);
			const tag = data.subarray(data.length - 16);
			result = sivAeadDecrypt(x, jobKey, counterNonce, ct, tag, aadBytes, 'aes-gcm-siv');
		}
		const transfer = result.buffer instanceof ArrayBuffer ? [result.buffer] : [];
		self.postMessage({ type: 'result', id, data: result }, { transfer });
	} catch (err) {
		const isAuth = err instanceof AuthenticationError;
		self.postMessage({
			type: 'error', id: msg.id,
			message: (err as Error).message,
			cipher: isAuth ? 'aes-gcm-siv' : undefined,
			isAuthError: isAuth,
		});
	} finally {
		if (msg.derivedKeyBytes) msg.derivedKeyBytes.fill(0);
		if (x) x.wipeBuffers();
	}
};
