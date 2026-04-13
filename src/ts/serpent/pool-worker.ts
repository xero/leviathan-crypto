// / <reference lib="webworker" />
// src/ts/serpent/pool-worker.ts
//
// Worker for SealStreamPool with SerpentCipher.
// Holds 3 derived keys (enc/mac/iv) and raw WASM instances.
// Direct WASM calls — no initModule (avoids same-thread module cache conflicts
// in @vitest/web-worker test environment).
//
// All HMAC / CBC / PKCS7 primitives come from `./shared-ops.js` — the same
// module the main-thread `SerpentCipher` uses. Byte-identical output with
// the main thread is the regression guard (see
// test/unit/stream/pool-byte-exact.test.ts). Must NOT import from `../init.js`:
// workers have their own isolated WASM instances, no shared-state registry.

import { constantTimeEqual, wipe, concat } from '../utils.js';
import { AuthenticationError } from '../errors.js';
import {
	hmacSha256,
	cbcEncryptChunk,
	cbcDecryptChunk,
	type Sha2OpsExports,
	type SerpentOpsExports,
} from './shared-ops.js';

// Worker-local augmentation: the pool worker also calls `wipeBuffers()` on
// teardown. Shared-ops doesn't need that method so it's not on the shared
// type — add it here.
type Sha2W     = Sha2OpsExports     & { wipeBuffers(): void };
type SerpentW  = SerpentOpsExports  & { wipeBuffers(): void };

let sha2: Sha2W | undefined;
let serpent: SerpentW | undefined;
let keys: Uint8Array | undefined;

self.onmessage = async (e: MessageEvent) => {
	const msg = e.data;

	if (msg.type === 'init') {
		try {
			const sha2Mem = new WebAssembly.Memory({ initial: 3, maximum: 3 });
			const sha2Inst = await WebAssembly.instantiate(
				msg.modules.sha2 as WebAssembly.Module,
				{ env: { memory: sha2Mem } },
			);
			sha2 = sha2Inst.exports as unknown as Sha2W;

			const serpentMem = new WebAssembly.Memory({ initial: 3, maximum: 3 });
			const serpentInst = await WebAssembly.instantiate(
				msg.modules.serpent as WebAssembly.Module,
				{ env: { memory: serpentMem } },
			);
			serpent = serpentInst.exports as unknown as SerpentW;

			keys = new Uint8Array(msg.derivedKeyBytes);
			if (keys.length !== 96)
				throw new Error(`expected 96 derived key bytes (got ${keys.length})`);
			msg.derivedKeyBytes.fill(0);
			self.postMessage({ type: 'ready' });
		} catch (err) {
			self.postMessage({ type: 'error', id: -1, message: (err as Error).message, isAuthError: false });
		}
		return;
	}

	if (msg.type === 'wipe') {
		if (keys) keys.fill(0);
		keys = undefined;
		if (sha2) sha2.wipeBuffers();
		if (serpent) serpent.wipeBuffers();
		sha2 = undefined;
		serpent = undefined;
		self.postMessage({ type: 'wiped' });
		return;
	}

	if (!keys || !sha2 || !serpent) {
		self.postMessage({ type: 'error', id: msg.id, message: 'worker not initialized', isAuthError: false });
		return;
	}

	try {
		const { id, op, counterNonce, data, aad } = msg;
		const aadBytes = aad ?? new Uint8Array(0);
		const jobKey = msg.derivedKeyBytes ?? keys;
		const encKey = jobKey.subarray(0, 32);
		const macKey = jobKey.subarray(32, 64);
		const ivKey  = jobKey.subarray(64, 96);

		let result: Uint8Array;
		if (op === 'seal') {
			const ivFull = hmacSha256(sha2, ivKey, counterNonce);
			const iv = ivFull.slice(0, 16);
			wipe(ivFull);
			const ct = cbcEncryptChunk(serpent, encKey, iv, data);
			const aadLenBuf = new Uint8Array(4);
			new DataView(aadLenBuf.buffer).setUint32(0, aadBytes.length, false);
			const tagInput = concat(counterNonce, aadLenBuf, aadBytes, ct);
			const tag = hmacSha256(sha2, macKey, tagInput);
			result = concat(ct, tag);
			wipe(iv); wipe(tagInput);
		} else {
			const ct = data.subarray(0, data.length - 32);
			const receivedTag = data.subarray(data.length - 32);
			const ivFull = hmacSha256(sha2, ivKey, counterNonce);
			const iv = ivFull.slice(0, 16);
			wipe(ivFull);
			const aadLenBuf = new Uint8Array(4);
			new DataView(aadLenBuf.buffer).setUint32(0, aadBytes.length, false);
			const tagInput = concat(counterNonce, aadLenBuf, aadBytes, ct);
			const expectedTag = hmacSha256(sha2, macKey, tagInput);
			// CRITICAL: verify HMAC before decrypting (Vaudenay 2002)
			if (!constantTimeEqual(expectedTag, receivedTag)) {
				wipe(iv); wipe(tagInput); wipe(expectedTag);
				throw new AuthenticationError('serpent');
			}
			wipe(tagInput); wipe(expectedTag);
			result = cbcDecryptChunk(serpent, encKey, iv, ct);
			wipe(iv);
		}
		const transfer = result.buffer instanceof ArrayBuffer ? [result.buffer] : [];
		self.postMessage({ type: 'result', id, data: result }, { transfer });
	} catch (err) {
		const isAuth = err instanceof AuthenticationError;
		self.postMessage({
			type: 'error', id: msg.id,
			message: (err as Error).message,
			cipher: isAuth ? 'serpent' : undefined,
			isAuthError: isAuth,
		});
	} finally {
		if (msg.derivedKeyBytes) msg.derivedKeyBytes.fill(0);
		if (sha2) sha2.wipeBuffers();
		if (serpent) serpent.wipeBuffers();
	}
};
