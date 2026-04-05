// / <reference lib="webworker" />
// src/ts/serpent/pool-worker.ts
//
// Worker for SealStreamPool with SerpentCipher.
// Holds 3 derived keys (enc/mac/iv) and raw WASM instances.
// Direct WASM calls — no initModule (avoids same-thread module cache conflicts
// in @vitest/web-worker test environment).

import { constantTimeEqual, wipe, concat } from '../utils.js';
import { AuthenticationError } from '../errors.js';

// Inline Sha2Exports and SerpentExports type subsets needed by the worker
interface Sha2W {
	memory: WebAssembly.Memory;
	getSha256InputOffset(): number;
	getSha256OutOffset(): number;
	hmac256Init(keyLen: number): void;
	hmac256Update(len: number): void;
	hmac256Final(): void;
	sha256Init(): void;
	sha256Update(len: number): void;
	sha256Final(): void;
	wipeBuffers(): void;
}

interface SerpentW {
	memory: WebAssembly.Memory;
	getKeyOffset(): number;
	getChunkPtOffset(): number;
	getChunkCtOffset(): number;
	getCbcIvOffset(): number;
	loadKey(n: number): number;
	cbcEncryptChunk(n: number): number;
	cbcDecryptChunk(n: number): number;
	wipeBuffers(): void;
}

let sha2: Sha2W | undefined;
let serpent: SerpentW | undefined;
let keys: Uint8Array | undefined;

function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
	const x = sha2 as Sha2W;
	let k = key;
	if (k.length > 64) {
		x.sha256Init();
		feedSha2(k);
		x.sha256Final();
		const mem = new Uint8Array(x.memory.buffer);
		k = mem.slice(x.getSha256OutOffset(), x.getSha256OutOffset() + 32);
	}
	const mem = new Uint8Array(x.memory.buffer);
	mem.set(k, x.getSha256InputOffset());
	x.hmac256Init(k.length);
	feedHmac(msg);
	x.hmac256Final();
	return new Uint8Array(x.memory.buffer).slice(x.getSha256OutOffset(), x.getSha256OutOffset() + 32);
}

function feedSha2(data: Uint8Array): void {
	const x = sha2 as Sha2W;
	const mem = new Uint8Array(x.memory.buffer);
	const off = x.getSha256InputOffset();
	let pos = 0;
	while (pos < data.length) {
		const n = Math.min(data.length - pos, 64);
		mem.set(data.subarray(pos, pos + n), off);
		x.sha256Update(n);
		pos += n;
	}
}

function feedHmac(data: Uint8Array): void {
	const x = sha2 as Sha2W;
	const mem = new Uint8Array(x.memory.buffer);
	const off = x.getSha256InputOffset();
	let pos = 0;
	while (pos < data.length) {
		const n = Math.min(data.length - pos, 64);
		mem.set(data.subarray(pos, pos + n), off);
		x.hmac256Update(n);
		pos += n;
	}
}

function pkcs7Pad(data: Uint8Array): Uint8Array {
	const padLen = 16 - (data.length % 16);
	const out = new Uint8Array(data.length + padLen);
	out.set(data);
	out.fill(padLen, data.length);
	return out;
}

// pkcs7Strip is only called after HMAC authentication succeeds (verify-then-decrypt).
// The early throw on invalid padLen is not a padding oracle in this context —
// the HMAC check is the oracle gate and runs in constant time before this point.
// If you move this call to a pre-auth site, revisit the timing properties.
function pkcs7Strip(data: Uint8Array): Uint8Array {
	if (data.length === 0) throw new RangeError('empty ciphertext');
	const padLen = data[data.length - 1];
	if (padLen === 0 || padLen > 16) throw new RangeError('invalid PKCS7 padding');
	if (padLen > data.length) throw new RangeError('invalid PKCS7 padding');
	let bad = 0;
	for (let i = data.length - padLen; i < data.length; i++) bad |= data[i] ^ padLen;
	if (bad !== 0) throw new RangeError('invalid PKCS7 padding');
	return data.subarray(0, data.length - padLen);
}

function cbcEncrypt(encKey: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
	const s = serpent as SerpentW;
	const mem = new Uint8Array(s.memory.buffer);
	mem.set(encKey, s.getKeyOffset());
	s.loadKey(encKey.length);
	mem.set(iv, s.getCbcIvOffset());
	const padded = pkcs7Pad(plaintext);
	mem.set(padded, s.getChunkPtOffset());
	s.cbcEncryptChunk(padded.length);
	return new Uint8Array(s.memory.buffer).slice(s.getChunkCtOffset(), s.getChunkCtOffset() + padded.length);
}

function cbcDecrypt(encKey: Uint8Array, iv: Uint8Array, ct: Uint8Array): Uint8Array {
	const s = serpent as SerpentW;
	const mem = new Uint8Array(s.memory.buffer);
	mem.set(encKey, s.getKeyOffset());
	s.loadKey(encKey.length);
	mem.set(iv, s.getCbcIvOffset());
	mem.set(ct, s.getChunkCtOffset());
	s.cbcDecryptChunk(ct.length);
	const raw = new Uint8Array(s.memory.buffer).slice(s.getChunkPtOffset(), s.getChunkPtOffset() + ct.length);
	return pkcs7Strip(raw);
}

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
			const ivFull = hmacSha256(ivKey, counterNonce);
			const iv = ivFull.slice(0, 16);
			wipe(ivFull);
			const ct = cbcEncrypt(encKey, iv, data);
			const aadLenBuf = new Uint8Array(4);
			new DataView(aadLenBuf.buffer).setUint32(0, aadBytes.length, false);
			const tagInput = concat(counterNonce, aadLenBuf, aadBytes, ct);
			const tag = hmacSha256(macKey, tagInput);
			result = concat(ct, tag);
			wipe(iv); wipe(tagInput);
		} else {
			const ct = data.subarray(0, data.length - 32);
			const receivedTag = data.subarray(data.length - 32);
			const ivFull = hmacSha256(ivKey, counterNonce);
			const iv = ivFull.slice(0, 16);
			wipe(ivFull);
			const aadLenBuf = new Uint8Array(4);
			new DataView(aadLenBuf.buffer).setUint32(0, aadBytes.length, false);
			const tagInput = concat(counterNonce, aadLenBuf, aadBytes, ct);
			const expectedTag = hmacSha256(macKey, tagInput);
			// CRITICAL: verify HMAC before decrypting (Vaudenay 2002)
			if (!constantTimeEqual(expectedTag, receivedTag)) {
				wipe(iv); wipe(tagInput); wipe(expectedTag);
				throw new AuthenticationError('serpent');
			}
			wipe(tagInput); wipe(expectedTag);
			result = cbcDecrypt(encKey, iv, ct);
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
