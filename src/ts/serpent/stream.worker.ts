// / <reference lib="webworker" />
// src/ts/serpent/stream.worker.ts
//
// Worker entry point for SerpentStreamPool. Runs in a Web Worker —
// no access to the main thread's module cache. Owns its own
// serpent.wasm and sha2.wasm instances with isolated linear memory.
// Implements sealChunk/openChunk inline using raw WASM exports.

// ── WASM export types (mirrored from index.ts / sha2/index.ts) ───────────────

interface SerpentExports {
	memory:           WebAssembly.Memory;
	getKeyOffset:     () => number;
	getNonceOffset:   () => number;
	getChunkPtOffset: () => number;
	getChunkCtOffset: () => number;
	getChunkSize:     () => number;
	loadKey:          (n: number) => number;
	resetCounter:     () => void;
	encryptChunk:     (n: number) => number;
	wipeBuffers:      () => void;
}

interface Sha2Exports {
	memory:                WebAssembly.Memory;
	getSha256InputOffset:  () => number;
	getSha256OutOffset:    () => number;
	sha256Init:            () => void;
	sha256Update:          (len: number) => void;
	sha256Final:           () => void;
	hmac256Init:           (keyLen: number) => void;
	hmac256Update:         (len: number) => void;
	hmac256Final:          () => void;
	wipeBuffers:           () => void;
}

let sx: SerpentExports | undefined;
let hx: Sha2Exports | undefined;

const ZERO_IV = new Uint8Array(16);

// ── Inline chunk ops ──────────────────────────────────────────────────────────

function hmacSha256(hx: Sha2Exports, key: Uint8Array, msg: Uint8Array): Uint8Array {
	// RFC 2104 §3: keys longer than block size (64 bytes) are pre-hashed.
	// mac_key is always 32 bytes in normal usage (half of HKDF 64-byte output),
	// but this guard must match the main-thread HMAC_SHA256.hash() behaviour
	// exactly — any divergence would cause authentication failures if key sizes
	// ever change.
	let k = key;
	if (k.length > 64) {
		hx.sha256Init();
		let pos = 0;
		while (pos < k.length) {
			const n = Math.min(k.length - pos, 64);
			new Uint8Array(hx.memory.buffer).set(k.subarray(pos, pos + n), hx.getSha256InputOffset());
			hx.sha256Update(n);
			pos += n;
		}
		hx.sha256Final();
		const out = new Uint8Array(hx.memory.buffer);
		k = out.slice(hx.getSha256OutOffset(), hx.getSha256OutOffset() + 32);
	}

	const mem = new Uint8Array(hx.memory.buffer);
	const inputOff = hx.getSha256InputOffset();
	mem.set(k, inputOff);
	hx.hmac256Init(k.length);
	let pos = 0;
	while (pos < msg.length) {
		const n = Math.min(msg.length - pos, 64);
		new Uint8Array(hx.memory.buffer).set(msg.subarray(pos, pos + n), inputOff);
		hx.hmac256Update(n);
		pos += n;
	}
	hx.hmac256Final();
	const out = new Uint8Array(hx.memory.buffer);
	return out.slice(hx.getSha256OutOffset(), hx.getSha256OutOffset() + 32);
}

function ctrEncrypt(sx: SerpentExports, key: Uint8Array, chunk: Uint8Array): Uint8Array {
	const mem = new Uint8Array(sx.memory.buffer);
	mem.set(key, sx.getKeyOffset());
	mem.set(ZERO_IV, sx.getNonceOffset());
	sx.loadKey(key.length);
	sx.resetCounter();
	new Uint8Array(sx.memory.buffer).set(chunk, sx.getChunkPtOffset());
	sx.encryptChunk(chunk.length);
	const out = new Uint8Array(sx.memory.buffer);
	return out.slice(sx.getChunkCtOffset(), sx.getChunkCtOffset() + chunk.length);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}

function workerSealChunk(encKey: Uint8Array, macKey: Uint8Array, chunk: Uint8Array): Uint8Array {
	const ciphertext = ctrEncrypt(sx as SerpentExports, encKey, chunk);
	const tag = hmacSha256(hx as Sha2Exports, macKey, ciphertext);
	const out = new Uint8Array(ciphertext.length + 32);
	out.set(ciphertext, 0);
	out.set(tag, ciphertext.length);
	return out;
}

function workerOpenChunk(encKey: Uint8Array, macKey: Uint8Array, wire: Uint8Array): Uint8Array {
	if (wire.length < 32)
		throw new RangeError('SerpentStream: chunk wire data too short');
	const ciphertext = wire.subarray(0, wire.length - 32);
	const tag = wire.subarray(wire.length - 32);
	const expectedTag = hmacSha256(hx as Sha2Exports, macKey, ciphertext);
	if (!constantTimeEqual(tag, expectedTag))
		throw new Error('SerpentStream: authentication failed');
	return ctrEncrypt(sx as SerpentExports, encKey, ciphertext);
}

// ── Message handler ───────────────────────────────────────────────────────────

self.onmessage = async (e: MessageEvent) => {
	const msg = e.data;

	if (msg.type === 'init') {
		try {
			const serpentMem = new WebAssembly.Memory({ initial: 3, maximum: 3 });
			const sha2Mem    = new WebAssembly.Memory({ initial: 3, maximum: 3 });
			const serpentInst = await WebAssembly.instantiate(
				msg.serpentModule as WebAssembly.Module,
				{ env: { memory: serpentMem } },
			);
			const sha2Inst = await WebAssembly.instantiate(
				msg.sha2Module as WebAssembly.Module,
				{ env: { memory: sha2Mem } },
			);
			sx = serpentInst.exports as unknown as SerpentExports;
			hx = sha2Inst.exports as unknown as Sha2Exports;
			self.postMessage({ type: 'ready' });
		} catch (err) {
			self.postMessage({ type: 'error', id: -1, message: (err as Error).message });
		}
		return;
	}

	if (!sx || !hx) {
		self.postMessage({ type: 'error', id: msg.id, message: 'worker not initialized' });
		return;
	}

	try {
		const { id, op, encKey, macKey, data } = msg;
		const result = op === 'seal'
			? workerSealChunk(encKey, macKey, data)
			: workerOpenChunk(encKey, macKey, data);
		self.postMessage({ type: 'result', id, data: result }, [result.buffer] as never);
	} catch (err) {
		self.postMessage({ type: 'error', id: msg.id, message: (err as Error).message });
	}
};
