// src/ts/chacha20/pool.ts
//
// XChaCha20Poly1305Pool — parallel worker pool for XChaCha20-Poly1305 AEAD.
// Dispatches independent encrypt/decrypt jobs across Web Workers, each with
// its own WebAssembly.Instance and isolated linear memory.

import { isInitialized } from '../init.js';

// ── Types ────────────────────────────────────────────────────────────────────

export interface PoolOpts {
	/** Number of workers. Default: navigator.hardwareConcurrency ?? 4 */
	workers?: number;
}

interface PendingJob {
	resolve: (data: Uint8Array) => void;
	reject:  (err: Error) => void;
}

interface QueuedJob {
	id:    number;
	op:    'encrypt' | 'decrypt';
	key:   Uint8Array;
	nonce: Uint8Array;
	data:  Uint8Array;
	aad:   Uint8Array;
}

// ── Module-private base64 decoder (copied from loader.ts) ────────────────────

function base64ToBytes(b64: string): Uint8Array {
	if (typeof atob === 'function') {
		const raw = atob(b64);
		const out = new Uint8Array(raw.length);
		for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
		return out;
	}
	return new Uint8Array(Buffer.from(b64, 'base64'));
}

// ── WASM module singleton ────────────────────────────────────────────────────

let _wasmModule: WebAssembly.Module | undefined;

async function getWasmModule(): Promise<WebAssembly.Module> {
	if (_wasmModule) return _wasmModule;
	const { WASM_BASE64 } = await import('../embedded/chacha.js');
	const bytes = base64ToBytes(WASM_BASE64);
	_wasmModule = await WebAssembly.compile(bytes.buffer as ArrayBuffer);
	return _wasmModule;
}

// ── Worker spawning ──────────────────────────────────────────────────────────

function spawnWorker(mod: WebAssembly.Module): Promise<Worker> {
	return new Promise((resolve, reject) => {
		const worker = new Worker(
			new URL('./pool.worker.js', import.meta.url),
			{ type: 'module' },
		);

		const onMessage = (e: MessageEvent) => {
			cleanup();
			if (e.data.type === 'ready') {
				resolve(worker);
			} else {
				worker.terminate();
				reject(new Error(`leviathan-crypto: worker init failed: ${e.data.message}`));
			}
		};

		const onError = (e: ErrorEvent) => {
			cleanup();
			worker.terminate();
			reject(new Error(`leviathan-crypto: worker init failed: ${e.message}`));
		};

		const cleanup = () => {
			worker.removeEventListener('message', onMessage);
			worker.removeEventListener('error', onError);
		};

		worker.addEventListener('message', onMessage);
		worker.addEventListener('error', onError);
		worker.postMessage({ type: 'init', module: mod });
	});
}

// ── Pool class ───────────────────────────────────────────────────────────────

/**
 * Parallel worker pool for XChaCha20-Poly1305 AEAD.
 *
 * Each worker owns its own `WebAssembly.Instance` with isolated linear memory.
 * Jobs are dispatched round-robin to idle workers; excess jobs queue until a
 * worker frees up.
 *
 * **Warning:** Input buffers (`key`, `nonce`, `plaintext`/`ciphertext`, `aad`)
 * are transferred to the worker and neutered on the calling side. The caller
 * must copy any buffer they need to retain after calling `encrypt()`/`decrypt()`.
 */
export class XChaCha20Poly1305Pool {
	private readonly _workers: Worker[];
	private readonly _idle: Worker[];
	private readonly _queue: QueuedJob[];
	private readonly _pending: Map<number, PendingJob>;
	private _nextId: number;
	private _disposed: boolean;

	private constructor(workers: Worker[]) {
		this._workers  = workers;
		this._idle     = [...workers];
		this._queue    = [];
		this._pending  = new Map();
		this._nextId   = 0;
		this._disposed = false;

		for (const w of workers) {
			w.onmessage = (e: MessageEvent) => this._onMessage(w, e);
		}
	}

	/**
	 * Create a new pool. Requires `init(['chacha20'])` to have been called.
	 * Compiles the WASM module once and distributes it to all workers.
	 */
	static async create(opts?: PoolOpts): Promise<XChaCha20Poly1305Pool> {
		if (!isInitialized('chacha20'))
			throw new Error('leviathan-crypto: call init([\'chacha20\']) before using XChaCha20Poly1305Pool');

		const n   = opts?.workers ?? (typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : undefined) ?? 4;
		const mod = await getWasmModule();

		// Sequential spawn — compatible with inline-worker test environments
		const workers: Worker[] = [];
		for (let i = 0; i < n; i++) workers.push(await spawnWorker(mod));

		return new XChaCha20Poly1305Pool(workers);
	}

	/**
	 * Encrypt plaintext with XChaCha20-Poly1305.
	 * Returns `ciphertext || tag` (plaintext.length + 16 bytes).
	 *
	 * **Warning:** All input buffers are transferred and neutered after dispatch.
	 */
	encrypt(
		key:       Uint8Array,
		nonce:     Uint8Array,
		plaintext: Uint8Array,
		aad:       Uint8Array = new Uint8Array(0),
	): Promise<Uint8Array> {
		if (this._disposed) return Promise.reject(new Error('leviathan-crypto: pool is disposed'));
		if (key.length !== 32)   return Promise.reject(new RangeError(`key must be 32 bytes (got ${key.length})`));
		if (nonce.length !== 24) return Promise.reject(new RangeError(`XChaCha20 nonce must be 24 bytes (got ${nonce.length})`));
		return this._dispatch('encrypt', key, nonce, plaintext, aad);
	}

	/**
	 * Decrypt ciphertext with XChaCha20-Poly1305.
	 * Input is `ciphertext || tag` (at least 16 bytes).
	 *
	 * **Warning:** All input buffers are transferred and neutered after dispatch.
	 */
	decrypt(
		key:        Uint8Array,
		nonce:      Uint8Array,
		ciphertext: Uint8Array,
		aad:        Uint8Array = new Uint8Array(0),
	): Promise<Uint8Array> {
		if (this._disposed) return Promise.reject(new Error('leviathan-crypto: pool is disposed'));
		if (key.length !== 32)    return Promise.reject(new RangeError(`key must be 32 bytes (got ${key.length})`));
		if (nonce.length !== 24)  return Promise.reject(new RangeError(`XChaCha20 nonce must be 24 bytes (got ${nonce.length})`));
		if (ciphertext.length < 16) return Promise.reject(new RangeError(`ciphertext too short — must include 16-byte tag (got ${ciphertext.length})`));
		return this._dispatch('decrypt', key, nonce, ciphertext, aad);
	}

	/** Terminates all workers. Rejects all pending and queued jobs. */
	dispose(): void {
		if (this._disposed) return;
		this._disposed = true;
		for (const w of this._workers) w.terminate();
		const err = new Error('leviathan-crypto: pool disposed');
		for (const { reject } of this._pending.values()) reject(err);
		for (const job of this._queue) this._pending.get(job.id)?.reject(err);
		this._pending.clear();
		this._queue.length = 0;
	}

	/** Number of workers in the pool. */
	get size(): number {
		return this._workers.length;
	}

	/** Number of jobs currently queued (waiting for a free worker). */
	get queueDepth(): number {
		return this._queue.length;
	}

	// ── Internals ────────────────────────────────────────────────────────────

	private _dispatch(
		op:    'encrypt' | 'decrypt',
		key:   Uint8Array,
		nonce: Uint8Array,
		data:  Uint8Array,
		aad:   Uint8Array,
	): Promise<Uint8Array> {
		return new Promise((resolve, reject) => {
			const id  = this._nextId++;
			const job: QueuedJob = { id, op, key, nonce, data, aad };
			this._pending.set(id, { resolve, reject });

			const worker = this._idle.pop();
			if (worker) this._send(worker, job);
			else        this._queue.push(job);
		});
	}

	private _send(worker: Worker, job: QueuedJob): void {
		worker.postMessage(
			{ type: 'job', ...job },
			[job.key.buffer, job.nonce.buffer, job.data.buffer, job.aad.buffer] as never,
		);
	}

	private _onMessage(worker: Worker, e: MessageEvent): void {
		const msg = e.data;
		const job = this._pending.get(msg.id);
		if (!job) return;
		this._pending.delete(msg.id);

		if (msg.type === 'result') job.resolve(msg.data);
		else                       job.reject(new Error(msg.message));

		const next = this._queue.shift();
		if (next) this._send(worker, next);
		else      this._idle.push(worker);
	}
}
