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
// src/ts/serpent/stream-pool.ts
//
// SerpentStreamPool — parallel worker pool for SerpentStream.
// Dispatches chunk-level seal/open jobs across Web Workers, each
// with its own serpent.wasm and sha2.wasm instances.

import { isInitialized } from '../init.js';
import { HKDF_SHA256 } from '../sha2/index.js';
import { decodeWasm } from '../loader.js';
import { u32be, u64be, deriveChunkKeys } from './stream.js';

// ── Types ────────────────────────────────────────────────────────────────────

export interface StreamPoolOpts {
	/** Number of workers. Default: navigator.hardwareConcurrency ?? 4 */
	workers?: number;
}

interface PendingJob {
	resolve: (data: Uint8Array) => void;
	reject:  (err: Error) => void;
}

interface QueuedJob {
	id:     number;
	op:     'seal' | 'open';
	encKey: Uint8Array;
	macKey: Uint8Array;
	data:   Uint8Array;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const CHUNK_MIN = 1024;
const CHUNK_MAX = 65536;
const CHUNK_DEF = 65536;

// ── WASM module singletons ──────────────────────────────────────────────────

let _serpentModule: WebAssembly.Module | undefined;
let _sha2Module:    WebAssembly.Module | undefined;

async function getSerpentModule(): Promise<WebAssembly.Module> {
	if (_serpentModule) return _serpentModule;
	const { WASM_GZ_BASE64 } = await import('../embedded/serpent.js');
	const bytes = await decodeWasm(WASM_GZ_BASE64);
	_serpentModule = await WebAssembly.compile(bytes.buffer as ArrayBuffer);
	return _serpentModule;
}

async function getSha2Module(): Promise<WebAssembly.Module> {
	if (_sha2Module) return _sha2Module;
	const { WASM_GZ_BASE64 } = await import('../embedded/sha2.js');
	const bytes = await decodeWasm(WASM_GZ_BASE64);
	_sha2Module = await WebAssembly.compile(bytes.buffer as ArrayBuffer);
	return _sha2Module;
}

// ── Worker spawning ──────────────────────────────────────────────────────────

function spawnWorker(
	serpentMod: WebAssembly.Module,
	sha2Mod:   WebAssembly.Module,
): Promise<Worker> {
	return new Promise((resolve, reject) => {
		const worker = new Worker(
			new URL('./stream.worker.js', import.meta.url),
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
		worker.postMessage({ type: 'init', serpentModule: serpentMod, sha2Module: sha2Mod });
	});
}

// ── Pool class ───────────────────────────────────────────────────────────────

/**
 * Parallel worker pool for SerpentStream chunked authenticated encryption.
 *
 * Each worker owns its own `serpent.wasm` and `sha2.wasm` instances with
 * isolated linear memory. Key derivation happens on the main thread; workers
 * receive pre-derived encKey/macKey per chunk.
 *
 * Produces the same wire format as `SerpentStream` -- either can decrypt
 * the other's output.
 */
export class SerpentStreamPool {
	private readonly _workers: Worker[];
	private readonly _idle: Worker[];
	private readonly _queue: QueuedJob[];
	private readonly _pending: Map<number, PendingJob>;
	private readonly _hkdf: HKDF_SHA256;
	private _nextId: number;
	private _disposed: boolean;

	private constructor(workers: Worker[], hkdf: HKDF_SHA256) {
		this._workers  = workers;
		this._idle     = [...workers];
		this._queue    = [];
		this._pending  = new Map();
		this._hkdf     = hkdf;
		this._nextId   = 0;
		this._disposed = false;

		for (const w of workers) {
			w.onmessage = (e: MessageEvent) => this._onMessage(w, e);
		}
	}

	/**
	 * Create a new pool. Requires `init(['serpent', 'sha2'])` to have been called.
	 * Compiles both WASM modules once and distributes them to all workers.
	 */
	static async create(opts?: StreamPoolOpts): Promise<SerpentStreamPool> {
		if (!isInitialized('serpent') || !isInitialized('sha2'))
			throw new Error('leviathan-crypto: call init([\'serpent\', \'sha2\']) before using SerpentStreamPool');

		const n = opts?.workers ?? (typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : undefined) ?? 4;
		const [serpentMod, sha2Mod] = await Promise.all([getSerpentModule(), getSha2Module()]);

		// Sequential spawn — compatible with inline-worker test environments
		const workers: Worker[] = [];
		for (let i = 0; i < n; i++) workers.push(await spawnWorker(serpentMod, sha2Mod));

		const hkdf = new HKDF_SHA256();
		return new SerpentStreamPool(workers, hkdf);
	}

	/**
	 * Encrypt plaintext with SerpentStream chunked authenticated encryption.
	 * Returns the complete wire format (header + encrypted chunks).
	 */
	async seal(key: Uint8Array, plaintext: Uint8Array, chunkSize?: number): Promise<Uint8Array> {
		if (this._disposed) throw new Error('leviathan-crypto: pool is disposed');
		if (key.length !== 32)
			throw new RangeError(`SerpentStream key must be 32 bytes (got ${key.length})`);
		const cs = chunkSize ?? CHUNK_DEF;
		if (cs < CHUNK_MIN || cs > CHUNK_MAX)
			throw new RangeError(`SerpentStream chunkSize must be ${CHUNK_MIN}..${CHUNK_MAX} (got ${cs})`);

		const streamNonce = new Uint8Array(16);
		crypto.getRandomValues(streamNonce);

		const chunkCount = plaintext.length === 0 ? 1 : Math.ceil(plaintext.length / cs);

		// Dispatch all chunk jobs in parallel
		const chunkPromises: Promise<Uint8Array>[] = [];
		for (let i = 0; i < chunkCount; i++) {
			const start = i * cs;
			const end = Math.min(start + cs, plaintext.length);
			const slice = plaintext.slice(start, end);
			const isLast = i === chunkCount - 1;
			const { encKey, macKey } = deriveChunkKeys(
				this._hkdf, key, streamNonce, cs, chunkCount, i, isLast,
			);
			chunkPromises.push(this._dispatch('seal', encKey, macKey, slice));
		}

		const chunkResults = await Promise.all(chunkPromises);

		// Compute total output size
		let totalWire = 28;
		for (const c of chunkResults) totalWire += c.length;

		const out = new Uint8Array(totalWire);
		// Write header
		out.set(streamNonce, 0);
		out.set(u32be(cs), 16);
		out.set(u64be(chunkCount), 20);

		let pos = 28;
		for (const c of chunkResults) {
			out.set(c, pos);
			pos += c.length;
		}

		return out;
	}

	/**
	 * Decrypt SerpentStream wire format.
	 * If any chunk fails authentication, rejects immediately -- no partial plaintext.
	 */
	async open(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
		if (this._disposed) throw new Error('leviathan-crypto: pool is disposed');
		if (key.length !== 32)
			throw new RangeError(`SerpentStream key must be 32 bytes (got ${key.length})`);
		if (ciphertext.length < 28 + 32)
			throw new RangeError('SerpentStream: ciphertext too short');

		// Parse header
		const streamNonce = ciphertext.subarray(0, 16);
		const csView = ciphertext.subarray(16, 20);
		const cs = (csView[0] << 24) | (csView[1] << 16) | (csView[2] << 8) | csView[3];
		const ccView = ciphertext.subarray(20, 28);
		let chunkCount = 0;
		for (let i = 0; i < 8; i++) chunkCount = chunkCount * 256 + ccView[i];

		// Dispatch all chunk jobs
		const chunkPromises: Promise<Uint8Array>[] = [];
		let pos = 28;
		for (let i = 0; i < chunkCount; i++) {
			const isLast = i === chunkCount - 1;
			const wireLen = isLast ? ciphertext.length - pos : cs + 32;
			const wireSlice = ciphertext.slice(pos, pos + wireLen);
			const { encKey, macKey } = deriveChunkKeys(
				this._hkdf, key, streamNonce, cs, chunkCount, i, isLast,
			);
			chunkPromises.push(this._dispatch('open', encKey, macKey, wireSlice));
			pos += wireLen;
		}

		// Await all — Promise.all rejects on first failure
		const results = await Promise.all(chunkPromises);

		// Reassemble plaintext
		let totalPt = 0;
		for (const r of results) totalPt += r.length;
		const plaintext = new Uint8Array(totalPt);
		let ptPos = 0;
		for (const r of results) {
			plaintext.set(r, ptPos);
			ptPos += r.length;
		}
		return plaintext;
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
		this._hkdf.dispose();
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
		op:     'seal' | 'open',
		encKey: Uint8Array,
		macKey: Uint8Array,
		data:   Uint8Array,
	): Promise<Uint8Array> {
		return new Promise((resolve, reject) => {
			const id  = this._nextId++;
			const job: QueuedJob = { id, op, encKey, macKey, data };
			this._pending.set(id, { resolve, reject });

			const worker = this._idle.pop();
			if (worker) this._send(worker, job);
			else        this._queue.push(job);
		});
	}

	private _send(worker: Worker, job: QueuedJob): void {
		// No transfer list: @vitest/web-worker (same-thread fake worker used in
		// Vitest test environment) silently drops postMessage calls that include a
		// non-empty Transferable array. encKey/macKey/data are already .slice()
		// copies — neutering was never part of SerpentStreamPool's public contract.
		worker.postMessage({ type: 'job', ...job });
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
