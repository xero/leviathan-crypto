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
// src/ts/chacha20/stream-pool.ts
//
// XChaCha20StreamPool — parallel worker pool for chunked XChaCha20-Poly1305
// streaming AEAD. Dispatches per-chunk encrypt/decrypt jobs across Web Workers,
// each with its own WebAssembly instance and isolated linear memory.
// Same chunk-level crypto as XChaCha20StreamSealer; different header (28 bytes
// with chunkCount for parallel open).

import { isInitialized } from '../init.js';
import { decodeWasm } from '../loader.js';
import { randomBytes } from '../utils.js';
import { u32be, u64be, chunkAAD } from './stream-sealer.js';

// ── Types ────────────────────────────────────────────────────────────────────

export interface XcStreamPoolOpts {
	/** Number of workers. Default: navigator.hardwareConcurrency ?? 4 */
	workers?: number;
}

export interface SealOpts {
	aad?: Uint8Array;
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

// ── Constants ────────────────────────────────────────────────────────────────

const CHUNK_MIN = 1024;
const CHUNK_MAX = 65536;
const CHUNK_DEF = 65536;
const HEADER    = 28;  // stream_id(16) + chunkSize(4) + chunkCount(8)

// ── WASM module singleton ────────────────────────────────────────────────────

let _wasmModule: WebAssembly.Module | undefined;

async function getWasmModule(): Promise<WebAssembly.Module> {
	if (_wasmModule) return _wasmModule;
	const { WASM_GZ_BASE64 } = await import('../embedded/chacha20.js');
	const bytes = await decodeWasm(WASM_GZ_BASE64);
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
 * Parallel worker pool for XChaCha20-Poly1305 chunked streaming AEAD.
 *
 * Same chunk-level crypto as `XChaCha20StreamSealer` (per-chunk random nonce,
 * position-bound AAD). Different wire format header — includes chunkCount for
 * parallel open (28 bytes vs sealer's 20).
 *
 * Wire format: stream_id(16) || chunkSize_u32be(4) || chunkCount_u64be(8) || chunks
 * Chunk:       isLast(1) || nonce(24) || ciphertext || tag(16)
 */
export class XChaCha20StreamPool {
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

	static async create(opts?: XcStreamPoolOpts): Promise<XChaCha20StreamPool> {
		if (!isInitialized('chacha20'))
			throw new Error('leviathan-crypto: call init([\'chacha20\']) before using XChaCha20StreamPool');

		const n   = opts?.workers ?? (typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : undefined) ?? 4;
		const mod = await getWasmModule();

		const workers: Worker[] = [];
		for (let i = 0; i < n; i++) workers.push(await spawnWorker(mod));

		return new XChaCha20StreamPool(workers);
	}

	async seal(key: Uint8Array, plaintext: Uint8Array, chunkSize?: number, opts?: SealOpts): Promise<Uint8Array> {
		if (this._disposed) throw new Error('leviathan-crypto: pool is disposed');
		if (key.length !== 32)
			throw new RangeError(`XChaCha20StreamPool key must be 32 bytes (got ${key.length})`);
		const cs = chunkSize ?? CHUNK_DEF;
		if (cs < CHUNK_MIN || cs > CHUNK_MAX)
			throw new RangeError(`XChaCha20StreamPool chunkSize must be ${CHUNK_MIN}..${CHUNK_MAX} (got ${cs})`);

		const streamId   = randomBytes(16);
		const userAad    = opts?.aad ?? new Uint8Array(0);
		const chunkCount = plaintext.length === 0 ? 1 : Math.ceil(plaintext.length / cs);

		const chunkPromises: Promise<{ sealed: Uint8Array; nonce: Uint8Array; isLast: boolean }>[] = [];
		for (let i = 0; i < chunkCount; i++) {
			const start  = i * cs;
			const end    = Math.min(start + cs, plaintext.length);
			const slice  = plaintext.slice(start, end);
			const nonce  = randomBytes(24);
			const isLast = i === chunkCount - 1;
			const aad    = chunkAAD(streamId, i, isLast, userAad);
			// key.slice() because worker may neuter the buffer
			const p = this._dispatch('encrypt', key.slice(), nonce.slice(), slice, aad)
				.then(sealed => ({ sealed, nonce, isLast }));
			chunkPromises.push(p);
		}

		const results = await Promise.all(chunkPromises);

		// Compute total output size
		let totalWire = HEADER;
		for (const r of results) totalWire += 1 + 24 + r.sealed.length;

		const out = new Uint8Array(totalWire);
		out.set(streamId, 0);
		out.set(u32be(cs), 16);
		out.set(u64be(chunkCount), 20);

		let pos = HEADER;
		for (const r of results) {
			out[pos] = r.isLast ? 1 : 0;
			out.set(r.nonce, pos + 1);
			out.set(r.sealed, pos + 25);
			pos += 1 + 24 + r.sealed.length;
		}

		return out;
	}

	async open(key: Uint8Array, ciphertext: Uint8Array, opts?: SealOpts): Promise<Uint8Array> {
		if (this._disposed) throw new Error('leviathan-crypto: pool is disposed');
		if (key.length !== 32)
			throw new RangeError(`XChaCha20StreamPool key must be 32 bytes (got ${key.length})`);
		if (ciphertext.length < HEADER + 1 + 24 + 16)
			throw new RangeError('XChaCha20StreamPool: ciphertext too short');

		// Parse header
		const streamId = ciphertext.subarray(0, 16);
		const cs = (ciphertext[16] << 24 | ciphertext[17] << 16 | ciphertext[18] << 8 | ciphertext[19]) >>> 0;
		if (cs < CHUNK_MIN || cs > CHUNK_MAX)
			throw new RangeError(`XChaCha20StreamPool: invalid chunkSize ${cs}`);
		let chunkCount = 0;
		for (let i = 20; i < 28; i++) chunkCount = chunkCount * 256 + ciphertext[i];
		if (chunkCount === 0)
			throw new RangeError('XChaCha20StreamPool: chunkCount must be > 0');

		const userAad = opts?.aad ?? new Uint8Array(0);

		// Dispatch all chunk jobs
		const chunkPromises: Promise<Uint8Array>[] = [];
		let pos = HEADER;
		for (let i = 0; i < chunkCount; i++) {
			const isLast = i === chunkCount - 1;
			// full chunk wire: isLast(1) + nonce(24) + ct(chunkSize) + tag(16)
			const wireLen = isLast ? ciphertext.length - pos : 1 + 24 + cs + 16;
			if (pos + wireLen > ciphertext.length)
				throw new RangeError('XChaCha20StreamPool: ciphertext truncated');

			const chunkWire = ciphertext.subarray(pos, pos + wireLen);
			const nonce   = chunkWire.subarray(1, 25);
			const payload = chunkWire.subarray(25); // ct || tag(16)
			const aad     = chunkAAD(streamId, i, isLast, userAad);
			chunkPromises.push(this._dispatch('decrypt', key.slice(), nonce.slice(), payload.slice(), aad));
			pos += wireLen;
		}

		const results = await Promise.all(chunkPromises);

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

	get size(): number {
		return this._workers.length;
	}

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
		// No transfer list: @vitest/web-worker (same-thread fake worker) silently
		// drops postMessage calls that include a non-empty Transferable array.
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
