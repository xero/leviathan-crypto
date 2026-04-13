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
// src/ts/stream/seal-stream-pool.ts
//
// SealStreamPool — parallel batch encryption/decryption using the STREAM
// construction. Dispatches per-chunk seal/open jobs across Web Workers.
// Any error is fatal: auth failure, crash, or timeout kills all workers,
// wipes keys, and rejects all pending promises.

import { randomBytes, wipe } from '../utils.js';
import { isInitialized } from '../init.js';
import { compileWasm } from '../loader.js';
import { AuthenticationError } from '../errors.js';
import type { WasmSource } from '../wasm-source.js';
import type { CipherSuite, DerivedKeys } from './types.js';
import { CHUNK_MIN, CHUNK_MAX, HEADER_SIZE, TAG_DATA, TAG_FINAL } from './constants.js';
import { writeHeader, readHeader, makeCounterNonce } from './header.js';

export interface PoolOpts {
	wasm: WasmSource | Record<string, WasmSource>;
	workers?: number;
	chunkSize?: number;
	framed?: boolean;
	jobTimeout?: number;
}

interface PendingJob {
	resolve: (data: Uint8Array) => void;
	reject: (err: Error) => void;
	timer: ReturnType<typeof setTimeout>;
}

interface QueuedJob {
	type: 'job';
	id: number;
	op: 'seal' | 'open';
	counterNonce: Uint8Array;
	data: Uint8Array;
	aad?: Uint8Array;
	derivedKeyBytes?: Uint8Array;
}

function isRecord(v: unknown): v is Record<string, WasmSource> {
	return typeof v === 'object' && v !== null
		&& !(v instanceof Uint8Array) && !(v instanceof ArrayBuffer)
		&& !(v instanceof URL) && !(v instanceof WebAssembly.Module)
		&& !(typeof Response !== 'undefined' && v instanceof Response)
		&& typeof (v as Record<string, unknown>).then !== 'function';
}

export class SealStreamPool {
	private readonly _cipher: CipherSuite;
	private readonly _chunkSize: number;
	private readonly _framed: boolean;
	private readonly _timeout: number;
	private readonly _header: Uint8Array;
	private _workers: Worker[];
	private _idle: Worker[];
	private _queue: QueuedJob[];
	private _pending: Map<number, PendingJob>;
	private _nextId: number;
	private _dead: boolean;
	private _sealed: boolean;
	private _keys: DerivedKeys | null;
	private _masterKey: Uint8Array | null;

	private constructor(
		cipher: CipherSuite,
		workers: Worker[],
		keys: DerivedKeys,
		masterKey: Uint8Array,
		header: Uint8Array,
		chunkSize: number,
		framed: boolean,
		timeout: number,
	) {
		this._cipher = cipher;
		this._workers = workers;
		this._idle = [...workers];
		this._queue = [];
		this._pending = new Map();
		this._nextId = 0;
		this._dead = false;
		this._sealed = false;
		this._keys = keys;
		this._masterKey = masterKey;
		this._header = header;
		this._chunkSize = chunkSize;
		this._framed = framed;
		this._timeout = timeout;

		for (const w of workers) {
			w.onmessage = (e: MessageEvent) => this._onMessage(w, e);
			w.onerror = (e: ErrorEvent) => this._onError(e);
		}
	}

	static async create(
		cipher: CipherSuite,
		key: Uint8Array,
		opts: PoolOpts,
	): Promise<SealStreamPool> {
		if (!isInitialized('sha2'))
			throw new Error(
				'leviathan-crypto: stream layer requires sha2 for key derivation — '
				+ 'call init({ sha2: ... }) before creating a SealStreamPool',
			);

		if (cipher.kemCtSize > 0)
			throw new Error(
				'leviathan-crypto: SealStreamPool does not support KEM-enabled cipher suites — '
				+ 'KEM encryption is asymmetric (seal uses encapsulation key, open requires decapsulation key) '
				+ 'and cannot share a single key across both directions. '
				+ 'Use SealStream / OpenStream directly for hybrid KEM encryption.',
			);

		const chunkSize = opts.chunkSize ?? 65536;
		if (chunkSize < CHUNK_MIN || chunkSize > CHUNK_MAX)
			throw new RangeError(`chunkSize must be in [${CHUNK_MIN}, ${CHUNK_MAX}] (got ${chunkSize})`);

		const framed = opts.framed ?? false;
		const timeout = opts.jobTimeout ?? 30_000;
		const n = opts.workers ?? (typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : undefined) ?? 4;

		// Compile WASM modules
		const modules: Record<string, WebAssembly.Module> = {};
		const required = cipher.wasmModules;

		if (isRecord(opts.wasm)) {
			const record = opts.wasm;
			for (const mod of required) {
				if (!(mod in record))
					throw new Error(`leviathan-crypto: pool requires WASM module '${mod}' (required: ${required.join(', ')})`);
				modules[mod] = await compileWasm(record[mod]);
			}
		} else {
			if (required.length > 1)
				throw new Error(`leviathan-crypto: cipher requires ${required.length} WASM modules (${required.join(', ')}) — provide a Record`);
			modules[required[0]] = await compileWasm(opts.wasm as WasmSource);
		}

		// For padded ciphers, validate that a full plaintext chunk fits in the WASM
		// after PKCS7 padding. PKCS7 always adds between 1 and blockSize bytes.
		if (cipher.padded) {
			const paddedFull = chunkSize + 16 - (chunkSize % 16);
			if (paddedFull > cipher.wasmChunkSize)
				throw new RangeError(
					`leviathan-crypto: chunkSize ${chunkSize} is too large for ${cipher.formatName} ` +
					`(padded full chunk = ${paddedFull}, WASM CHUNK_SIZE = ${cipher.wasmChunkSize}). ` +
					`Use chunkSize \u2264 ${cipher.wasmChunkSize - 1}.`,
				);
		}

		if (key.length !== cipher.keySize)
			throw new RangeError(`key must be ${cipher.keySize} bytes (got ${key.length})`);

		// Generate nonce and derive keys
		const nonce = randomBytes(16);
		const keys = cipher.deriveKeys(key, nonce);
		const header = writeHeader(cipher.formatEnum, framed, nonce, chunkSize);

		// Spawn workers sequentially (compatible with @vitest/web-worker)
		const workers: Worker[] = [];
		for (let i = 0; i < n; i++) {
			const w = cipher.createPoolWorker();
			await new Promise<void>((resolve, reject) => {
				const onMsg = (e: MessageEvent) => {
					w.removeEventListener('message', onMsg);
					w.removeEventListener('error', onErr);
					if (e.data.type === 'ready') resolve();
					else {
						w.terminate(); reject(new Error(`worker init failed: ${e.data.message}`));
					}
				};
				const onErr = (e: ErrorEvent) => {
					w.removeEventListener('message', onMsg);
					w.removeEventListener('error', onErr);
					w.terminate();
					reject(new Error(`worker init failed: ${e.message}`));
				};
				w.addEventListener('message', onMsg);
				w.addEventListener('error', onErr);
				const initKeyBytes = keys.bytes.slice();
				w.postMessage(
					{ type: 'init', modules, derivedKeyBytes: initKeyBytes },
					{ transfer: [initKeyBytes.buffer] },
				);
			});
			workers.push(w);
		}

		return new SealStreamPool(cipher, workers, keys, key.slice(), header, chunkSize, framed, timeout);
	}

	get header(): Uint8Array {
		return this._header;
	}
	get dead(): boolean {
		return this._dead;
	}
	get size(): number {
		return this._workers.length;
	}

	async seal(plaintext: Uint8Array): Promise<Uint8Array> {
		if (this._dead) throw new Error('leviathan-crypto: pool is dead');
		if (this._sealed) throw new Error(
			'leviathan-crypto: seal() already called on this pool. '
			+ 'Create a new pool for each encryption to prevent nonce reuse.',
		);

		const chunkCount = plaintext.length === 0 ? 1 : Math.ceil(plaintext.length / this._chunkSize);
		const jobs: Promise<Uint8Array>[] = [];

		for (let i = 0; i < chunkCount; i++) {
			const start = i * this._chunkSize;
			const end = Math.min(start + this._chunkSize, plaintext.length);
			const slice = plaintext.slice(start, end);
			const isLast = i === chunkCount - 1;
			const counterNonce = makeCounterNonce(i, isLast ? TAG_FINAL : TAG_DATA);
			jobs.push(this._dispatch({ op: 'seal', counterNonce, data: slice }));
		}

		try {
			const results = await Promise.all(jobs);
			let totalLen = HEADER_SIZE;
			for (const r of results) totalLen += this._framed ? r.length + 4 : r.length;
			const ciphertext = new Uint8Array(totalLen);
			ciphertext.set(this._header, 0);
			let pos = HEADER_SIZE;
			for (const r of results) {
				if (this._framed) {
					new DataView(ciphertext.buffer, pos).setUint32(0, r.length, false);
					pos += 4;
				}
				ciphertext.set(r, pos); pos += r.length;
			}
			this._sealed = true;
			return ciphertext;
		} catch (err) {
			this._killAll(err as Error);
			throw err;
		}
	}

	async open(ciphertext: Uint8Array): Promise<Uint8Array> {
		if (this._dead) throw new Error('leviathan-crypto: pool is dead');
		if (ciphertext.length < HEADER_SIZE)
			throw new RangeError(
				`leviathan-crypto: ciphertext too short — need at least ${HEADER_SIZE} bytes for header`,
			);

		// Validate header before splitting chunks
		const h = readHeader(ciphertext.subarray(0, HEADER_SIZE));
		if (h.formatEnum !== this._cipher.formatEnum)
			throw new Error(
				`leviathan-crypto: pool expected format 0x${this._cipher.formatEnum.toString(16).padStart(2, '0')}, `
				+ `got 0x${h.formatEnum.toString(16).padStart(2, '0')}`,
			);
		if (h.chunkSize !== this._chunkSize)
			throw new RangeError(
				`leviathan-crypto: pool chunkSize mismatch — pool expects ${this._chunkSize}, `
				+ `header says ${h.chunkSize}`,
			);
		if (h.framed !== this._framed)
			throw new Error(
				`leviathan-crypto: pool framing mismatch — pool is ${this._framed ? 'framed' : 'unframed'}, `
				+ `header says ${h.framed ? 'framed' : 'unframed'}`,
			);

		// Re-derive keys from the nonce embedded in this ciphertext's header.
		// The pool's _keys are tied to its own seal nonce — for arbitrary incoming
		// ciphertext the nonce may differ, so we derive fresh keys here.
		if (!this._masterKey) throw new Error('leviathan-crypto: pool master key has been wiped');
		const openKeys = this._cipher.deriveKeys(this._masterKey, h.nonce);
		let openKeysWiped = false;

		try {
			// Strip header before chunk splitting
			const body = ciphertext.subarray(HEADER_SIZE);
			if (body.length === 0)
				throw new RangeError('leviathan-crypto: empty ciphertext — seal() always produces at least one chunk');

			// Compute max wire chunk size for per-chunk validation
			const tagSize = this._cipher.tagSize;
			const paddedSize = this._cipher.padded
				? this._chunkSize + 16 - (this._chunkSize % 16)
				: this._chunkSize;
			const maxWireChunk = paddedSize + tagSize;

			// Split ciphertext body into chunks
			const chunks: Uint8Array[] = [];
			let pos = 0;
			if (this._framed) {
				while (pos < body.length) {
					if (pos + 4 > body.length)
						throw new RangeError('leviathan-crypto: truncated frame header');
					const dv = new DataView(body.buffer, body.byteOffset + pos);
					const len = dv.getUint32(0, false);
					pos += 4;
					if (pos + len > body.length)
						throw new RangeError(
							`leviathan-crypto: frame claims ${len} bytes but only ${body.length - pos} remain`,
						);
					chunks.push(body.subarray(pos, pos + len));
					pos += len;
				}
			} else {
				// Unframed: split by expected wire chunk size
				const fullChunkWire = maxWireChunk;
				while (pos < body.length) {
					const remaining = body.length - pos;
					if (remaining <= fullChunkWire) {
						chunks.push(body.subarray(pos));
						break;
					}
					chunks.push(body.subarray(pos, pos + fullChunkWire));
					pos += fullChunkWire;
				}
			}

			// Validate and dispatch chunks
			const jobs: Promise<Uint8Array>[] = [];
			for (let i = 0; i < chunks.length; i++) {
				if (chunks[i].length < tagSize)
					throw new RangeError(
						`leviathan-crypto: chunk ${i} too short — need at least ${tagSize} bytes for tag `
						+ `(got ${chunks[i].length})`,
					);
				if (chunks[i].length > maxWireChunk)
					throw new RangeError(
						`leviathan-crypto: chunk ${i} exceeds max wire size `
						+ `(${chunks[i].length} > ${maxWireChunk})`,
					);
				const isLast = i === chunks.length - 1;
				const counterNonce = makeCounterNonce(i, isLast ? TAG_FINAL : TAG_DATA);
				jobs.push(this._dispatch({
					op: 'open', counterNonce, data: chunks[i],
					derivedKeyBytes: openKeys.bytes.slice(),
				}));
			}
			// All per-job key copies made — wipe the main-thread openKeys immediately
			// rather than waiting for Promise.all. earlyWiped tracks this so the
			// finally below only fires on pre-dispatch throws (empty body, frame errors,
			// chunk validation), not as a redundant second call on the normal path.
			this._cipher.wipeKeys(openKeys);
			openKeysWiped = true;

			const results = await Promise.all(jobs);
			let totalLen = 0;
			for (const r of results) totalLen += r.length;
			const plaintext = new Uint8Array(totalLen);
			let ptPos = 0;
			for (const r of results) {
				plaintext.set(r, ptPos); ptPos += r.length;
			}
			return plaintext;
		} catch (err) {
			this._killAll(err as Error);
			throw err;
		} finally {
			if (!openKeysWiped) this._cipher.wipeKeys(openKeys);
		}
	}

	destroy(): void {
		this._killAll(new Error('leviathan-crypto: pool destroyed'));
	}

	// ── Internals ────────────────────────────────────────────────────────────

	private _dispatch(job: Omit<QueuedJob, 'id' | 'type'>): Promise<Uint8Array> {
		return new Promise((resolve, reject) => {
			if (this._dead) {
				reject(new Error('leviathan-crypto: pool is dead')); return;
			}
			const id = this._nextId++;
			const timer = setTimeout(() => {
				this._killAll(new Error(`leviathan-crypto: pool job ${id} timed out after ${this._timeout}ms`));
			}, this._timeout);
			this._pending.set(id, { resolve, reject, timer });
			const worker = this._idle.pop();
			if (worker) this._send(worker, { type: 'job', id, ...job });
			else this._queue.push({ type: 'job', id, ...job });
		});
	}

	private _send(worker: Worker, job: QueuedJob): void {
		const transfer: ArrayBuffer[] = [];
		// Only transfer data.buffer when the Uint8Array owns the buffer exclusively.
		// Subarrays from open() share the caller's ciphertext buffer — transferring
		// one would detach all sibling views dispatched as parallel jobs.
		if (job.data.buffer instanceof ArrayBuffer
			&& job.data.byteOffset === 0
			&& job.data.byteLength === job.data.buffer.byteLength)
			transfer.push(job.data.buffer);
		if (job.counterNonce.buffer instanceof ArrayBuffer
			&& job.counterNonce.buffer !== job.data.buffer)
			transfer.push(job.counterNonce.buffer);
		if (job.derivedKeyBytes?.buffer instanceof ArrayBuffer)
			transfer.push(job.derivedKeyBytes.buffer);
		// aad is intentionally not transferred — caller may retain the reference
		worker.postMessage(job, { transfer });
	}

	private _onMessage(worker: Worker, e: MessageEvent): void {
		const msg = e.data;
		const pending = this._pending.get(msg.id);
		if (!pending) return;
		clearTimeout(pending.timer);
		this._pending.delete(msg.id);

		if (msg.type === 'result') {
			pending.resolve(msg.data);
			const next = this._queue.shift();
			if (next) this._send(worker, next);
			else this._idle.push(worker);
		} else {
			const err = msg.isAuthError
				? new AuthenticationError(msg.cipher)
				: new Error(msg.message);
			pending.reject(err);
			this._killAll(err);
		}
	}

	private _onError(e: ErrorEvent): void {
		this._killAll(new Error(`leviathan-crypto: pool worker crashed: ${e.message}`));
	}

	private _killAll(error: Error): void {
		if (this._dead) return;
		this._dead = true;
		for (const { timer } of this._pending.values()) clearTimeout(timer);
		for (const { reject } of this._pending.values()) reject(error);
		this._pending.clear();
		this._queue.length = 0;

		const workers = this._workers;
		this._workers = [];
		this._idle.length = 0;

		// Fire-and-forget: wipe each worker's key material, then terminate.
		// On timeout, terminate anyway — the main-thread key handles are
		// wiped below so the owning surface no longer has access.
		for (const w of workers) this._wipeThenTerminate(w);

		if (this._keys) {
			wipe(this._keys.bytes); this._keys = null;
		}
		if (this._masterKey) {
			wipe(this._masterKey); this._masterKey = null;
		}
	}

	private _wipeThenTerminate(w: Worker): void {
		const WIPE_ACK_TIMEOUT_MS = 100;
		let done = false;
		// prefer-const false positive: `finish` (defined below) closes over
		// `t` and is invoked synchronously from the catch path before the
		// `t = setTimeout(...)` assignment runs.
		// eslint-disable-next-line prefer-const
		let t: ReturnType<typeof setTimeout> | undefined;
		const finish = (): void => {
			if (done) return;
			done = true;
			if (t !== undefined) clearTimeout(t);
			w.removeEventListener('message', onMsg);
			w.terminate();
		};
		const onMsg = (e: MessageEvent): void => {
			if (e.data && e.data.type === 'wiped') finish();
		};
		w.addEventListener('message', onMsg);
		try {
			w.postMessage({ type: 'wipe' });
		} catch {
			finish(); return;
		}
		t = setTimeout(finish, WIPE_ACK_TIMEOUT_MS);
	}
}
