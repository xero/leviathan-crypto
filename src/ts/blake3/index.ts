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
// src/ts/blake3/index.ts
//
// BLAKE3 public API. One-shot and streaming flavours of hash, keyed_hash,
// derive_key (BLAKE3 §2.3 Modes), and the XOF reader (§2.6). Call
// `blake3Init(source)` before constructing any class.

import {
	getInstance, initModule, isInitialized,
	_acquireModule, _releaseModule, _assertNotOwned,
} from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import type { HashFn } from '../types.js';
import type { Blake3Exports } from './types.js';
import { validateKey, validateContext, validateOutputLen } from './validate.js';

export type { WasmSource };
export type { Blake3Exports };
export { isInitialized };

export async function blake3Init(source: WasmSource): Promise<void> {
	return initModule('blake3', source);
}

function getExports(): Blake3Exports {
	return getInstance('blake3').exports as unknown as Blake3Exports;
}

// Input scratch sits past BUFFER_END from src/asm/blake3/buffers.ts;
// usable region is 131072 - INPUT_SCRATCH_OFF bytes.
const INPUT_SCRATCH_OFF = 27648;
const INPUT_SCRATCH_MAX = 131072 - INPUT_SCRATCH_OFF;

// One-shot output staging cap; larger XOF reads go through OutputReader.
const OUTPUT_STAGING_SIZE = 1024;

// BLAKE3 §2.6: root compress emits 64 bytes per squeeze.
const ROOT_BLOCK_SIZE = 64;

function tooBigForScratchError(len: number): RangeError {
	return new RangeError(
		`leviathan-crypto: blake3 input length ${len} exceeds the per-call `
		+ `WASM input scratch (${INPUT_SCRATCH_MAX} bytes). Split the input or `
		+ 'use the streaming surface (BLAKE3Stream / BLAKE3KeyedHashStream / '
		+ 'BLAKE3DeriveKeyStream).',
	);
}

function tooBigForOneShotError(len: number): RangeError {
	return new RangeError(
		`leviathan-crypto: blake3 outLen ${len} exceeds the per-call output `
		+ `staging size (${OUTPUT_STAGING_SIZE} bytes). For larger XOF reads `
		+ 'use finalizeXof() and BLAKE3OutputReader.read(n).',
	);
}

// Stage `input` into INPUT_SCRATCH_OFF and return (offset, length) for
// the WASM hash() call. Caller is responsible for wiping the scratch
// region after the WASM call returns (we do that in a finally in each
// public method so secret-derived inputs do not linger).
function stageInput(x: Blake3Exports, input: Uint8Array): void {
	if (input.length > INPUT_SCRATCH_MAX) throw tooBigForScratchError(input.length);
	const mem = new Uint8Array(x.memory.buffer);
	mem.set(input, INPUT_SCRATCH_OFF);
}

function wipeInput(x: Blake3Exports, len: number): void {
	const mem = new Uint8Array(x.memory.buffer);
	mem.fill(0, INPUT_SCRATCH_OFF, INPUT_SCRATCH_OFF + len);
}

// One-shot hash entry, no key / no context. Writes the requested prefix
// of the BLAKE3 hash output to a fresh Uint8Array and returns it. Wipes
// the input scratch on the way out.
function oneShotHash(
	x: Blake3Exports,
	input: Uint8Array,
	outLen: number,
): Uint8Array {
	const outOff = x.getOutputStagingOffset();
	stageInput(x, input);
	try {
		x.hash(INPUT_SCRATCH_OFF, input.length, outOff, outLen);
		const mem = new Uint8Array(x.memory.buffer);
		return mem.slice(outOff, outOff + outLen);
	} finally {
		wipeInput(x, input.length);
		x.wipeBuffers();
	}
}

function oneShotKeyedHash(
	x: Blake3Exports,
	key: Uint8Array,
	input: Uint8Array,
	outLen: number,
): Uint8Array {
	const mem    = new Uint8Array(x.memory.buffer);
	const keyOff = x.getKeyedKeyOffset();
	const outOff = x.getOutputStagingOffset();
	mem.set(key, keyOff);
	stageInput(x, input);
	try {
		x.hashKeyed(keyOff, INPUT_SCRATCH_OFF, input.length, outOff, outLen);
		return mem.slice(outOff, outOff + outLen);
	} finally {
		mem.fill(0, keyOff, keyOff + 32);
		wipeInput(x, input.length);
		x.wipeBuffers();
	}
}

function oneShotDeriveKey(
	x: Blake3Exports,
	contextBytes: Uint8Array,
	material: Uint8Array,
	outLen: number,
): Uint8Array {
	if (contextBytes.length + material.length > INPUT_SCRATCH_MAX)
		throw tooBigForScratchError(contextBytes.length + material.length);
	const mem    = new Uint8Array(x.memory.buffer);
	const ctxOff = INPUT_SCRATCH_OFF;
	const matOff = INPUT_SCRATCH_OFF + contextBytes.length;
	const outOff = x.getOutputStagingOffset();
	mem.set(contextBytes, ctxOff);
	mem.set(material,     matOff);
	try {
		x.deriveKey(ctxOff, contextBytes.length, matOff, material.length, outOff, outLen);
		return mem.slice(outOff, outOff + outLen);
	} finally {
		mem.fill(0, ctxOff, matOff + material.length);
		x.wipeBuffers();
	}
}

// ── BLAKE3 ──────────────────────────────────────────────────────────────────

/**
 * BLAKE3 default-mode hash (BLAKE3 §2.3 Modes — `hash`).
 *
 * One-shot: `hash(msg, outLen?)` runs the full chunk / tree / root
 * pipeline and returns `outLen` (default 32) bytes of XOF output.
 * Module exclusivity is acquired and released per call.
 */
export class BLAKE3 {
	private readonly x: Blake3Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array, outLen = 32): Uint8Array {
		_assertNotOwned('blake3');
		if (!(msg instanceof Uint8Array))
			throw new TypeError('leviathan-crypto: blake3 message must be a Uint8Array');
		validateOutputLen(outLen);
		if (outLen > OUTPUT_STAGING_SIZE) throw tooBigForOneShotError(outLen);
		return oneShotHash(this.x, msg, outLen);
	}

	dispose(): void {
		_assertNotOwned('blake3');
		try {
			this.x.wipeBuffers();
		} catch { /* idempotent */ }
	}
}

/**
 * BLAKE3 keyed_hash (BLAKE3 §2.3 Modes — `keyed_hash`).
 *
 * The 32-byte key seeds the chunk machine in place of the BLAKE3 IV and
 * every compress carries the KEYED_HASH flag. Use cases include MACs and
 * keyed-pseudorandom generation; the construction is a PRF when the key
 * is uniform and secret.
 */
export class BLAKE3KeyedHash {
	private readonly x: Blake3Exports;
	constructor() {
		this.x = getExports();
	}

	hash(key: Uint8Array, msg: Uint8Array, outLen = 32): Uint8Array {
		_assertNotOwned('blake3');
		validateKey(key);
		if (!(msg instanceof Uint8Array))
			throw new TypeError('leviathan-crypto: blake3 message must be a Uint8Array');
		validateOutputLen(outLen);
		if (outLen > OUTPUT_STAGING_SIZE) throw tooBigForOneShotError(outLen);
		return oneShotKeyedHash(this.x, key, msg, outLen);
	}

	dispose(): void {
		_assertNotOwned('blake3');
		try {
			this.x.wipeBuffers();
		} catch { /* idempotent */ }
	}
}

/**
 * BLAKE3 derive_key (BLAKE3 §2.3 Modes — `derive_key`).
 *
 * Two-pass KDF: pass 1 hashes the context string with the
 * DERIVE_KEY_CONTEXT flag, pass 2 hashes the key material with the
 * DERIVE_KEY_MATERIAL flag using the pass-1 output as its starting CV.
 * Context strings are conventionally hardcoded UTF-8 application
 * constants; empty contexts are rejected by `validateContext`.
 */
export class BLAKE3DeriveKey {
	private readonly x: Blake3Exports;
	constructor() {
		this.x = getExports();
	}

	derive(
		context: string | Uint8Array,
		material: Uint8Array,
		outLen = 32,
	): Uint8Array {
		_assertNotOwned('blake3');
		const ctxBytes = validateContext(context);
		if (!(material instanceof Uint8Array))
			throw new TypeError('leviathan-crypto: blake3 derive_key material must be a Uint8Array');
		validateOutputLen(outLen);
		if (outLen > OUTPUT_STAGING_SIZE) throw tooBigForOneShotError(outLen);
		return oneShotDeriveKey(this.x, ctxBytes, material, outLen);
	}

	dispose(): void {
		_assertNotOwned('blake3');
		try {
			this.x.wipeBuffers();
		} catch { /* idempotent */ }
	}
}

// ── Streaming base ─────────────────────────────────────────────────────────
//
// Buffer input, run one-shot WASM hash at finalize. Lifecycle mirrors
// SHA3_256Stream. See docs/architecture.md.

class StreamState {
	chunks: Uint8Array[] = [];
	totalLen = 0;
	consumed = false;

	pushChunk(chunk: Uint8Array): void {
		if (this.consumed)
			throw new Error('BLAKE3 stream: update() after finalize/finalizeXof');
		if (!(chunk instanceof Uint8Array))
			throw new TypeError('BLAKE3 stream: chunk must be a Uint8Array');
		if (this.totalLen + chunk.length > INPUT_SCRATCH_MAX)
			throw tooBigForScratchError(this.totalLen + chunk.length);
		this.chunks.push(chunk);
		this.totalLen += chunk.length;
	}

	concat(): Uint8Array {
		if (this.chunks.length === 1) return this.chunks[0];
		const out = new Uint8Array(this.totalLen);
		let pos = 0;
		for (const c of this.chunks) {
			out.set(c, pos);
			pos += c.length;
		}
		return out;
	}

	wipe(): void {
		// Drop references; we don't own caller buffers. concat() buffers
		// are wiped by the calling class.
		this.chunks = [];
		this.totalLen = 0;
	}
}

// ── BLAKE3Stream ───────────────────────────────────────────────────────────

/**
 * Streaming BLAKE3 default-mode hash (BLAKE3 §2.3 Modes — `hash`).
 *
 * `update()` accepts chunks of any size; `finalize()` returns the
 * `outLen`-byte (default 32) digest and disposes the instance. Holds
 * exclusive access to the `blake3` WASM module from construction until
 * `dispose()` or `finalize()` / `finalizeXof()`.
 */
export class BLAKE3Stream {
	private readonly x: Blake3Exports;
	private _tok: symbol | undefined;
	private readonly _state = new StreamState();

	constructor() {
		this.x = getExports();
		this._tok = _acquireModule('blake3');
	}

	update(chunk: Uint8Array): this {
		this._checkLive();
		this._state.pushChunk(chunk);
		return this;
	}

	finalize(outLen = 32): Uint8Array {
		this._checkLive();
		validateOutputLen(outLen);
		if (outLen > OUTPUT_STAGING_SIZE) throw tooBigForOneShotError(outLen);
		this._state.consumed = true;
		const full = this._state.concat();
		try {
			return oneShotHash(this.x, full, outLen);
		} finally {
			this.dispose();
		}
	}

	finalizeXof(): BLAKE3OutputReader {
		this._checkLive();
		// _checkLive guarantees _tok is set; the local capture lets the type
		// system see this beyond the assignment to undefined on the next line.
		const tok = this._tok as symbol;
		this._state.consumed = true;
		// The reader holds the module token for its own lifetime; transfer
		// ownership rather than releasing-then-reacquiring (which would race
		// against any other consumer trying to acquire the module in between).
		this._tok = undefined;
		const full = this._state.concat();
		return new BLAKE3OutputReader('hash', this.x, tok, full);
	}

	dispose(): void {
		if (this._tok === undefined) return;
		this._state.wipe();
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('blake3', this._tok);
			this._tok = undefined;
		}
	}

	private _checkLive(): void {
		if (this._tok === undefined)
			throw new Error('BLAKE3Stream: instance has been disposed');
		if (this._state.consumed)
			throw new Error('BLAKE3Stream: stream has been finalized');
	}
}

// ── BLAKE3KeyedHashStream ──────────────────────────────────────────────────

/**
 * Streaming BLAKE3 keyed_hash (BLAKE3 §2.3 Modes). Key is bound at construction
 * time. Same lifecycle as `BLAKE3Stream`.
 */
export class BLAKE3KeyedHashStream {
	private readonly x: Blake3Exports;
	private _tok: symbol | undefined;
	private readonly _state = new StreamState();
	private readonly _key: Uint8Array;

	constructor(key: Uint8Array) {
		validateKey(key);
		this.x = getExports();
		this._tok = _acquireModule('blake3');
		// Defensive copy: we own this buffer for the lifetime of the stream
		// and wipe it on dispose / finalize.
		this._key = new Uint8Array(32);
		this._key.set(key);
	}

	update(chunk: Uint8Array): this {
		this._checkLive();
		this._state.pushChunk(chunk);
		return this;
	}

	finalize(outLen = 32): Uint8Array {
		this._checkLive();
		validateOutputLen(outLen);
		if (outLen > OUTPUT_STAGING_SIZE) throw tooBigForOneShotError(outLen);
		this._state.consumed = true;
		const full = this._state.concat();
		try {
			return oneShotKeyedHash(this.x, this._key, full, outLen);
		} finally {
			this.dispose();
		}
	}

	finalizeXof(): BLAKE3OutputReader {
		this._checkLive();
		const tok = this._tok as symbol;
		this._state.consumed = true;
		this._tok = undefined;
		const full = this._state.concat();
		const reader = new BLAKE3OutputReader('keyed', this.x, tok, full, this._key);
		// Reader owns its own copy of the key; wipe the stream's.
		this._key.fill(0);
		return reader;
	}

	dispose(): void {
		if (this._tok === undefined) return;
		this._key.fill(0);
		this._state.wipe();
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('blake3', this._tok);
			this._tok = undefined;
		}
	}

	private _checkLive(): void {
		if (this._tok === undefined)
			throw new Error('BLAKE3KeyedHashStream: instance has been disposed');
		if (this._state.consumed)
			throw new Error('BLAKE3KeyedHashStream: stream has been finalized');
	}
}

// ── BLAKE3DeriveKeyStream ──────────────────────────────────────────────────

/**
 * Streaming BLAKE3 derive_key (BLAKE3 §2.3 Modes). Context is bound at
 * construction time; updates stream the material; finalize derives.
 * Same lifecycle as `BLAKE3Stream`.
 */
export class BLAKE3DeriveKeyStream {
	private readonly x: Blake3Exports;
	private _tok: symbol | undefined;
	private readonly _state = new StreamState();
	private readonly _ctxBytes: Uint8Array;

	constructor(context: string | Uint8Array) {
		this._ctxBytes = validateContext(context);
		this.x = getExports();
		this._tok = _acquireModule('blake3');
	}

	update(chunk: Uint8Array): this {
		this._checkLive();
		this._state.pushChunk(chunk);
		return this;
	}

	finalize(outLen = 32): Uint8Array {
		this._checkLive();
		validateOutputLen(outLen);
		if (outLen > OUTPUT_STAGING_SIZE) throw tooBigForOneShotError(outLen);
		this._state.consumed = true;
		const full = this._state.concat();
		try {
			return oneShotDeriveKey(this.x, this._ctxBytes, full, outLen);
		} finally {
			this.dispose();
		}
	}

	finalizeXof(): BLAKE3OutputReader {
		this._checkLive();
		const tok = this._tok as symbol;
		this._state.consumed = true;
		this._tok = undefined;
		const full = this._state.concat();
		return new BLAKE3OutputReader('derive', this.x, tok, full, undefined, this._ctxBytes);
	}

	dispose(): void {
		if (this._tok === undefined) return;
		this._state.wipe();
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('blake3', this._tok);
			this._tok = undefined;
		}
	}

	private _checkLive(): void {
		if (this._tok === undefined)
			throw new Error('BLAKE3DeriveKeyStream: instance has been disposed');
		if (this._state.consumed)
			throw new Error('BLAKE3DeriveKeyStream: stream has been finalized');
	}
}

// ── BLAKE3OutputReader ─────────────────────────────────────────────────────

type ReaderMode = 'hash' | 'keyed' | 'derive';

/**
 * BLAKE3 XOF reader (BLAKE3 §2.6 Extendable Output).
 *
 * Sequential `read(nBytes)` calls squeeze the next bytes of XOF output.
 * Constructed via `finalizeXof()` on a streaming class. Holds module
 * exclusivity until `dispose()`.
 *
 * Implementation: the first `read()` runs the underlying hash entry once
 * to populate the WASM-side root-compress snapshot (ROOT_STATE_*), then
 * caches the first 64-byte XOF block. Subsequent reads pump
 * `squeezeXofBlock` on the WASM module with an incrementing counter to
 * lift additional 64-byte blocks off the snapshot. The reader's lifetime
 * coincides with its hold on the module token, so `ROOT_STATE_*` stays
 * intact between read calls (no other consumer can fire a hash that
 * would clobber it).
 */
export class BLAKE3OutputReader {
	private readonly x: Blake3Exports;
	private _tok: symbol | undefined;
	private readonly _mode: ReaderMode;
	private readonly _input: Uint8Array;
	private readonly _key:   Uint8Array | undefined;
	private readonly _ctx:   Uint8Array | undefined;
	private readonly _blockBuf = new Uint8Array(ROOT_BLOCK_SIZE);
	private _blockPos = ROOT_BLOCK_SIZE;  // forces refill on first read
	private _nextCounter = 0n;
	private _populated = false;

	/** @internal Constructed by `finalizeXof()` on a streaming class. */
	constructor(
		mode: ReaderMode,
		x: Blake3Exports,
		tok: symbol,
		input: Uint8Array,
		key?:  Uint8Array,
		ctx?:  Uint8Array,
	) {
		this._mode  = mode;
		this.x      = x;
		this._tok   = tok;
		this._input = input;
		// Defensive copy of key, the reader outlives the parent stream's
		// _key buffer (which is wiped on transfer).
		if (key) {
			this._key = new Uint8Array(32);
			this._key.set(key);
		} else {
			this._key = undefined;
		}
		this._ctx = ctx;
	}

	read(nBytes: number): Uint8Array {
		if (this._tok === undefined)
			throw new Error('BLAKE3OutputReader: instance has been disposed');
		validateOutputLen(nBytes);

		if (!this._populated) {
			this._populate();
		}

		const out = new Uint8Array(nBytes);
		let pos = 0;
		while (pos < nBytes) {
			if (this._blockPos >= ROOT_BLOCK_SIZE) {
				this._squeezeNextBlock();
			}
			const available = ROOT_BLOCK_SIZE - this._blockPos;
			const take      = Math.min(nBytes - pos, available);
			out.set(this._blockBuf.subarray(this._blockPos, this._blockPos + take), pos);
			this._blockPos += take;
			pos            += take;
		}
		return out;
	}

	dispose(): void {
		if (this._tok === undefined) return;
		this._blockBuf.fill(0);
		this._blockPos    = ROOT_BLOCK_SIZE;
		this._nextCounter = 0n;
		if (this._key) this._key.fill(0);
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('blake3', this._tok);
			this._tok = undefined;
		}
	}

	// Captures ROOT_STATE_* inside WASM, copies block 0 to _blockBuf.
	// Does NOT call wipeBuffers; that would clear ROOT_STATE_* and break
	// subsequent squeezeXofBlock calls. The reader wipes on dispose.
	private _populate(): void {
		const x      = this.x;
		const outOff = x.getOutputStagingOffset();
		const mem    = new Uint8Array(x.memory.buffer);

		if (this._input.length > INPUT_SCRATCH_MAX) throw tooBigForScratchError(this._input.length);
		mem.set(this._input, INPUT_SCRATCH_OFF);

		try {
			switch (this._mode) {
			case 'hash':
				x.hash(INPUT_SCRATCH_OFF, this._input.length, outOff, ROOT_BLOCK_SIZE);
				break;
			case 'keyed': {
				if (!this._key) throw new Error('BLAKE3OutputReader: keyed mode without key');
				const keyOff = x.getKeyedKeyOffset();
				mem.set(this._key, keyOff);
				try {
					x.hashKeyed(keyOff, INPUT_SCRATCH_OFF, this._input.length, outOff, ROOT_BLOCK_SIZE);
				} finally {
					mem.fill(0, keyOff, keyOff + 32);
				}
				break;
			}
			case 'derive': {
				if (!this._ctx) throw new Error('BLAKE3OutputReader: derive mode without context');
				const ctx = this._ctx;
				if (ctx.length + this._input.length > INPUT_SCRATCH_MAX)
					throw tooBigForScratchError(ctx.length + this._input.length);
				// Re-stage with context prefixed in front of material.
				mem.set(ctx,         INPUT_SCRATCH_OFF);
				mem.set(this._input, INPUT_SCRATCH_OFF + ctx.length);
				try {
					x.deriveKey(
						INPUT_SCRATCH_OFF, ctx.length,
						INPUT_SCRATCH_OFF + ctx.length, this._input.length,
						outOff, ROOT_BLOCK_SIZE,
					);
				} finally {
					mem.fill(0, INPUT_SCRATCH_OFF, INPUT_SCRATCH_OFF + ctx.length);
				}
				break;
			}
			}

			this._blockBuf.set(mem.subarray(outOff, outOff + ROOT_BLOCK_SIZE));
			this._blockPos    = 0;
			this._nextCounter = 1n;
			this._populated   = true;
		} finally {
			const inLen = this._mode === 'derive' && this._ctx
				? this._ctx.length + this._input.length
				: this._input.length;
			mem.fill(0, INPUT_SCRATCH_OFF, INPUT_SCRATCH_OFF + inLen);
			mem.fill(0, outOff,            outOff + ROOT_BLOCK_SIZE);
		}
	}

	private _squeezeNextBlock(): void {
		const x      = this.x;
		const outOff = x.getOutputStagingOffset();
		const ctr    = this._nextCounter;
		const ctrLo  = Number(ctr & 0xffffffffn);
		const ctrHi  = Number((ctr >> 32n) & 0xffffffffn);
		x.squeezeXofBlock(ctrLo, ctrHi, outOff);
		const mem = new Uint8Array(x.memory.buffer);
		this._blockBuf.set(mem.subarray(outOff, outOff + ROOT_BLOCK_SIZE));
		this._blockPos    = 0;
		this._nextCounter = ctr + 1n;
		// Scrub the staging slot now that the bytes are in _blockBuf; the
		// reader's wipe-on-dispose covers _blockBuf itself.
		mem.fill(0, outOff, outOff + ROOT_BLOCK_SIZE);
	}
}

// ── BLAKE3Hash, Fortuna HashFn const ───────────────────────────────────────

/**
 * Stateless BLAKE3-256 HashFn. Shape mirrors `SHA256Hash` in
 * `src/ts/sha2/hash.ts`: 32-byte output, single WASM module dependency,
 * `digest(msg)` runs a one-shot hash with default `outLen`.
 *
 * Usable as a Fortuna accumulator / reseed hash when paired with a
 * matching 32-byte-key Generator.
 */
export const BLAKE3Hash: HashFn = {
	outputSize: 32,
	wasmModules: ['blake3'],

	digest(msg: Uint8Array): Uint8Array {
		_assertNotOwned('blake3');
		const x = getExports();
		return oneShotHash(x, msg, 32);
	},
};
