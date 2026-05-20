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
// src/ts/sign/verify-stream.ts
//
// VerifyStream class, buffered streaming verification for
// StreamableSignatureSuite. Holds payload chunks internally; on finalize
// verifies and returns the payload, or throws and wipes.
//
// v3 attached envelope wire (parsed in this order):
//   [suite_byte: u8][ctx_len: u8][ctx: ctx_len bytes]
//   [payload_len: u32 BE][payload: payload_len bytes][sig: remainder]
//
// State machine:
//   ParsingHeader  -> read suite, ctx_len, ctx, payload_len. payload_len
//                     is the head-of-payload marker, so we transition
//                     directly to ParsingPayload once it lands.
//   ParsingPayload -> read exactly payload_len bytes, driving the running
//                     prehash on the way. transition to ParsingSig.
//   ParsingSig     -> accumulate trailing sig bytes (<= suite.sigMaxSize).
//                     finalize verifies.
//   Finalized      -> finalize() called; subsequent operations throw.
//   Disposed       -> dispose() called; everything throws.

import { constantTimeEqual, concat } from '../utils.js';
import { SigningError } from '../errors.js';
import type { StreamableSignatureSuite } from './types.js';
import { createRunningHash } from './hasher.js';
import type { RunningHash } from './hasher.js';

const enum State {
	ParsingHeader  = 0,
	ParsingPayload = 1,
	ParsingSig     = 2,
	Finalized      = 3,
	Disposed       = 4,
}

export class VerifyStream {
	private readonly suite: StreamableSignatureSuite;
	private readonly pk: Uint8Array;
	private readonly expectedCtx: Uint8Array;

	private state: State = State.ParsingHeader;

	private headerBuf = new Uint8Array(0);
	private payloadChunks: Uint8Array[] = [];
	private payloadHasher: RunningHash | undefined;
	private payloadRemaining = 0;
	private sigBuf = new Uint8Array(0);

	constructor(
		suite: StreamableSignatureSuite,
		pk: Uint8Array,
		ctx: Uint8Array,
	) {
		this.suite = suite;
		this.pk = pk;
		this.expectedCtx = ctx;
	}

	/**
	 * Feed bytes from the wire. Header parsing is byte-by-byte tolerant;
	 * payload bytes accumulate up to the wire-declared payload_len; the
	 * trailing sig bytes accumulate until finalize.
	 */
	update(chunk: Uint8Array): void {
		if (this.state === State.Disposed)
			throw new SigningError('sig-stream-disposed');
		if (this.state === State.Finalized)
			throw new SigningError('sig-stream-finalized');

		let rest = chunk;
		if (this.state === State.ParsingHeader) {
			rest = this.consumeHeaderBytes(rest);
			if ((this.state as State) === State.ParsingHeader) return;
		}
		if (rest.length === 0) return;

		if (this.state === State.ParsingPayload) {
			rest = this.consumePayloadBytes(rest);
			if (rest.length === 0) return;
		}

		if ((this.state as State) === State.ParsingSig) {
			this.consumeSigBytes(rest);
		}
	}

	/**
	 * Verify the buffered signature. Returns the payload on success.
	 * Throws and wipes the buffered payload on verification failure.
	 */
	finalize(): Uint8Array {
		if (this.state === State.Disposed)
			throw new SigningError('sig-stream-disposed');
		if (this.state === State.Finalized)
			throw new SigningError('sig-stream-finalized');

		// From here on, the stream transitions to Finalized regardless of
		// success/failure so a partial parse cannot leave the hasher (and
		// its WASM module) held.
		const priorState = this.state;
		this.state = State.Finalized;
		const h = this.payloadHasher;
		this.payloadHasher = undefined;

		try {
			if (priorState !== State.ParsingSig) {
				this.wipeBuffers();
				throw new SigningError(
					'sig-blob-too-short',
					'finalize before payload completed',
				);
			}
			if (this.sigBuf.length === 0) {
				this.wipeBuffers();
				throw new SigningError(
					'sig-blob-too-short',
					'finalize before any sig bytes arrived',
				);
			}
			if (this.sigBuf.length > this.suite.sigMaxSize) {
				this.wipeBuffers();
				throw new SigningError(
					'sig-blob-too-short',
					`trailing sig ${this.sigBuf.length} > suite.sigMaxSize ${this.suite.sigMaxSize}`,
				);
			}

			const digest = (h as RunningHash).finalize();
			const sig = this.sigBuf;
			try {
				if (!this.suite.verifyPrehashed(this.pk, digest, sig, this.expectedCtx)) {
					this.wipeBuffers();
					throw new SigningError('verify-failed');
				}
			} catch (e) {
				this.wipeBuffers();
				throw e;
			}
			// `concat` allocates a fresh buffer, so wiping the chunks here
			// does not corrupt the returned payload; it just drops the
			// internal duplicates that would otherwise linger until GC.
			const out = concat(...this.payloadChunks);
			this.wipeBuffers();
			return out;
		} finally {
			if (h !== undefined) h.dispose();
		}
	}

	/** Wipe all internal state. Idempotent. */
	dispose(): void {
		if (this.state === State.Disposed) return;
		this.state = State.Disposed;
		if (this.payloadHasher !== undefined) {
			this.payloadHasher.dispose();
			this.payloadHasher = undefined;
		}
		this.wipeBuffers();
	}

	private consumeHeaderBytes(chunk: Uint8Array): Uint8Array {
		const combined = new Uint8Array(this.headerBuf.length + chunk.length);
		combined.set(this.headerBuf, 0);
		combined.set(chunk, this.headerBuf.length);

		if (combined.length < 2) {
			this.headerBuf = combined;
			return new Uint8Array(0);
		}

		const suiteByte = combined[0];
		if (suiteByte !== this.suite.formatEnum) {
			this.state = State.Finalized;
			this.wipeBuffers();
			throw new SigningError(
				'sig-suite-mismatch',
				`wire suite 0x${suiteByte.toString(16)} != suite.formatEnum 0x${this.suite.formatEnum.toString(16)}`,
			);
		}

		const ctxLen = combined[1];
		const headerEnd = 2 + ctxLen + 4;
		if (combined.length < headerEnd) {
			this.headerBuf = combined;
			return new Uint8Array(0);
		}

		const wireCtx = combined.subarray(2, 2 + ctxLen);
		if (!constantTimeEqual(wireCtx, this.expectedCtx)) {
			this.state = State.Finalized;
			this.wipeBuffers();
			throw new SigningError('sig-ctx-mismatch');
		}

		// payload_len lives at offset 2 + ctxLen, u32 BE per the v3
		// envelope wire. Multiply the high byte instead of <<24 so a
		// 0x80-or-higher high byte does not turn the result negative
		// and silently bypass the payload-overflow check downstream.
		const lOff = 2 + ctxLen;
		this.payloadRemaining =
			combined[lOff] * 0x1000000
			+ ((combined[lOff + 1] << 16)
				| (combined[lOff + 2] << 8)
				| combined[lOff + 3]);

		this.payloadHasher = createRunningHash(this.suite.prehashAlgorithm);
		this.headerBuf = new Uint8Array(0);
		this.state = this.payloadRemaining === 0
			? State.ParsingSig
			: State.ParsingPayload;

		return combined.subarray(headerEnd);
	}

	private consumePayloadBytes(chunk: Uint8Array): Uint8Array {
		if (this.payloadRemaining === 0) {
			this.state = State.ParsingSig;
			return chunk;
		}
		const take = Math.min(chunk.length, this.payloadRemaining);
		const segment = chunk.subarray(0, take);
		// Copy so a caller-side mutation cannot retroactively alter the
		// buffered payload we return at finalize.
		const owned = new Uint8Array(segment);
		this.payloadChunks.push(owned);
		(this.payloadHasher as RunningHash).update(owned);
		this.payloadRemaining -= take;
		if (this.payloadRemaining === 0) this.state = State.ParsingSig;
		return chunk.subarray(take);
	}

	private consumeSigBytes(chunk: Uint8Array): void {
		const combined = new Uint8Array(this.sigBuf.length + chunk.length);
		combined.set(this.sigBuf, 0);
		combined.set(chunk, this.sigBuf.length);
		this.sigBuf = combined;
	}

	private wipeBuffers(): void {
		for (const c of this.payloadChunks) c.fill(0);
		this.payloadChunks = [];
		if (this.sigBuf.length > 0) {
			this.sigBuf.fill(0);
			this.sigBuf = new Uint8Array(0);
		}
		if (this.headerBuf.length > 0) {
			this.headerBuf.fill(0);
			this.headerBuf = new Uint8Array(0);
		}
	}
}
