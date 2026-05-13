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
// State machine:
//   ParsingHeader -> reading suite_byte, ctx_len, then ctx
//   ParsingData   -> reading payload + sig bytes; running prehash on payload
//   Finalized     -> finalize() called; subsequent operations throw
//   Disposed      -> dispose() called; everything throws

import { constantTimeEqual, concat } from '../utils.js';
import { SigningError } from '../errors.js';
import type { StreamableSignatureSuite } from './types.js';
import { createRunningHash } from './hasher.js';
import type { RunningHash } from './hasher.js';

const enum State {
	ParsingHeader = 0,
	ParsingData = 1,
	Finalized = 2,
	Disposed = 3,
}

export class VerifyStream {
	private readonly suite: StreamableSignatureSuite;
	private readonly pk: Uint8Array;
	private readonly expectedCtx: Uint8Array;

	private state: State = State.ParsingHeader;

	private headerBuf = new Uint8Array(0);
	private payloadChunks: Uint8Array[] = [];
	private payloadHasher: RunningHash | undefined;
	private sigWindow = new Uint8Array(0);

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
	 * payload bytes accumulate behind a sliding sigSize-byte window.
	 */
	update(chunk: Uint8Array): void {
		if (this.state === State.Disposed)
			throw new SigningError('sig-stream-disposed');
		if (this.state === State.Finalized)
			throw new SigningError('sig-stream-finalized');

		let rest = chunk;
		if (this.state === State.ParsingHeader) {
			rest = this.consumeHeaderBytes(chunk);
			if ((this.state as State) !== State.ParsingData) return;
		}
		if (rest.length > 0) this.consumeDataBytes(rest);
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
			if (priorState !== State.ParsingData) {
				this.wipeBuffers();
				throw new SigningError(
					'sig-blob-too-short', 'finalize before header completed',
				);
			}
			if (this.sigWindow.length !== this.suite.sigSize) {
				this.wipeBuffers();
				throw new SigningError(
					'sig-blob-too-short',
					`sigWindow has ${this.sigWindow.length} bytes, expected ${this.suite.sigSize}`,
				);
			}

			const digest = (h as RunningHash).finalize();
			const sig = this.sigWindow;
			if (!this.suite.verifyPrehashed(this.pk, digest, sig, this.expectedCtx)) {
				this.wipeBuffers();
				throw new SigningError('verify-failed');
			}
			return concat(...this.payloadChunks);
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
		if (suiteByte !== this.suite.formatEnum)
			throw new SigningError(
				'sig-suite-mismatch',
				`wire suite 0x${suiteByte.toString(16)} != suite.formatEnum 0x${this.suite.formatEnum.toString(16)}`,
			);

		const ctxLen = combined[1];
		if (combined.length < 2 + ctxLen) {
			this.headerBuf = combined;
			return new Uint8Array(0);
		}

		const wireCtx = combined.subarray(2, 2 + ctxLen);
		if (!constantTimeEqual(wireCtx, this.expectedCtx))
			throw new SigningError('sig-ctx-mismatch');

		this.payloadHasher = createRunningHash(this.suite.prehashAlgorithm);
		this.state = State.ParsingData;
		this.headerBuf = new Uint8Array(0);

		return combined.subarray(2 + ctxLen);
	}

	private consumeDataBytes(chunk: Uint8Array): void {
		const combined = new Uint8Array(this.sigWindow.length + chunk.length);
		combined.set(this.sigWindow, 0);
		combined.set(chunk, this.sigWindow.length);

		const sigSize = this.suite.sigSize;
		if (combined.length <= sigSize) {
			this.sigWindow = combined;
			return;
		}

		const payloadEnd = combined.length - sigSize;
		const payloadChunk = combined.slice(0, payloadEnd);
		this.payloadChunks.push(payloadChunk);
		(this.payloadHasher as RunningHash).update(payloadChunk);
		this.sigWindow = combined.slice(payloadEnd);
	}

	private wipeBuffers(): void {
		for (const c of this.payloadChunks) c.fill(0);
		this.payloadChunks = [];
		if (this.sigWindow.length > 0) {
			this.sigWindow.fill(0);
			this.sigWindow = new Uint8Array(0);
		}
		if (this.headerBuf.length > 0) {
			this.headerBuf.fill(0);
			this.headerBuf = new Uint8Array(0);
		}
	}
}
