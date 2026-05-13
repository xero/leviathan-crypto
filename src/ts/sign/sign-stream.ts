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
// src/ts/sign/sign-stream.ts
//
// SignStream class, streaming signature production for StreamableSignatureSuite.
// Sender writes: preamble + payload bytes + sig (from finalize). Wire format
// is identical to Sign.sign output.

import { SigningError } from '../errors.js';
import type { StreamableSignatureSuite } from './types.js';
import { createRunningHash } from './hasher.js';
import type { RunningHash } from './hasher.js';

export class SignStream {
	/** Header bytes; write to output first. Available immediately. */
	readonly preamble: Uint8Array;

	private readonly suite: StreamableSignatureSuite;
	private readonly sk: Uint8Array;
	private hasher: RunningHash | undefined;
	private finalized = false;
	private disposed = false;

	constructor(
		suite: StreamableSignatureSuite,
		sk: Uint8Array,
		ctx: Uint8Array,
	) {
		this.suite = suite;
		this.sk = sk;

		if (ctx.length > 255)
			throw new SigningError(
				'sig-ctx-too-long',
				`ctx length ${ctx.length} > 255 (wire format ctx_len is u8)`,
			);
		const preamble = new Uint8Array(2 + ctx.length);
		preamble[0] = suite.formatEnum;
		preamble[1] = ctx.length;
		preamble.set(ctx, 2);
		this.preamble = preamble;

		this.hasher = createRunningHash(suite.prehashAlgorithm);
	}

	/** Feed a chunk to the running prehash. */
	update(chunk: Uint8Array): void {
		if (this.disposed) throw new SigningError('sig-stream-disposed');
		if (this.finalized) throw new SigningError('sig-stream-finalized');
		(this.hasher as RunningHash).update(chunk);
	}

	/**
	 * Finalize the running prehash and sign. Returns the signature bytes.
	 * Caller writes these as the last segment of the output stream.
	 */
	finalize(): Uint8Array {
		if (this.disposed) throw new SigningError('sig-stream-disposed');
		if (this.finalized) throw new SigningError('sig-stream-finalized');
		this.finalized = true;

		const h = this.hasher as RunningHash;
		try {
			const digest = h.finalize();
			const userCtx = this.preamble.subarray(2);
			return this.suite.signPrehashed(this.sk, digest, userCtx);
		} finally {
			h.dispose();
			this.hasher = undefined;
		}
	}

	/** Wipe lib-owned state. Idempotent. */
	dispose(): void {
		if (this.disposed) return;
		this.disposed = true;
		if (this.hasher !== undefined) {
			this.hasher.dispose();
			this.hasher = undefined;
		}
	}
}
