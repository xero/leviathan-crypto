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
//
// The v3 attached envelope carries `payload_len: u32 BE` between ctx and
// payload, so the preamble cannot be built up front: streaming sign feeds
// the digest, not the payload itself, and the payload length is unknown
// until the stream ends. The caller passes the total payload length to
// `buildPreamble` at assembly time. The caller already has the payload
// buffered separately (they fed it to `update` chunk by chunk), so the
// length is available when they go to compose the wire.

import { SigningError } from '../errors.js';
import { wipe } from '../utils.js';
import type { StreamableSignatureSuite } from './types.js';
import { USER_CTX_MAX } from './ctx.js';
import { createRunningHash } from './hasher.js';
import type { RunningHash } from './hasher.js';

export class SignStream {
	private readonly suite: StreamableSignatureSuite;
	private readonly sk: Uint8Array;
	private readonly ctx: Uint8Array;
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

		if (ctx.length > USER_CTX_MAX)
			throw new SigningError(
				'sig-ctx-too-long',
				`user_ctx length ${ctx.length} > ${USER_CTX_MAX}`,
			);
		// Copy ctx so a later caller-side mutation cannot retroactively
		// change the bytes the preamble emits.
		this.ctx = new Uint8Array(ctx);

		this.hasher = createRunningHash(suite.prehashAlgorithm);
	}

	/**
	 * Build the wire-format preamble for a given payload length. Caller
	 * supplies the length they will write between the preamble and the
	 * signature, which lets the preamble carry the v3 envelope's
	 * `payload_len: u32 BE` field. Wire shape:
	 *   [suite_byte: u8][ctx_len: u8][ctx: ctx_len bytes][payload_len: u32 BE]
	 *
	 * Available at any point in the stream lifecycle (the bytes depend
	 * only on the constructor args plus the caller-supplied length).
	 */
	buildPreamble(payloadLength: number): Uint8Array {
		if (!Number.isInteger(payloadLength) || payloadLength < 0)
			throw new SigningError(
				'sig-malformed-input',
				`payloadLength must be a non-negative integer, got ${payloadLength}`,
			);
		if (payloadLength > 0xFFFFFFFF)
			throw new SigningError(
				'sig-malformed-input',
				`payloadLength ${payloadLength} > 2^32 - 1 (wire format payload_len is u32)`,
			);
		const out = new Uint8Array(2 + this.ctx.length + 4);
		let pos = 0;
		out[pos++] = this.suite.formatEnum;
		out[pos++] = this.ctx.length;
		out.set(this.ctx, pos); pos += this.ctx.length;
		out[pos++] = (payloadLength >>> 24) & 0xFF;
		out[pos++] = (payloadLength >>> 16) & 0xFF;
		out[pos++] = (payloadLength >>>  8) & 0xFF;
		out[pos]   =  payloadLength         & 0xFF;
		return out;
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
			return this.suite.signPrehashed(this.sk, digest, this.ctx);
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
		wipe(this.ctx);
	}
}
