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
// src/ts/sign/envelope.ts
//
// Sign, single-shot signing/verification using the attached envelope wire
// format. Mirrors the static-only-class pattern from stream/seal.ts.
//
// Wire format:
//   [suite_byte: u8][ctx_len: u8][ctx: ctx_len bytes]
//   [payload: ...][sig: suite.sigSize bytes]
//
// Total: 2 + ctx_len + payload_len + suite.sigSize. Payload length is
// deduced from the blob length; there is no length prefix on sig because
// sigSize is catalog-known per suite.

import { constantTimeEqual } from '../utils.js';
import { SigningError } from '../errors.js';
import type { SignatureSuite } from './types.js';

// eslint-disable-next-line @typescript-eslint/no-extraneous-class
export class Sign {
	/**
	 * Single-shot sign. Returns the attached envelope blob.
	 */
	static sign(
		suite: SignatureSuite,
		sk: Uint8Array,
		msg: Uint8Array,
		ctx: Uint8Array,
	): Uint8Array {
		const sig = suite.sign(sk, msg, ctx);
		return assembleBlob(suite.formatEnum, ctx, msg, sig);
	}

	/**
	 * Single-shot verify. Returns the extracted payload on success.
	 *
	 * @throws SigningError('sig-blob-too-short')  blob < 2 + sigSize.
	 * @throws SigningError('sig-suite-mismatch')  wire suite_byte mismatch.
	 * @throws SigningError('sig-ctx-overflow')    ctx_len past sig boundary.
	 * @throws SigningError('sig-ctx-mismatch')    caller ctx != wire ctx.
	 * @throws SigningError('verify-failed')       suite.verify returned false.
	 */
	static verify(
		suite: SignatureSuite,
		pk: Uint8Array,
		blob: Uint8Array,
		ctx: Uint8Array,
	): Uint8Array {
		const minSize = 2 + suite.sigSize;
		if (blob.length < minSize)
			throw new SigningError(
				'sig-blob-too-short',
				`blob length ${blob.length} < min ${minSize}`,
			);
		const suiteByte = blob[0];
		if (suiteByte !== suite.formatEnum)
			throw new SigningError(
				'sig-suite-mismatch',
				`wire suite 0x${suiteByte.toString(16)} != suite.formatEnum 0x${suite.formatEnum.toString(16)}`,
			);
		const ctxLen = blob[1];
		const payloadEnd = blob.length - suite.sigSize;
		if (2 + ctxLen > payloadEnd)
			throw new SigningError(
				'sig-ctx-overflow',
				`ctx_len ${ctxLen} pushes past sig boundary`,
			);
		const wireCtx = blob.subarray(2, 2 + ctxLen);
		if (!constantTimeEqual(wireCtx, ctx))
			throw new SigningError('sig-ctx-mismatch');
		const payload = blob.subarray(2 + ctxLen, payloadEnd);
		const sig = blob.subarray(payloadEnd, blob.length);
		if (!suite.verify(pk, payload, sig, wireCtx))
			throw new SigningError('verify-failed');
		return payload;
	}

	/**
	 * Detached sign. Returns just the raw signature bytes (no envelope).
	 * Caller is responsible for transmitting (suite, msg, sig, ctx)
	 * out-of-band.
	 */
	static signDetached(
		suite: SignatureSuite,
		sk: Uint8Array,
		msg: Uint8Array,
		ctx: Uint8Array,
	): Uint8Array {
		return suite.sign(sk, msg, ctx);
	}

	/**
	 * Detached verify. Returns boolean; does NOT throw on signature failure.
	 * Contract violations in the suite (wrong-size key, ctx too long) still
	 * throw SigningError per the suite contract.
	 */
	static verifyDetached(
		suite: SignatureSuite,
		pk: Uint8Array,
		msg: Uint8Array,
		sig: Uint8Array,
		ctx: Uint8Array,
	): boolean {
		return suite.verify(pk, msg, sig, ctx);
	}

	/**
	 * Introspect a blob without verifying. Validates structural shape only
	 * (length and ctx_len in range); does NOT call suite.verify and does NOT
	 * compare ctx. Returns offsets the caller can use to extract wire ctx,
	 * payload, and sig themselves.
	 *
	 * @throws SigningError('sig-blob-too-short') blob < 2 + sigSize.
	 * @throws SigningError('sig-ctx-overflow')   ctx_len past sig boundary.
	 */
	static peek(blob: Uint8Array, suite: SignatureSuite): {
		suiteByte: number;
		ctx: Uint8Array;
		payloadOffset: number;
		payloadLength: number;
		sigOffset: number;
	} {
		const minSize = 2 + suite.sigSize;
		if (blob.length < minSize)
			throw new SigningError(
				'sig-blob-too-short',
				`blob length ${blob.length} < min ${minSize}`,
			);
		const suiteByte = blob[0];
		const ctxLen = blob[1];
		const sigOffset = blob.length - suite.sigSize;
		const payloadOffset = 2 + ctxLen;
		if (payloadOffset > sigOffset)
			throw new SigningError(
				'sig-ctx-overflow',
				`ctx_len ${ctxLen} pushes past sig boundary`,
			);
		return {
			suiteByte,
			ctx: blob.subarray(2, payloadOffset),
			payloadOffset,
			payloadLength: sigOffset - payloadOffset,
			sigOffset,
		};
	}
}

function assembleBlob(
	suiteByte: number,
	ctx: Uint8Array,
	payload: Uint8Array,
	sig: Uint8Array,
): Uint8Array {
	if (ctx.length > 255)
		throw new SigningError(
			'sig-ctx-too-long',
			`ctx length ${ctx.length} > 255 (wire format ctx_len is u8)`,
		);
	const out = new Uint8Array(1 + 1 + ctx.length + payload.length + sig.length);
	let pos = 0;
	out[pos++] = suiteByte;
	out[pos++] = ctx.length;
	out.set(ctx, pos); pos += ctx.length;
	out.set(payload, pos); pos += payload.length;
	out.set(sig, pos);
	return out;
}
