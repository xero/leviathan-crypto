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
// Wire format see: docs/signing.md#attached-envelope.

import { constantTimeEqual } from '../utils.js';
import { SigningError } from '../errors.js';
import type { SignatureSuite } from './types.js';

// 1 suite_byte + 1 ctx_len + 4 payload_len. Smallest legal blob carries
// at least these six header bytes plus the suite's sig.
const ENVELOPE_HEADER_FIXED = 6;

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
	 * @throws SigningError('sig-blob-too-short')  blob cannot fit the wire shape.
	 * @throws SigningError('sig-suite-mismatch')  wire suite_byte mismatch.
	 * @throws SigningError('sig-ctx-mismatch')    caller ctx != wire ctx.
	 * @throws SigningError('verify-failed')       suite.verify returned false.
	 */
	static verify(
		suite: SignatureSuite,
		pk: Uint8Array,
		blob: Uint8Array,
		ctx: Uint8Array,
	): Uint8Array {
		const { suiteByte, ctxLen, payloadLen, payloadOffset, sigOffset }
			= parseHeader(blob, suite);
		if (suiteByte !== suite.formatEnum)
			throw new SigningError(
				'sig-suite-mismatch',
				`wire suite 0x${suiteByte.toString(16)} != suite.formatEnum 0x${suite.formatEnum.toString(16)}`,
			);
		const wireCtx = blob.subarray(2, 2 + ctxLen);
		if (!constantTimeEqual(wireCtx, ctx))
			throw new SigningError('sig-ctx-mismatch');
		const payload = blob.subarray(payloadOffset, payloadOffset + payloadLen);
		const sig = blob.subarray(sigOffset, blob.length);
		if (!suite.verify(pk, payload, sig, wireCtx))
			throw new SigningError('verify-failed');
		return payload;
	}

	/**
	 * Detached sign. Returns just the raw signature bytes (no envelope).
	 * Caller is responsible for transmitting (suite, msg, sig, ctx)
	 * out-of-band. signDetached is the interop surface; the wire is
	 * exactly what the underlying primitive emits, no leviathan-specific
	 * framing.
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
	 * (ctx_len and payload_len in range); does NOT call suite.verify and
	 * does NOT compare ctx. Returns offsets the caller can use to extract
	 * wire ctx, payload, and sig themselves.
	 *
	 * @throws SigningError('sig-blob-too-short') blob cannot fit the wire shape.
	 */
	static peek(blob: Uint8Array, suite: SignatureSuite): {
		suiteByte: number;
		ctx: Uint8Array;
		payloadOffset: number;
		payloadLength: number;
		sigOffset: number;
	} {
		const { suiteByte, ctxLen, payloadLen, payloadOffset, sigOffset }
			= parseHeader(blob, suite);
		return {
			suiteByte,
			ctx: blob.subarray(2, 2 + ctxLen),
			payloadOffset,
			payloadLength: payloadLen,
			sigOffset,
		};
	}
}

/**
 * Parse the wire header. Throws SigningError('sig-blob-too-short')
 * on every wire-shape overflow; .message carries the specifics.
 */
function parseHeader(blob: Uint8Array, suite: SignatureSuite): {
	suiteByte: number;
	ctxLen: number;
	payloadLen: number;
	payloadOffset: number;
	sigOffset: number;
} {
	if (blob.length < ENVELOPE_HEADER_FIXED)
		throw new SigningError(
			'sig-blob-too-short',
			`blob length ${blob.length} < min ${ENVELOPE_HEADER_FIXED} (suite + ctx_len + payload_len header)`,
		);
	const suiteByte = blob[0];
	const ctxLen    = blob[1];
	const payloadLenOffset = 2 + ctxLen;
	const payloadOffset    = payloadLenOffset + 4;
	if (blob.length < payloadOffset)
		throw new SigningError(
			'sig-blob-too-short',
			`blob length ${blob.length} cannot fit ctx (${ctxLen} bytes) + payload_len header`,
		);
	const payloadLen = readU32BE(blob, payloadLenOffset);
	const sigOffset  = payloadOffset + payloadLen;
	if (sigOffset > blob.length)
		throw new SigningError(
			'sig-blob-too-short',
			`payload_len ${payloadLen} pushes payload past blob end (blob length ${blob.length})`,
		);
	if (sigOffset + suite.sigMaxSize < blob.length)
		throw new SigningError(
			'sig-blob-too-short',
			`trailing sig ${blob.length - sigOffset} > suite.sigMaxSize ${suite.sigMaxSize}`,
		);
	return { suiteByte, ctxLen, payloadLen, payloadOffset, sigOffset };
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
	if (payload.length > 0xFFFFFFFF)
		throw new SigningError(
			'sig-malformed-input',
			`payload length ${payload.length} > 2^32 - 1 (wire format payload_len is u32)`,
		);
	const out = new Uint8Array(
		2 + ctx.length + 4 + payload.length + sig.length,
	);
	let pos = 0;
	out[pos++] = suiteByte;
	out[pos++] = ctx.length;
	out.set(ctx, pos); pos += ctx.length;
	writeU32BE(out, pos, payload.length); pos += 4;
	out.set(payload, pos); pos += payload.length;
	out.set(sig, pos);
	return out;
}

function readU32BE(buf: Uint8Array, off: number): number {
	// Multiply by 2^24 instead of <<24 so the high byte does not
	// sign-extend into a negative JS number, which would propagate
	// through the subsequent arithmetic and silently bypass the
	// payload-overflow check.
	return (
		buf[off] * 0x1000000
		+ ((buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3])
	);
}

function writeU32BE(buf: Uint8Array, off: number, value: number): void {
	buf[off]     = (value >>> 24) & 0xFF;
	buf[off + 1] = (value >>> 16) & 0xFF;
	buf[off + 2] = (value >>>  8) & 0xFF;
	buf[off + 3] =  value         & 0xFF;
}
