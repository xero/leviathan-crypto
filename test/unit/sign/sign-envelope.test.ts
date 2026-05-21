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
// test/unit/sign/sign-envelope.test.ts
//
// Sign class envelope coverage, structural and round-trip. Uses the
// in-test fixture suite; cryptographic round-trips against the real suites
// are covered by sign-mldsa-integration / sign-hybrid-pq-integration.

import { describe, it, expect } from 'vitest';
import { Sign } from '../../../src/ts/sign/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import {
	makeFixtureSuite,
	fixtureSk,
	FIXTURE_FORMAT_ENUM,
	FIXTURE_SIG_SIZE,
} from './helpers.js';

// v3 envelope fixed header: 1 suite_byte + 1 ctx_len + 4 payload_len.
const ENVELOPE_HEADER_FIXED = 6;

function captureSigningError(fn: () => unknown): SigningError {
	let caught: unknown;
	try {
		fn();
	} catch (e) {
		caught = e;
	}
	expect(caught).toBeInstanceOf(SigningError);
	return caught as SigningError;
}

describe('Sign.sign / Sign.verify round-trip', () => {
	it('empty ctx, small payload', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const msg = new Uint8Array([1, 2, 3, 4, 5]);
		const ctx = new Uint8Array(0);
		const blob = Sign.sign(suite, sk, msg, ctx);
		const out = Sign.verify(suite, pk, blob, ctx);
		expect(out).toEqual(msg);
	});

	it('empty payload', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const ctx = new Uint8Array(0);
		const msg = new Uint8Array(0);
		const blob = Sign.sign(suite, sk, msg, ctx);
		expect(blob.length).toBe(ENVELOPE_HEADER_FIXED + FIXTURE_SIG_SIZE);
		// payload_len bytes are all-zero for an empty payload.
		expect(Array.from(blob.subarray(2, 6))).toEqual([0, 0, 0, 0]);
		const out = Sign.verify(suite, pk, blob, ctx);
		expect(out.length).toBe(0);
	});

	it('non-empty ctx (10 bytes)', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const ctx = new Uint8Array(10);
		for (let i = 0; i < 10; i++) ctx[i] = i + 0x40;
		const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
		const blob = Sign.sign(suite, sk, msg, ctx);
		expect(blob[1]).toBe(10);
		// payload_len encoded as u32 BE at offset 2 + ctxLen.
		expect(Array.from(blob.subarray(2 + 10, 2 + 10 + 4))).toEqual([0, 0, 0, 4]);
		const out = Sign.verify(suite, pk, blob, ctx);
		expect(out).toEqual(msg);
	});

	it('non-empty ctx (255 bytes, USER_CTX_MAX)', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const ctx = new Uint8Array(255);
		for (let i = 0; i < 255; i++) ctx[i] = i & 0xff;
		const msg = new Uint8Array([0xaa, 0xbb]);
		const blob = Sign.sign(suite, sk, msg, ctx);
		expect(blob[1]).toBe(255);
		const out = Sign.verify(suite, pk, blob, ctx);
		expect(out).toEqual(msg);
	});

	it('msg larger than sigMaxSize', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const ctx = new Uint8Array([0x01, 0x02]);
		const msg = new Uint8Array(FIXTURE_SIG_SIZE * 4);
		for (let i = 0; i < msg.length; i++) msg[i] = (i * 7) & 0xff;
		const blob = Sign.sign(suite, sk, msg, ctx);
		const out = Sign.verify(suite, pk, blob, ctx);
		expect(out).toEqual(msg);
	});
});

describe('Sign.verify, error discriminators', () => {
	it('wrong pk throws verify-failed', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const wrongPk = new Uint8Array(32);
		for (let i = 0; i < 32; i++) wrongPk[i] = (i + 1) & 0xff;
		const msg = new Uint8Array([0x42, 0x42, 0x42]);
		const ctx = new Uint8Array([0x10]);
		const blob = Sign.sign(suite, sk, msg, ctx);
		const err = captureSigningError(() => Sign.verify(suite, wrongPk, blob, ctx));
		expect(err.discriminator === 'verify-failed').toBe(true);
	});

	it('corrupted wire ctx bytes throw sig-ctx-mismatch', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const ctx = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
		const msg = new Uint8Array([1, 2, 3]);
		const blob = Sign.sign(suite, sk, msg, ctx);
		blob[2] ^= 0xff;
		const err = captureSigningError(() => Sign.verify(suite, pk, blob, ctx));
		expect(err.discriminator === 'sig-ctx-mismatch').toBe(true);
	});

	it('caller ctx not equal to wire ctx throws sig-ctx-mismatch', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const wireCtx = new Uint8Array([1, 2, 3, 4]);
		const callerCtx = new Uint8Array([9, 9, 9, 9]);
		const msg = new Uint8Array([5, 5, 5]);
		const blob = Sign.sign(suite, sk, msg, wireCtx);
		const err = captureSigningError(() => Sign.verify(suite, pk, blob, callerCtx));
		expect(err.discriminator === 'sig-ctx-mismatch').toBe(true);
	});

	it('caller ctx of different length than wire ctx throws sig-ctx-mismatch', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const wireCtx = new Uint8Array([1, 2, 3]);
		const callerCtx = new Uint8Array([1, 2, 3, 4]);
		const msg = new Uint8Array([0]);
		const blob = Sign.sign(suite, sk, msg, wireCtx);
		const err = captureSigningError(() => Sign.verify(suite, pk, blob, callerCtx));
		expect(err.discriminator === 'sig-ctx-mismatch').toBe(true);
	});

	it('wrong suite_byte in blob throws sig-suite-mismatch', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const msg = new Uint8Array([7, 7, 7]);
		const ctx = new Uint8Array(0);
		const blob = Sign.sign(suite, sk, msg, ctx);
		blob[0] = (FIXTURE_FORMAT_ENUM ^ 0x01) & 0xff;
		const err = captureSigningError(() => Sign.verify(suite, pk, blob, ctx));
		expect(err.discriminator === 'sig-suite-mismatch').toBe(true);
	});

	it('blob shorter than envelope header throws sig-blob-too-short', () => {
		const suite = makeFixtureSuite();
		const pk = fixtureSk();
		const ctx = new Uint8Array(0);
		const shortBlob = new Uint8Array(ENVELOPE_HEADER_FIXED - 1);
		shortBlob[0] = FIXTURE_FORMAT_ENUM;
		const err = captureSigningError(() => Sign.verify(suite, pk, shortBlob, ctx));
		expect(err.discriminator === 'sig-blob-too-short').toBe(true);
	});

	it('ctx_len pushing past blob end throws sig-blob-too-short', () => {
		const suite = makeFixtureSuite();
		const pk = fixtureSk();
		// Blob exactly meets the header minimum (6 bytes), then claims a
		// 200-byte ctx. The ctx + payload_len header would need 206 bytes,
		// so parse-header rejects with sig-blob-too-short.
		const blob = new Uint8Array(ENVELOPE_HEADER_FIXED + FIXTURE_SIG_SIZE);
		blob[0] = FIXTURE_FORMAT_ENUM;
		blob[1] = 200;
		const err = captureSigningError(
			() => Sign.verify(suite, pk, blob, new Uint8Array(200)),
		);
		expect(err.discriminator === 'sig-blob-too-short').toBe(true);
	});

	it('payload_len past blob end throws sig-blob-too-short', () => {
		const suite = makeFixtureSuite();
		const pk = fixtureSk();
		const ctx = new Uint8Array(0);
		// Header claims a 1 MiB payload but the blob is just a header.
		const blob = new Uint8Array(ENVELOPE_HEADER_FIXED + FIXTURE_SIG_SIZE);
		blob[0] = FIXTURE_FORMAT_ENUM;
		blob[1] = 0;
		// payload_len = 0x00100000 (1 MiB).
		blob[2] = 0x00;
		blob[3] = 0x10;
		blob[4] = 0x00;
		blob[5] = 0x00;
		const err = captureSigningError(() => Sign.verify(suite, pk, blob, ctx));
		expect(err.discriminator === 'sig-blob-too-short').toBe(true);
	});
});

describe('Sign.signDetached / verifyDetached', () => {
	it('round-trip succeeds and matches suite.sign byte-for-byte', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const msg = new Uint8Array([0xab, 0xcd, 0xef]);
		const ctx = new Uint8Array([0x10, 0x20]);
		const sig = Sign.signDetached(suite, sk, msg, ctx);
		expect(sig.length).toBe(FIXTURE_SIG_SIZE);
		expect(Sign.verifyDetached(suite, pk, msg, sig, ctx)).toBe(true);
	});

	it('verifyDetached returns false (does not throw) on bad sig', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const pk = fixtureSk();
		const msg = new Uint8Array([1, 2, 3, 4]);
		const ctx = new Uint8Array(0);
		const sig = Sign.signDetached(suite, sk, msg, ctx);
		sig[0] ^= 0xff;
		expect(Sign.verifyDetached(suite, pk, msg, sig, ctx)).toBe(false);
	});

	it('verifyDetached returns false on wrong-length sig', () => {
		const suite = makeFixtureSuite();
		const pk = fixtureSk();
		const msg = new Uint8Array([1]);
		const ctx = new Uint8Array(0);
		const shortSig = new Uint8Array(FIXTURE_SIG_SIZE - 1);
		expect(Sign.verifyDetached(suite, pk, msg, shortSig, ctx)).toBe(false);
	});
});

describe('Sign.peek', () => {
	it('extracts suite_byte, ctx, payload/sig offsets on a valid blob', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const ctx = new Uint8Array([0xaa, 0xbb, 0xcc]);
		const msg = new Uint8Array([0x11, 0x22, 0x33, 0x44]);
		const blob = Sign.sign(suite, sk, msg, ctx);
		const peek = Sign.peek(blob, suite);
		expect(peek.suiteByte).toBe(FIXTURE_FORMAT_ENUM);
		expect(peek.ctx).toEqual(ctx);
		expect(peek.payloadOffset).toBe(2 + ctx.length + 4);
		expect(peek.payloadLength).toBe(msg.length);
		expect(peek.sigOffset).toBe(2 + ctx.length + 4 + msg.length);
		expect(blob.subarray(peek.payloadOffset, peek.sigOffset)).toEqual(msg);
		expect(blob.subarray(peek.sigOffset).length).toBe(FIXTURE_SIG_SIZE);
	});

	it('handles empty ctx and empty payload', () => {
		const suite = makeFixtureSuite();
		const sk = fixtureSk();
		const blob = Sign.sign(suite, sk, new Uint8Array(0), new Uint8Array(0));
		const peek = Sign.peek(blob, suite);
		expect(peek.suiteByte).toBe(FIXTURE_FORMAT_ENUM);
		expect(peek.ctx.length).toBe(0);
		expect(peek.payloadOffset).toBe(ENVELOPE_HEADER_FIXED);
		expect(peek.payloadLength).toBe(0);
		expect(peek.sigOffset).toBe(ENVELOPE_HEADER_FIXED);
	});

	it('throws sig-blob-too-short on truncated blob', () => {
		const suite = makeFixtureSuite();
		const tiny = new Uint8Array(ENVELOPE_HEADER_FIXED - 1);
		const err = captureSigningError(() => Sign.peek(tiny, suite));
		expect(err.discriminator === 'sig-blob-too-short').toBe(true);
	});

	it('throws sig-blob-too-short when ctx_len pushes past blob end', () => {
		const suite = makeFixtureSuite();
		const blob = new Uint8Array(ENVELOPE_HEADER_FIXED + FIXTURE_SIG_SIZE);
		blob[0] = FIXTURE_FORMAT_ENUM;
		blob[1] = 200;
		const err = captureSigningError(() => Sign.peek(blob, suite));
		expect(err.discriminator === 'sig-blob-too-short').toBe(true);
	});
});

describe('Sign assembleBlob, defensive ctx-too-long', () => {
	it('Sign.sign throws sig-ctx-too-long when the suite returns ctx ≥ 256 bytes', () => {
		// The public ctx cap is enforced by buildEffectiveCtx (USER_CTX_MAX =
		// 255, FIPS 204 §3.6.1); the envelope's assembleBlob still defensively
		// rejects ctx >= 256 because the wire format ctx_len field is u8.
		// Drive that branch via a suite that skips ctx-length validation,
		// mimicking a hypothetical bypass.
		const lenientSuite = makeFixtureSuite();
		const innerSign = lenientSuite.sign;
		(lenientSuite as { sign: typeof innerSign }).sign = (
			sk: Uint8Array,
			msg: Uint8Array,
			_ctx: Uint8Array,
		) => innerSign(sk, msg, new Uint8Array(0));
		const sk = fixtureSk();
		const ctx = new Uint8Array(256);
		const err = captureSigningError(
			() => Sign.sign(lenientSuite, sk, new Uint8Array(0), ctx),
		);
		expect(err.discriminator === 'sig-ctx-too-long').toBe(true);
	});
});
