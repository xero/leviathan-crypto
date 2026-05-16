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
// test/unit/sign/sign-stream-equivalence-ed25519.test.ts
//
// Real-suite Sign-vs-SignStream byte-equivalence gate for the Ed25519
// prehash suite (0x11). Ed25519ph is deterministic per RFC 8032
// §5.1.7, so the buffered `Sign.sign(suite, sk, msg, ctx)` output
// MUST be byte-identical to `SignStream(suite, sk, ctx).update(...).finalize()`
// over the same content. Also confirms VerifyStream accepts both and
// rejects mid-stream tampered payload.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, concat } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { WASM_GZ_BASE64 as curve25519Wasm } from '../../../src/ts/embedded/curve25519.js';
import { WASM_GZ_BASE64 as sha2Wasm } from '../../../src/ts/embedded/sha2.js';
import {
	Sign, SignStream, VerifyStream,
	Ed25519PreHashSuite,
} from '../../../src/ts/sign/index.js';
import { SigningError } from '../../../src/ts/errors.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ ed25519: curve25519Wasm, sha2: sha2Wasm });
});

function makeMsg(n: number): Uint8Array {
	const m = new Uint8Array(n);
	for (let i = 0; i < n; i++) m[i] = (i * 31 + 5) & 0xff;
	return m;
}

function ctxOf(n: number): Uint8Array {
	const c = new Uint8Array(n);
	for (let i = 0; i < n; i++) c[i] = (i + 0x40) & 0xff;
	return c;
}

const MSG_SIZES = [0, 1, 100, 10000];
const CTX_SIZES = [0, 10, 200];

describe('SignStream byte-equivalent to Sign.sign (Ed25519PreHashSuite)', () => {
	for (const ctxLen of CTX_SIZES) {
		for (const msgLen of MSG_SIZES) {
			it(`ctx=${ctxLen} msg=${msgLen}`, () => {
				const { sk } = Ed25519PreHashSuite.keygen();
				const msg = makeMsg(msgLen);
				const ctx = ctxOf(ctxLen);

				const blobOneShot = Sign.sign(Ed25519PreHashSuite, sk, msg, ctx);

				const s = new SignStream(Ed25519PreHashSuite, sk, ctx);
				let blobStream: Uint8Array;
				try {
					s.update(msg);
					const sig = s.finalize();
					blobStream = concat(s.preamble, msg, sig);
				} finally {
					s.dispose();
				}
				expect(Array.from(blobStream)).toEqual(Array.from(blobOneShot));
			});
		}
	}
});

describe('SignStream chunked vs one-shot byte-equivalence', () => {
	it('chunking the message in 5 pieces produces byte-identical output', () => {
		const { sk } = Ed25519PreHashSuite.keygen();
		const msg = makeMsg(523);  // not a multiple of any block size
		const ctx = ctxOf(13);

		const blobOneShot = Sign.sign(Ed25519PreHashSuite, sk, msg, ctx);

		const s = new SignStream(Ed25519PreHashSuite, sk, ctx);
		let blobStream: Uint8Array;
		try {
			s.update(msg.subarray(0, 7));
			s.update(msg.subarray(7, 99));
			s.update(msg.subarray(99, 250));
			s.update(msg.subarray(250, 499));
			s.update(msg.subarray(499));
			const sig = s.finalize();
			blobStream = concat(s.preamble, msg, sig);
		} finally {
			s.dispose();
		}
		expect(Array.from(blobStream)).toEqual(Array.from(blobOneShot));
	});
});

describe('VerifyStream round-trip and tamper rejection', () => {
	it('VerifyStream accepts the streamed blob and returns the payload', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const msg = makeMsg(256);
		const ctx = ctxOf(20);
		const blob = Sign.sign(Ed25519PreHashSuite, sk, msg, ctx);
		const v = new VerifyStream(Ed25519PreHashSuite, pk, ctx);
		try {
			v.update(blob);
			const out = v.finalize();
			expect(Array.from(out)).toEqual(Array.from(msg));
		} finally {
			v.dispose();
		}
	});

	it('VerifyStream rejects a mid-stream byte flip', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const msg = makeMsg(256);
		const ctx = ctxOf(20);
		const blob = Sign.sign(Ed25519PreHashSuite, sk, msg, ctx);
		const tampered = blob.slice();
		// Flip a byte well inside the payload (after header, before sig).
		const payloadStart = 2 + ctx.length;
		tampered[payloadStart + 7] ^= 0x80;

		const v = new VerifyStream(Ed25519PreHashSuite, pk, ctx);
		let caught: unknown;
		try {
			v.update(tampered);
			v.finalize();
		} catch (e) {
			caught = e;
		} finally {
			v.dispose();
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('verify-failed');
	});
});
