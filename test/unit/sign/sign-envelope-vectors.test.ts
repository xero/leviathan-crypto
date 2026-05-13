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
// test/unit/sign/sign-envelope-vectors.test.ts
//
// Wire-format gate for the v3 sign envelope. Asserts byte-equality
// between hand-assembled blob hex (test/vectors/sign_envelope.ts) and
// Sign.sign output. Uses the deterministic fixture suite so the gate
// is independent of any real cryptographic primitive.

import { describe, it, expect } from 'vitest';
import { Sign } from '../../../src/ts/sign/index.js';
import { hexToBytes, bytesToHex } from '../../../src/ts/utils.js';
import {
	signEnvelopeVectors,
	FIXTURE_SK_HEX,
} from '../../vectors/sign_envelope.js';
import { makeFixtureSuite, FIXTURE_FORMAT_ENUM } from './helpers.js';

describe('Sign envelope wire-format vectors', () => {
	for (const v of signEnvelopeVectors) {
		it(v.description, () => {
			expect(v.formatEnum).toBe(FIXTURE_FORMAT_ENUM);
			const sk = hexToBytes(FIXTURE_SK_HEX);
			const ctx = hexToBytes(v.ctxHex);
			const msg = hexToBytes(v.payloadHex);
			const expectedSig = hexToBytes(v.sigHex);
			const expectedBlob = hexToBytes(v.expectedBlobHex);
			const suite = makeFixtureSuite();
			const blob = Sign.sign(suite, sk, msg, ctx);
			expect(bytesToHex(blob)).toBe(v.expectedBlobHex);
			expect(blob).toEqual(expectedBlob);

			const peek = Sign.peek(blob, suite);
			expect(peek.suiteByte).toBe(v.formatEnum);
			expect(peek.ctx).toEqual(ctx);
			expect(peek.payloadLength).toBe(msg.length);
			expect(blob.subarray(peek.payloadOffset, peek.sigOffset)).toEqual(msg);
			expect(blob.subarray(peek.sigOffset)).toEqual(expectedSig);

			const out = Sign.verify(suite, sk, blob, ctx);
			expect(out).toEqual(msg);
		});
	}
});
