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
// test/unit/sign/sign-mldsa-vectors.test.ts
//
// Wire-format KAT replay for the v3 sign envelope. Loads
// test/vectors/sign_mldsa.ts (three deterministic vectors covering
// MlDsa{44,65,87}PreHashSuite) and asserts that Sign.verify returns the
// expected payload and Sign.peek returns the expected offsets. The
// production suite.sign path is hedged, so this file does NOT compare
// regenerated sig bytes; the integration test covers hedged-produce-then
// -verify, and these vectors lock the wire bytes for verifiers.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, hexToBytes } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }  from '../../../src/ts/sha3/embedded.js';
import {
	Sign,
	MlDsa44PreHashSuite, MlDsa65PreHashSuite, MlDsa87PreHashSuite,
} from '../../../src/ts/sign/index.js';
import type { StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import { signMldsaVectors } from '../../vectors/sign_mldsa.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm });
});

const SUITE_BY_FORMAT: Record<number, StreamableSignatureSuite> = {
	0x13: MlDsa44PreHashSuite,
	0x14: MlDsa65PreHashSuite,
	0x15: MlDsa87PreHashSuite,
};

describe('sign_mldsa KAT replay', () => {
	it('has three vectors covering all three threat levels', () => {
		expect(signMldsaVectors.length).toBe(3);
		const formats = signMldsaVectors.map((v) => v.formatEnum).sort();
		expect(formats).toEqual([0x13, 0x14, 0x15]);
	});

	it.each(signMldsaVectors)(
		'$id $description: Sign.verify returns the expected payload',
		(v) => {
			const suite = SUITE_BY_FORMAT[v.formatEnum];
			expect(suite).toBeDefined();
			const pk   = hexToBytes(v.pkHex);
			const blob = hexToBytes(v.blobHex);
			const ctx  = hexToBytes(v.ctxHex);
			const msg  = hexToBytes(v.msgHex);
			const out  = Sign.verify(suite, pk, blob, ctx);
			expect(out).toEqual(msg);
		},
	);

	it.each(signMldsaVectors)(
		'$id $description: Sign.peek returns expected offsets',
		(v) => {
			const suite = SUITE_BY_FORMAT[v.formatEnum];
			const blob  = hexToBytes(v.blobHex);
			const ctx   = hexToBytes(v.ctxHex);
			const msg   = hexToBytes(v.msgHex);
			const peek  = Sign.peek(blob, suite);
			expect(peek.suiteByte).toBe(v.formatEnum);
			expect(peek.payloadLength).toBe(msg.length);
			expect(Array.from(peek.ctx)).toEqual(Array.from(ctx));
			expect(peek.payloadOffset).toBe(2 + ctx.length);
			expect(peek.sigOffset).toBe(blob.length - suite.sigSize);
		},
	);
});
