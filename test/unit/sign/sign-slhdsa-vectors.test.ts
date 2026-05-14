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
// test/unit/sign/sign-slhdsa-vectors.test.ts
//
// Wire-format KAT replay for the v3 sign envelope. Loads
// test/vectors/sign_slhdsa.ts (six deterministic vectors covering
// SlhDsa{128f,192f,256f}Suite and their PreHash counterparts) and asserts
// that Sign.verify returns the expected payload and Sign.peek returns
// the expected offsets. The production suite.sign path is hedged, so
// this file does NOT compare regenerated sig bytes; the integration
// test covers hedged-produce-then-verify, and these vectors lock the
// wire bytes for verifiers.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, hexToBytes } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import {
	Sign,
	SlhDsa128fSuite, SlhDsa192fSuite, SlhDsa256fSuite,
	SlhDsa128fPreHashSuite, SlhDsa192fPreHashSuite, SlhDsa256fPreHashSuite,
} from '../../../src/ts/sign/index.js';
import type { SignatureSuite } from '../../../src/ts/sign/index.js';
import { signSlhdsaVectors } from '../../vectors/sign_slhdsa.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ slhdsa: slhdsaWasm, sha3: sha3Wasm });
});

const SUITE_BY_FORMAT: Record<number, SignatureSuite> = {
	0x06: SlhDsa128fSuite,
	0x07: SlhDsa192fSuite,
	0x08: SlhDsa256fSuite,
	0x16: SlhDsa128fPreHashSuite,
	0x17: SlhDsa192fPreHashSuite,
	0x18: SlhDsa256fPreHashSuite,
};

describe('sign_slhdsa KAT replay', () => {
	it('has six vectors covering pure + prehash across all three threat levels', () => {
		expect(signSlhdsaVectors.length).toBe(6);
		const formats = signSlhdsaVectors.map((v) => v.formatEnum).sort((a, b) => a - b);
		expect(formats).toEqual([0x06, 0x07, 0x08, 0x16, 0x17, 0x18]);
	});

	it.each(signSlhdsaVectors)(
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

	it.each(signSlhdsaVectors)(
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
