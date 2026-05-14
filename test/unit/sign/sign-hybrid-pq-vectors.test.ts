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
// test/unit/sign/sign-hybrid-pq-vectors.test.ts
//
// KAT replay against test/vectors/sign_hybrid_pq.ts. Loads the three
// composite vectors (one per hybrid format byte) and asserts that
// Sign.verify returns the expected payload and Sign.peek reports the
// expected offsets. The composite signature bytes themselves are
// byte-stable under the deterministic sub-sign path used by the
// generator (scripts/gen-hybrid-pq-vectors.ts), but suite.sign is hedged,
// so this file does NOT compare regenerated sigs.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, hexToBytes } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm }  from '../../../src/ts/mldsa/embedded.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import {
	Sign,
	MlDsa44SlhDsa128fSuite,
	MlDsa65SlhDsa192fSuite,
	MlDsa87SlhDsa256fSuite,
} from '../../../src/ts/sign/index.js';
import type { SignatureSuite } from '../../../src/ts/sign/index.js';
import { signHybridPqVectors } from '../../vectors/sign_hybrid_pq.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, slhdsa: slhdsaWasm, sha3: sha3Wasm });
});

const SUITE_BY_FORMAT: Record<number, SignatureSuite> = {
	0x30: MlDsa44SlhDsa128fSuite,
	0x31: MlDsa65SlhDsa192fSuite,
	0x32: MlDsa87SlhDsa256fSuite,
};

describe('sign_hybrid_pq KAT replay', () => {
	it('has three vectors covering the three hybrid format bytes', () => {
		expect(signHybridPqVectors.length).toBe(3);
		const formats = signHybridPqVectors.map((v) => v.formatEnum).sort((a, b) => a - b);
		expect(formats).toEqual([0x30, 0x31, 0x32]);
	});

	it.each(signHybridPqVectors)(
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

	it.each(signHybridPqVectors)(
		'$id $description: Sign.peek matches structural offsets',
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

	it.each(signHybridPqVectors)(
		'$id $description: catalog sizes match the recorded pk/sk/sig',
		(v) => {
			const suite = SUITE_BY_FORMAT[v.formatEnum];
			const pk = hexToBytes(v.pkHex);
			const sk = hexToBytes(v.skHex);
			const blob = hexToBytes(v.blobHex);
			const msg  = hexToBytes(v.msgHex);
			const ctx  = hexToBytes(v.ctxHex);
			expect(pk.length).toBe(suite.pkSize);
			expect(sk.length).toBe(suite.skSize);
			expect(blob.length).toBe(2 + ctx.length + msg.length + suite.sigSize);
		},
	);
});
