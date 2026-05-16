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
// test/unit/sign/sign-ed25519-vectors.test.ts
//
// Wire-format KAT replay for the Ed25519 suites. Loads
// test/vectors/sign_ed25519.ts (7 deterministic records covering
// Ed25519Suite and Ed25519PreHashSuite) and asserts that
// `Sign.sign(suite, sk, msg, ctx)` produces byte-identical envelope
// output to the recorded `blobHex`, that `Sign.verify` returns the
// expected payload, and that `Sign.peek` reports the documented
// offsets. Unlike ML-DSA, Ed25519 is deterministic in both modes per
// RFC 8032, so sign-side byte equality IS the gate (no separate hedged
// integration path needed for byte stability).

import { describe, it, expect, beforeAll } from 'vitest';
import { init, hexToBytes } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { WASM_GZ_BASE64 as curve25519Wasm } from '../../../src/ts/embedded/curve25519.js';
import { WASM_GZ_BASE64 as sha2Wasm } from '../../../src/ts/embedded/sha2.js';
import {
	Sign,
	Ed25519Suite, Ed25519PreHashSuite,
} from '../../../src/ts/sign/index.js';
import type { SignatureSuite } from '../../../src/ts/sign/index.js';
import {
	signEd25519Vectors,
} from '../../vectors/sign_ed25519.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ ed25519: curve25519Wasm, sha2: sha2Wasm });
});

const SUITE_BY_FORMAT: Record<number, SignatureSuite> = {
	0x01: Ed25519Suite,
	0x11: Ed25519PreHashSuite,
};

describe('sign_ed25519 KAT replay', () => {
	it('has 7 vectors covering pure and prehash modes', () => {
		expect(signEd25519Vectors.length).toBe(7);
		const formats = signEd25519Vectors.map((v) => v.formatEnum).sort();
		expect(formats).toEqual([0x01, 0x01, 0x01, 0x11, 0x11, 0x11, 0x11]);
	});

	it.each(signEd25519Vectors)(
		'$id $description: Sign.sign produces the recorded envelope bytes',
		(v) => {
			const suite = SUITE_BY_FORMAT[v.formatEnum];
			expect(suite).toBeDefined();
			const sk   = hexToBytes(v.skHex);
			const msg  = hexToBytes(v.msgHex);
			const ctx  = hexToBytes(v.ctxHex);
			const blob = Sign.sign(suite, sk, msg, ctx);
			expect(Array.from(blob)).toEqual(Array.from(hexToBytes(v.blobHex)));
		},
	);

	it.each(signEd25519Vectors)(
		'$id $description: Sign.verify returns the expected payload',
		(v) => {
			const suite = SUITE_BY_FORMAT[v.formatEnum];
			const pk   = hexToBytes(v.pkHex);
			const blob = hexToBytes(v.blobHex);
			const ctx  = hexToBytes(v.ctxHex);
			const msg  = hexToBytes(v.msgHex);
			const out  = Sign.verify(suite, pk, blob, ctx);
			expect(Array.from(out)).toEqual(Array.from(msg));
		},
	);

	it.each(signEd25519Vectors)(
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
