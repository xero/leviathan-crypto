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
// test/unit/sign/sign-stream-equivalence.test.ts
//
// Byte-equivalence between Sign.sign output and SignStream's
// `preamble + msg + finalize()` for the same (suite, sk, msg, ctx).
// VerifyStream consumes both and returns the original payload.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import {
	Sign, SignStream, VerifyStream,
} from '../../../src/ts/sign/index.js';
import { concat } from '../../../src/ts/utils.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import {
	makeStreamableFixtureSuite, fixtureSk,
} from './helpers.js';

beforeAll(async () => {
	await init({ sha3: sha3Wasm });
});

function makeMsg(n: number): Uint8Array {
	const m = new Uint8Array(n);
	for (let i = 0; i < n; i++) m[i] = (i * 31 + 5) & 0xff;
	return m;
}

const MSG_SIZES = [0, 1, 1024, 100 * 1024];
// 255 = USER_CTX_MAX. The streamable fixture suite does not route through
// buildEffectiveCtx (its sign is a self-contained XOR), so the full
// USER_CTX_MAX range is exercisable here.
const CTX_SIZES = [0, 10, 255];

function ctxOf(n: number): Uint8Array {
	const c = new Uint8Array(n);
	for (let i = 0; i < n; i++) c[i] = (i + 0x40) & 0xff;
	return c;
}

describe('SignStream is byte-equivalent to Sign.sign', () => {
	for (const ctxLen of CTX_SIZES) {
		for (const msgLen of MSG_SIZES) {
			it(`ctx=${ctxLen} msg=${msgLen}`, () => {
				const suite = makeStreamableFixtureSuite();
				const sk = fixtureSk();
				const msg = makeMsg(msgLen);
				const ctx = ctxOf(ctxLen);

				const blobOneShot = Sign.sign(suite, sk, msg, ctx);

				const s = new SignStream(suite, sk, ctx);
				s.update(msg);
				const sig = s.finalize();
				const blobStream = concat(s.buildPreamble(msg.length), msg, sig);

				expect(Array.from(blobStream)).toEqual(Array.from(blobOneShot));
			});
		}
	}
});

describe('SignStream output verifies via both Sign.verify and VerifyStream', () => {
	for (const ctxLen of CTX_SIZES) {
		for (const msgLen of MSG_SIZES) {
			it(`ctx=${ctxLen} msg=${msgLen}`, () => {
				const suite = makeStreamableFixtureSuite();
				const sk = fixtureSk();
				const pk = fixtureSk();
				const msg = makeMsg(msgLen);
				const ctx = ctxOf(ctxLen);

				const s = new SignStream(suite, sk, ctx);
				s.update(msg);
				const sig = s.finalize();
				const blob = concat(s.buildPreamble(msg.length), msg, sig);

				// Sign.verify path
				const out1 = Sign.verify(suite, pk, blob, ctx);
				expect(Array.from(out1)).toEqual(Array.from(msg));

				// VerifyStream path
				const v = new VerifyStream(suite, pk, ctx);
				v.update(blob);
				const out2 = v.finalize();
				expect(Array.from(out2)).toEqual(Array.from(msg));
			});
		}
	}
});
