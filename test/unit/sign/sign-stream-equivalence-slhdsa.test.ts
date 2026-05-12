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
// test/unit/sign/sign-stream-equivalence-slhdsa.test.ts
//
// Real-suite Sign-vs-SignStream byte-equivalence gate for the three
// SLH-DSA prehash suites (0x16 / 0x17 / 0x18). The fixture-suite version
// in sign-stream-equivalence.test.ts exercises the wire-format path; this
// file exercises the real SHAKE prehash + SLH-DSA sub-sign path. Hedged
// `sign` cannot be byte-compared, so the gate is driven on a deterministic
// signature path: a buffered digest from single-shot SHAKE128/256 and a
// streamed digest from SHAKE128Stream/SHAKE256Stream are fed through the
// same `signHashPrehashedDeterministic` entry; the produced sigs must be
// byte-identical, and the assembled envelope blob must round-trip
// through Sign.verify and VerifyStream.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import {
	Sign, VerifyStream,
	SlhDsa128fPreHashSuite, SlhDsa192fPreHashSuite, SlhDsa256fPreHashSuite,
} from '../../../src/ts/sign/index.js';
import type { StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import {
	SlhDsa128f, SlhDsa192f, SlhDsa256f,
} from '../../../src/ts/slhdsa/index.js';
import {
	SHAKE128, SHAKE256, SHAKE128Stream, SHAKE256Stream,
} from '../../../src/ts/sha3/index.js';
import { concat } from '../../../src/ts/utils.js';
import { buildEffectiveCtx } from '../../../src/ts/sign/ctx.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ slhdsa: slhdsaWasm, sha3: sha3Wasm });
});

type SlhClass = typeof SlhDsa128f | typeof SlhDsa192f | typeof SlhDsa256f;

interface Case {
	name:        string;
	suite:       StreamableSignatureSuite;
	SlhDsaClass: SlhClass;
	prehash:     'SHAKE128' | 'SHAKE256';
}

const CASES: Case[] = [
	{
		name: 'SlhDsa128fPreHashSuite',
		suite: SlhDsa128fPreHashSuite,
		SlhDsaClass: SlhDsa128f,
		prehash: 'SHAKE128',
	},
	{
		name: 'SlhDsa192fPreHashSuite',
		suite: SlhDsa192fPreHashSuite,
		SlhDsaClass: SlhDsa192f,
		prehash: 'SHAKE256',
	},
	{
		name: 'SlhDsa256fPreHashSuite',
		suite: SlhDsa256fPreHashSuite,
		SlhDsaClass: SlhDsa256f,
		prehash: 'SHAKE256',
	},
];

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

function shakeOneShot(prehash: 'SHAKE128' | 'SHAKE256', msg: Uint8Array, outLen: number): Uint8Array {
	if (prehash === 'SHAKE128') {
		const h = new SHAKE128();
		try {
			return h.hash(msg, outLen);
		} finally {
			h.dispose();
		}
	}
	const h = new SHAKE256();
	try {
		return h.hash(msg, outLen);
	} finally {
		h.dispose();
	}
}

function shakeStreamed(prehash: 'SHAKE128' | 'SHAKE256', chunks: Uint8Array[], outLen: number): Uint8Array {
	if (prehash === 'SHAKE128') {
		const h = new SHAKE128Stream(outLen);
		try {
			for (const c of chunks) h.update(c);
			return h.finalize();
		} finally {
			h.dispose();
		}
	}
	const h = new SHAKE256Stream(outLen);
	try {
		for (const c of chunks) h.update(c);
		return h.finalize();
	} finally {
		h.dispose();
	}
}

// Keep the matrix small: real SLH-DSA sign is heavy (~100ms for 256f). Cover
// the boundary inputs (empty, small, USER_CTX_MAX-200) without sweeping every
// combo the fixture-suite test does.
const MSG_SIZES = [0, 1024];
const CTX_SIZES = [0, 200];

describe('SignStream byte-equivalent to buffered sign under deterministic sub-sign', () => {
	for (const c of CASES) {
		for (const msgLen of MSG_SIZES) {
			for (const ctxLen of CTX_SIZES) {
				it(`${c.name} msg=${msgLen} ctx=${ctxLen}`, () => {
					const msg = makeMsg(msgLen);
					const ctx = ctxOf(ctxLen);
					const effectiveCtx = buildEffectiveCtx(c.suite.ctxDomain, ctx);

					const buffered = shakeOneShot(c.prehash, msg, c.suite.prehashSize);
					const chunks = msgLen > 0
						? [msg.subarray(0, Math.min(7, msg.length)), msg.subarray(Math.min(7, msg.length))]
						: [new Uint8Array(0)];
					const streamed = shakeStreamed(c.prehash, chunks, c.suite.prehashSize);

					expect(Array.from(streamed)).toEqual(Array.from(buffered));

					const inst = new c.SlhDsaClass();
					let pk: Uint8Array;
					let sk: Uint8Array;
					let sigBuffered: Uint8Array;
					let sigStreamed: Uint8Array;
					try {
						const kp = inst.keygen();
						pk = kp.verificationKey;
						sk = kp.signingKey;
						sigBuffered = inst.signHashPrehashedDeterministic(sk, buffered, c.prehash, effectiveCtx);
						sigStreamed = inst.signHashPrehashedDeterministic(sk, streamed, c.prehash, effectiveCtx);
					} finally {
						inst.dispose();
					}

					expect(Array.from(sigStreamed)).toEqual(Array.from(sigBuffered));

					// Assemble the envelope blob the way Sign.sign would (suite_byte,
					// ctx_len, ctx, payload, sig) and verify it round-trips through
					// both Sign.verify and VerifyStream against the real hedged
					// suite.verify path.
					const blob = concat(
						new Uint8Array([c.suite.formatEnum, ctx.length]),
						ctx, msg, sigBuffered,
					);
					const out1 = Sign.verify(c.suite, pk, blob, ctx);
					expect(Array.from(out1)).toEqual(Array.from(msg));

					const v = new VerifyStream(c.suite, pk, ctx);
					try {
						v.update(blob);
						const out2 = v.finalize();
						expect(Array.from(out2)).toEqual(Array.from(msg));
					} finally {
						v.dispose();
					}
				});
			}
		}
	}
});
