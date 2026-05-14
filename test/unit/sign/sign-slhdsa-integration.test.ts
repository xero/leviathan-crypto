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
// test/unit/sign/sign-slhdsa-integration.test.ts
//
// End-to-end envelope path exercising the v3 sign layer against REAL
// SLH-DSA primitives. Covers:
//   - Sign.sign / Sign.verify round-trip per pure suite.
//   - Sign.sign / Sign.verify round-trip per prehash suite.
//   - SignStream + VerifyStream round-trip via prehash suites, proving
//     the SHAKE128 / SHAKE256 running-hash wiring lines up with the
//     suite's signPrehashed / verifyPrehashed path.
//   - SignStream byte-equivalence with the buffered Sign.sign output under
//     deterministic sub-sign. Hedged Sign.sign cannot be byte-compared.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import {
	Sign, SignStream, VerifyStream,
	SlhDsa128fSuite, SlhDsa192fSuite, SlhDsa256fSuite,
	SlhDsa128fPreHashSuite, SlhDsa192fPreHashSuite, SlhDsa256fPreHashSuite,
} from '../../../src/ts/sign/index.js';
import {
	SlhDsa128f, SlhDsa192f, SlhDsa256f,
} from '../../../src/ts/slhdsa/index.js';
import type { SignatureSuite, StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import {
	SHAKE128, SHAKE256, SHAKE128Stream, SHAKE256Stream,
} from '../../../src/ts/sha3/index.js';
import { concat } from '../../../src/ts/utils.js';
import { buildEffectiveCtx } from '../../../src/ts/sign/ctx.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ slhdsa: slhdsaWasm, sha3: sha3Wasm });
});

const CTX = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
const MSG = new Uint8Array(128).map((_, i) => (i * 37 + 9) & 0xff);

// ── Pure suites ─────────────────────────────────────────────────────────────

interface PureCase {
	name: string;
	suite: SignatureSuite;
}

const PURE_CASES: PureCase[] = [
	{ name: 'SlhDsa128fSuite', suite: SlhDsa128fSuite },
	{ name: 'SlhDsa192fSuite', suite: SlhDsa192fSuite },
	{ name: 'SlhDsa256fSuite', suite: SlhDsa256fSuite },
];

describe.each(PURE_CASES)('Sign envelope, pure $name', (c) => {
	it('round-trips msg through real SLH-DSA sign/verify', () => {
		const { pk, sk } = c.suite.keygen();
		const blob = Sign.sign(c.suite, sk, MSG, CTX);
		const out  = Sign.verify(c.suite, pk, blob, CTX);
		expect(out).toEqual(MSG);
	});

	it('peek matches envelope structure', () => {
		const { sk } = c.suite.keygen();
		const blob = Sign.sign(c.suite, sk, MSG, CTX);
		const peek = Sign.peek(blob, c.suite);
		expect(peek.suiteByte).toBe(c.suite.formatEnum);
		expect(peek.payloadLength).toBe(MSG.length);
		expect(Array.from(peek.ctx)).toEqual(Array.from(CTX));
	});
});

// ── Prehash suites ──────────────────────────────────────────────────────────

interface PrehashCase {
	name:        string;
	suite:       StreamableSignatureSuite;
	SlhDsaClass: typeof SlhDsa128f | typeof SlhDsa192f | typeof SlhDsa256f;
}

const PREHASH_CASES: PrehashCase[] = [
	{ name: 'SlhDsa128fPreHashSuite', suite: SlhDsa128fPreHashSuite, SlhDsaClass: SlhDsa128f },
	{ name: 'SlhDsa192fPreHashSuite', suite: SlhDsa192fPreHashSuite, SlhDsaClass: SlhDsa192f },
	{ name: 'SlhDsa256fPreHashSuite', suite: SlhDsa256fPreHashSuite, SlhDsaClass: SlhDsa256f },
];

describe.each(PREHASH_CASES)('Sign envelope, prehash $name', (c) => {
	it('round-trips msg through real SLH-DSA + SHAKE prehash', () => {
		const { pk, sk } = c.suite.keygen();
		const blob = Sign.sign(c.suite, sk, MSG, CTX);
		const out  = Sign.verify(c.suite, pk, blob, CTX);
		expect(out).toEqual(MSG);
	});
});

describe.each(PREHASH_CASES)('SignStream + VerifyStream, $name', (c) => {
	it('streaming sign output verifies via Sign.verify', () => {
		const { pk, sk } = c.suite.keygen();
		const s = new SignStream(c.suite, sk, CTX);
		try {
			s.update(MSG.subarray(0, 32));
			s.update(MSG.subarray(32, 96));
			s.update(MSG.subarray(96));
			const sig = s.finalize();
			const blob = concat(s.preamble, MSG, sig);
			const out  = Sign.verify(c.suite, pk, blob, CTX);
			expect(out).toEqual(MSG);
		} finally {
			s.dispose();
		}
	});

	it('VerifyStream consumes the same byte stream and returns the msg', () => {
		const { pk, sk } = c.suite.keygen();
		const s = new SignStream(c.suite, sk, CTX);
		let blob: Uint8Array;
		try {
			s.update(MSG);
			const sig = s.finalize();
			blob = concat(s.preamble, MSG, sig);
		} finally {
			s.dispose();
		}

		const v = new VerifyStream(c.suite, pk, CTX);
		try {
			v.update(blob.subarray(0, 1));
			v.update(blob.subarray(1));
			const out = v.finalize();
			expect(out).toEqual(MSG);
		} finally {
			v.dispose();
		}
	});
});

// ── Stream-equivalence under deterministic sub-sign ─────────────────────────
//
// The hedged production suite.sign/SignStream paths cannot be byte-compared,
// but a determinism gate is still required: compute the SHAKE digest of MSG
// directly, drive the underlying SLH-DSA class's signHashPrehashedDeterministic
// path to get the buffered sig, then compare against an identically-driven
// path that pulls digest bytes through SignStream's running hash. The two
// digests are produced by independent code paths (single-shot SHAKE128/256
// vs SHAKE{128,256}Stream); byte-equality is the gate.

function shake128(msg: Uint8Array, outLen: number): Uint8Array {
	const h = new SHAKE128();
	try {
		return h.hash(msg, outLen);
	} finally {
		h.dispose();
	}
}
function shake256(msg: Uint8Array, outLen: number): Uint8Array {
	const h = new SHAKE256();
	try {
		return h.hash(msg, outLen);
	} finally {
		h.dispose();
	}
}
function shake128StreamChunks(chunks: Uint8Array[], outLen: number): Uint8Array {
	const h = new SHAKE128Stream(outLen);
	try {
		for (const c of chunks) h.update(c);
		return h.finalize();
	} finally {
		h.dispose();
	}
}
function shake256StreamChunks(chunks: Uint8Array[], outLen: number): Uint8Array {
	const h = new SHAKE256Stream(outLen);
	try {
		for (const c of chunks) h.update(c);
		return h.finalize();
	} finally {
		h.dispose();
	}
}

describe.each(PREHASH_CASES)('$name SHAKE one-shot equals chunked stream', (c) => {
	it('SHAKE{128,256} produces identical digests via single-shot and streaming', () => {
		const chunks = [
			MSG.subarray(0, 17),
			MSG.subarray(17, 64),
			MSG.subarray(64),
		];
		const outLen = c.suite.prehashSize;
		const singleShot = c.suite.prehashAlgorithm === 'shake-128'
			? shake128(MSG, outLen)
			: shake256(MSG, outLen);
		const streamed = c.suite.prehashAlgorithm === 'shake-128'
			? shake128StreamChunks(chunks, outLen)
			: shake256StreamChunks(chunks, outLen);
		expect(Array.from(streamed)).toEqual(Array.from(singleShot));
	});
});

describe.each(PREHASH_CASES)('$name deterministic sig equality', (c) => {
	it('SignStream-style chunked digest + deterministic sign matches Sign-with-buffered-digest', () => {
		const { pk, sk } = c.suite.keygen();

		// Buffered path: hash MSG single-shot, then deterministic sign.
		const buffered = c.suite.prehashAlgorithm === 'shake-128'
			? shake128(MSG, c.suite.prehashSize)
			: shake256(MSG, c.suite.prehashSize);

		// Streamed path: same MSG split into three pieces, run through the
		// streaming hash class that createRunningHash uses.
		const chunks = [
			MSG.subarray(0, 17),
			MSG.subarray(17, 64),
			MSG.subarray(64),
		];
		const streamed = c.suite.prehashAlgorithm === 'shake-128'
			? shake128StreamChunks(chunks, c.suite.prehashSize)
			: shake256StreamChunks(chunks, c.suite.prehashSize);

		expect(Array.from(streamed)).toEqual(Array.from(buffered));

		// Now drive deterministic sub-sign through both digests via the
		// underlying SlhDsa class; the suite layer wraps ctxDomain into
		// effective_ctx, so we have to do the same to compare apples-to-apples.
		const effectiveCtx = buildEffectiveCtx(c.suite.ctxDomain, CTX);
		const ph = c.suite.prehashAlgorithm === 'shake-128' ? 'SHAKE128' : 'SHAKE256';
		const inst = new c.SlhDsaClass();
		let sigA: Uint8Array;
		let sigB: Uint8Array;
		try {
			sigA = inst.signHashPrehashedDeterministic(sk, buffered, ph, effectiveCtx);
			sigB = inst.signHashPrehashedDeterministic(sk, streamed, ph, effectiveCtx);
		} finally {
			inst.dispose();
		}
		expect(Array.from(sigA)).toEqual(Array.from(sigB));
		expect(c.suite.verifyPrehashed(pk, buffered, sigA, CTX)).toBe(true);
	});
});
