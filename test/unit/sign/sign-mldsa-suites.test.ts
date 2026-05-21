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
// test/unit/sign/sign-mldsa-suites.test.ts
//
// Surface and round-trip coverage for the six exported ML-DSA suite
// consts (MlDsa44/65/87Suite and MlDsa44/65/87PreHashSuite). Asserts
// catalog format bytes, ctxDomain naming, wasmModules immutability, key
// and signature sizes, hedged-sign byte uniqueness, prehash digest-size
// validation, and basic sign/verify round-trip with empty, small, and
// large ctx.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, utf8ToBytes } from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }  from '../../../src/ts/sha3/embedded.js';
import {
	MlDsa44Suite, MlDsa65Suite, MlDsa87Suite,
	MlDsa44PreHashSuite, MlDsa65PreHashSuite, MlDsa87PreHashSuite,
	CTX_DOMAIN_MAX,
} from '../../../src/ts/sign/index.js';
import type {
	SignatureSuite,
	StreamableSignatureSuite,
} from '../../../src/ts/sign/index.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm });
});

// ── Catalog assignments, locked at suite construction ──────────────────────

interface SuiteCase {
	name:       string;
	suite:      SignatureSuite;
	formatEnum: number;
	formatName: string;
	ctxDomain:  string;
	pkSize:     number;
	skSize:     number;
	sigMaxSize:    number;
}

const PURE_CASES: SuiteCase[] = [
	{
		name: 'MlDsa44Suite', suite: MlDsa44Suite,
		formatEnum: 0x03, formatName: 'mldsa44',
		ctxDomain: 'mldsa44-envelope-v3',
		pkSize: 1312, skSize: 2560, sigMaxSize: 2420,
	},
	{
		name: 'MlDsa65Suite', suite: MlDsa65Suite,
		formatEnum: 0x04, formatName: 'mldsa65',
		ctxDomain: 'mldsa65-envelope-v3',
		pkSize: 1952, skSize: 4032, sigMaxSize: 3309,
	},
	{
		name: 'MlDsa87Suite', suite: MlDsa87Suite,
		formatEnum: 0x05, formatName: 'mldsa87',
		ctxDomain: 'mldsa87-envelope-v3',
		pkSize: 2592, skSize: 4896, sigMaxSize: 4627,
	},
];

interface PrehashCase extends SuiteCase {
	suite:            StreamableSignatureSuite;
	prehashAlgorithm: 'sha3-256' | 'sha3-512';
	prehashSize:      number;
}

const PREHASH_CASES: PrehashCase[] = [
	{
		name: 'MlDsa44PreHashSuite', suite: MlDsa44PreHashSuite,
		formatEnum: 0x13, formatName: 'mldsa44-prehash',
		ctxDomain: 'mldsa44-prehash-envelope-v3',
		pkSize: 1312, skSize: 2560, sigMaxSize: 2420,
		prehashAlgorithm: 'sha3-256', prehashSize: 32,
	},
	{
		name: 'MlDsa65PreHashSuite', suite: MlDsa65PreHashSuite,
		formatEnum: 0x14, formatName: 'mldsa65-prehash',
		ctxDomain: 'mldsa65-prehash-envelope-v3',
		pkSize: 1952, skSize: 4032, sigMaxSize: 3309,
		prehashAlgorithm: 'sha3-256', prehashSize: 32,
	},
	{
		name: 'MlDsa87PreHashSuite', suite: MlDsa87PreHashSuite,
		formatEnum: 0x15, formatName: 'mldsa87-prehash',
		ctxDomain: 'mldsa87-prehash-envelope-v3',
		pkSize: 2592, skSize: 4896, sigMaxSize: 4627,
		prehashAlgorithm: 'sha3-512', prehashSize: 64,
	},
];

const ALL_CASES: SuiteCase[] = [...PURE_CASES, ...PREHASH_CASES];

describe('suite catalog surface', () => {
	it.each(ALL_CASES)('$name has correct format byte and name', (c) => {
		expect(c.suite.formatEnum).toBe(c.formatEnum);
		expect(c.suite.formatName).toBe(c.formatName);
	});

	it.each(ALL_CASES)('$name has correct ctxDomain', (c) => {
		expect(c.suite.ctxDomain).toBe(c.ctxDomain);
		expect(utf8ToBytes(c.suite.ctxDomain).length)
			.toBeLessThanOrEqual(CTX_DOMAIN_MAX);
	});

	it.each(ALL_CASES)('$name has correct key + sig sizes', (c) => {
		expect(c.suite.pkSize).toBe(c.pkSize);
		expect(c.suite.skSize).toBe(c.skSize);
		expect(c.suite.sigMaxSize).toBe(c.sigMaxSize);
	});

	it.each(ALL_CASES)('$name advertises ["mldsa","sha3"] wasmModules', (c) => {
		expect(Array.from(c.suite.wasmModules)).toEqual(['mldsa', 'sha3']);
	});

	it.each(ALL_CASES)('$name wasmModules array is frozen', (c) => {
		expect(Object.isFrozen(c.suite.wasmModules)).toBe(true);
	});

	it.each(PREHASH_CASES)('$name advertises prehash algo + size', (c) => {
		expect(c.suite.prehashAlgorithm).toBe(c.prehashAlgorithm);
		expect(c.suite.prehashSize).toBe(c.prehashSize);
	});
});

// ── Round-trip per suite (one keygen, sign+verify across ctx shapes) ───────

const SMALL_CTX  = new Uint8Array(10).map((_, i) => (i * 13 + 7) & 0xff);
// 226 = 253 - len('mldsa{XX}-prehash-envelope-v3' 27 bytes), the smallest
// effective per-suite user_ctx ceiling across pure and prehash ML-DSA. Sits
// under both the FIPS 204 §3.6.1 absolute cap (USER_CTX_MAX = 255) and the
// combined effective_ctx cap enforced by buildEffectiveCtx.
const LARGE_CTX  = new Uint8Array(226).map((_, i) => (i * 31 + 5) & 0xff);
const EMPTY_CTX  = new Uint8Array(0);
const TEST_MSG   = new Uint8Array(64).map((_, i) => (i * 17 + 3) & 0xff);

function makeOtherKey(suite: SignatureSuite): Uint8Array {
	const { pk } = suite.keygen();
	return pk;
}

describe.each(ALL_CASES)('$name round-trip', (c) => {
	it('keygen returns correctly-sized pk/sk', () => {
		const { pk, sk } = c.suite.keygen();
		expect(pk.length).toBe(c.pkSize);
		expect(sk.length).toBe(c.skSize);
	});

	it('sign + verify with empty ctx', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(sig.length).toBe(c.sigMaxSize);
		expect(c.suite.verify(pk, TEST_MSG, sig, EMPTY_CTX)).toBe(true);
	});

	it('sign + verify with 10-byte ctx', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, SMALL_CTX);
		expect(c.suite.verify(pk, TEST_MSG, sig, SMALL_CTX)).toBe(true);
	});

	it('sign + verify with 226-byte ctx (combined effective_ctx ceiling)', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, LARGE_CTX);
		expect(c.suite.verify(pk, TEST_MSG, sig, LARGE_CTX)).toBe(true);
	});

	it('verify under wrong pk returns false', () => {
		const { sk } = c.suite.keygen();
		const sig    = c.suite.sign(sk, TEST_MSG, SMALL_CTX);
		const otherPk = makeOtherKey(c.suite);
		expect(c.suite.verify(otherPk, TEST_MSG, sig, SMALL_CTX)).toBe(false);
	});

	it('hedged sign produces two distinct sigs for the same (sk,msg)', () => {
		const { sk } = c.suite.keygen();
		const a = c.suite.sign(sk, TEST_MSG, EMPTY_CTX);
		const b = c.suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(a).not.toEqual(b);
	});
});

// ── Prehash-specific: digest validation + verify shape ─────────────────────

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

describe.each(PREHASH_CASES)('$name prehash digest contracts', (c) => {
	it('signPrehashed with correct-size digest verifies', () => {
		const { pk, sk } = c.suite.keygen();
		const digest = new Uint8Array(c.prehashSize)
			.map((_, i) => (i * 19 + 11) & 0xff);
		const sig = c.suite.signPrehashed(sk, digest, SMALL_CTX);
		expect(sig.length).toBe(c.sigMaxSize);
		expect(c.suite.verifyPrehashed(pk, digest, sig, SMALL_CTX)).toBe(true);
	});

	it('signPrehashed with wrong-size digest throws sig-malformed-input', () => {
		const { sk } = c.suite.keygen();
		const bad = new Uint8Array(c.prehashSize + 1);
		const err = captureSigningError(
			() => c.suite.signPrehashed(sk, bad, SMALL_CTX),
		);
		expect(err.discriminator).toBe('sig-malformed-input');
	});

	it('verifyPrehashed with wrong-size digest throws sig-malformed-input', () => {
		const { pk, sk } = c.suite.keygen();
		const digest = new Uint8Array(c.prehashSize)
			.map((_, i) => (i * 23 + 1) & 0xff);
		const sig = c.suite.signPrehashed(sk, digest, EMPTY_CTX);
		const bad = new Uint8Array(c.prehashSize + 1);
		const err = captureSigningError(
			() => c.suite.verifyPrehashed(pk, bad, sig, EMPTY_CTX),
		);
		expect(err.discriminator).toBe('sig-malformed-input');
	});
});
