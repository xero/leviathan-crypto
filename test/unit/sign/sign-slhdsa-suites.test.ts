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
// test/unit/sign/sign-slhdsa-suites.test.ts
//
// Surface and round-trip coverage for the six exported SLH-DSA suite
// consts (SlhDsa{128f,192f,256f}Suite and SlhDsa{128f,192f,256f}PreHashSuite).
// Asserts catalog format bytes, ctxDomain naming, wasmModules immutability,
// key and signature sizes, hedged-sign byte uniqueness, prehash digest-size
// validation, and basic sign/verify round-trip with empty, small, and
// large ctx. Mirrors sign-mldsa-suites.test.ts.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, utf8ToBytes } from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import {
	SlhDsa128fSuite, SlhDsa192fSuite, SlhDsa256fSuite,
	SlhDsa128fPreHashSuite, SlhDsa192fPreHashSuite, SlhDsa256fPreHashSuite,
	CTX_DOMAIN_MAX,
} from '../../../src/ts/sign/index.js';
import type {
	SignatureSuite,
	StreamableSignatureSuite,
} from '../../../src/ts/sign/index.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ slhdsa: slhdsaWasm, sha3: sha3Wasm });
});

// ── Catalog assignments, locked at suite construction ──────────────────────

interface SuiteCase {
	name:        string;
	suite:       SignatureSuite;
	formatEnum:  number;
	formatName:  string;
	ctxDomain:   string;
	pkSize:      number;
	skSize:      number;
	sigSize:     number;
	wasmModules: readonly string[];
}

// FIPS 205 §11.1 Table 2:
//   128f: n=16, pk=32,  sk=64,  sig=17088
//   192f: n=24, pk=48,  sk=96,  sig=35664
//   256f: n=32, pk=64,  sk=128, sig=49856
const PURE_CASES: SuiteCase[] = [
	{
		name: 'SlhDsa128fSuite', suite: SlhDsa128fSuite,
		formatEnum: 0x06, formatName: 'slhdsa128f',
		ctxDomain: 'slhdsa128f-envelope-v3',
		pkSize: 32, skSize: 64, sigSize: 17088,
		wasmModules: ['slhdsa'],
	},
	{
		name: 'SlhDsa192fSuite', suite: SlhDsa192fSuite,
		formatEnum: 0x07, formatName: 'slhdsa192f',
		ctxDomain: 'slhdsa192f-envelope-v3',
		pkSize: 48, skSize: 96, sigSize: 35664,
		wasmModules: ['slhdsa'],
	},
	{
		name: 'SlhDsa256fSuite', suite: SlhDsa256fSuite,
		formatEnum: 0x08, formatName: 'slhdsa256f',
		ctxDomain: 'slhdsa256f-envelope-v3',
		pkSize: 64, skSize: 128, sigSize: 49856,
		wasmModules: ['slhdsa'],
	},
];

interface PrehashCase extends SuiteCase {
	suite:            StreamableSignatureSuite;
	prehashAlgorithm: 'shake-128' | 'shake-256';
	prehashSize:      number;
}

const PREHASH_CASES: PrehashCase[] = [
	{
		name: 'SlhDsa128fPreHashSuite', suite: SlhDsa128fPreHashSuite,
		formatEnum: 0x16, formatName: 'slhdsa128f-prehash',
		ctxDomain: 'slhdsa128f-prehash-envelope-v3',
		pkSize: 32, skSize: 64, sigSize: 17088,
		wasmModules: ['slhdsa', 'sha3'],
		prehashAlgorithm: 'shake-128', prehashSize: 32,
	},
	{
		name: 'SlhDsa192fPreHashSuite', suite: SlhDsa192fPreHashSuite,
		formatEnum: 0x17, formatName: 'slhdsa192f-prehash',
		ctxDomain: 'slhdsa192f-prehash-envelope-v3',
		pkSize: 48, skSize: 96, sigSize: 35664,
		wasmModules: ['slhdsa', 'sha3'],
		prehashAlgorithm: 'shake-256', prehashSize: 64,
	},
	{
		name: 'SlhDsa256fPreHashSuite', suite: SlhDsa256fPreHashSuite,
		formatEnum: 0x18, formatName: 'slhdsa256f-prehash',
		ctxDomain: 'slhdsa256f-prehash-envelope-v3',
		pkSize: 64, skSize: 128, sigSize: 49856,
		wasmModules: ['slhdsa', 'sha3'],
		prehashAlgorithm: 'shake-256', prehashSize: 64,
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
		expect(c.suite.sigSize).toBe(c.sigSize);
	});

	it.each(ALL_CASES)('$name advertises expected wasmModules', (c) => {
		expect(Array.from(c.suite.wasmModules)).toEqual(c.wasmModules);
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
const LARGE_CTX  = new Uint8Array(200).map((_, i) => (i * 31 + 5) & 0xff);
const EMPTY_CTX  = new Uint8Array(0);
const OVER_CTX   = new Uint8Array(201);
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
		expect(sig.length).toBe(c.sigSize);
		expect(c.suite.verify(pk, TEST_MSG, sig, EMPTY_CTX)).toBe(true);
	});

	it('sign + verify with 10-byte ctx', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, SMALL_CTX);
		expect(c.suite.verify(pk, TEST_MSG, sig, SMALL_CTX)).toBe(true);
	});

	it('sign + verify with 200-byte ctx (USER_CTX_MAX)', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, LARGE_CTX);
		expect(c.suite.verify(pk, TEST_MSG, sig, LARGE_CTX)).toBe(true);
	});

	it('201-byte ctx throws sig-ctx-too-long', () => {
		const { sk } = c.suite.keygen();
		let caught: unknown;
		try {
			c.suite.sign(sk, TEST_MSG, OVER_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-ctx-too-long');
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
		expect(sig.length).toBe(c.sigSize);
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
