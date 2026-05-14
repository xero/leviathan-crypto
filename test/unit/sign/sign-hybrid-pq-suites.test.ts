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
// test/unit/sign/sign-hybrid-pq-suites.test.ts
//
// Surface and round-trip coverage for the three exported PQ-only hybrid
// suite consts (MlDsa44SlhDsa128fSuite / MlDsa65SlhDsa192fSuite /
// MlDsa87SlhDsa256fSuite). Asserts catalog format bytes, ctxDomain naming,
// wasmModules immutability, composite key + sig sizes derived as
// mldsa + slhdsa, prehash configuration per security tier, ctx-length
// contract, hedged-sign byte uniqueness, and basic sign/verify round-trip
// across empty / small / cap-boundary ctx shapes.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, utf8ToBytes } from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm }  from '../../../src/ts/mldsa/embedded.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import {
	MlDsa44SlhDsa128fSuite,
	MlDsa65SlhDsa192fSuite,
	MlDsa87SlhDsa256fSuite,
	CTX_DOMAIN_MAX,
} from '../../../src/ts/sign/index.js';
import type { StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import { MLDSA44, MLDSA65, MLDSA87 } from '../../../src/ts/mldsa/index.js';
import { SLHDSA128F, SLHDSA192F, SLHDSA256F } from '../../../src/ts/slhdsa/index.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, slhdsa: slhdsaWasm, sha3: sha3Wasm });
});

// FIPS 204 §4 Table 1 + FIPS 205 §11.1 Table 2 derived sizes:
//   0x30 (44 + 128f) → pk 1344,  sk 2624,  sig 19508
//   0x31 (65 + 192f) → pk 2000,  sk 4128,  sig 38973
//   0x32 (87 + 256f) → pk 2656,  sk 5024,  sig 54483

interface HybridCase {
	name:             string;
	suite:            StreamableSignatureSuite;
	formatEnum:       number;
	formatName:       string;
	ctxDomain:        string;
	pkSize:           number;
	skSize:           number;
	sigSize:          number;
	wasmModules:      readonly string[];
	prehashAlgorithm: 'shake-128' | 'shake-256';
	prehashSize:      number;
}

const CASES: HybridCase[] = [
	{
		name: 'MlDsa44SlhDsa128fSuite', suite: MlDsa44SlhDsa128fSuite,
		formatEnum: 0x30, formatName: 'mldsa44-slhdsa128f',
		ctxDomain: 'mldsa44-slhdsa128f-envelope-v3',
		pkSize: MLDSA44.pkBytes  + SLHDSA128F.pkBytes,
		skSize: MLDSA44.skBytes  + SLHDSA128F.skBytes,
		sigSize: MLDSA44.sigBytes + SLHDSA128F.sigBytes,
		wasmModules: ['mldsa', 'sha3', 'slhdsa'],
		prehashAlgorithm: 'shake-128', prehashSize: 32,
	},
	{
		name: 'MlDsa65SlhDsa192fSuite', suite: MlDsa65SlhDsa192fSuite,
		formatEnum: 0x31, formatName: 'mldsa65-slhdsa192f',
		ctxDomain: 'mldsa65-slhdsa192f-envelope-v3',
		pkSize: MLDSA65.pkBytes  + SLHDSA192F.pkBytes,
		skSize: MLDSA65.skBytes  + SLHDSA192F.skBytes,
		sigSize: MLDSA65.sigBytes + SLHDSA192F.sigBytes,
		wasmModules: ['mldsa', 'sha3', 'slhdsa'],
		prehashAlgorithm: 'shake-256', prehashSize: 64,
	},
	{
		name: 'MlDsa87SlhDsa256fSuite', suite: MlDsa87SlhDsa256fSuite,
		formatEnum: 0x32, formatName: 'mldsa87-slhdsa256f',
		ctxDomain: 'mldsa87-slhdsa256f-envelope-v3',
		pkSize: MLDSA87.pkBytes  + SLHDSA256F.pkBytes,
		skSize: MLDSA87.skBytes  + SLHDSA256F.skBytes,
		sigSize: MLDSA87.sigBytes + SLHDSA256F.sigBytes,
		wasmModules: ['mldsa', 'sha3', 'slhdsa'],
		prehashAlgorithm: 'shake-256', prehashSize: 64,
	},
];

// Sanity-check against the spec-derived catalog sizes (FIPS 204 §4 for
// ML-DSA, FIPS 205 §11.1 Table 2 for SLH-DSA).
describe('hybrid catalog numeric gates', () => {
	it('0x30 sizes match FIPS 204 §4 + FIPS 205 §11.1 Table 2', () => {
		expect(CASES[0].pkSize).toBe(1344);
		expect(CASES[0].skSize).toBe(2624);
		expect(CASES[0].sigSize).toBe(19508);
	});
	it('0x31 sizes match FIPS 204 §4 + FIPS 205 §11.1 Table 2', () => {
		expect(CASES[1].pkSize).toBe(2000);
		expect(CASES[1].skSize).toBe(4128);
		expect(CASES[1].sigSize).toBe(38973);
	});
	it('0x32 sizes match FIPS 204 §4 + FIPS 205 §11.1 Table 2', () => {
		expect(CASES[2].pkSize).toBe(2656);
		expect(CASES[2].skSize).toBe(5024);
		expect(CASES[2].sigSize).toBe(54483);
	});
});

describe('suite catalog surface', () => {
	it.each(CASES)('$name has correct format byte + name', (c) => {
		expect(c.suite.formatEnum).toBe(c.formatEnum);
		expect(c.suite.formatName).toBe(c.formatName);
	});

	it.each(CASES)('$name has correct ctxDomain', (c) => {
		expect(c.suite.ctxDomain).toBe(c.ctxDomain);
		expect(utf8ToBytes(c.suite.ctxDomain).length)
			.toBeLessThanOrEqual(CTX_DOMAIN_MAX);
	});

	it.each(CASES)('$name pk/sk/sig sizes equal sum of half sizes', (c) => {
		expect(c.suite.pkSize).toBe(c.pkSize);
		expect(c.suite.skSize).toBe(c.skSize);
		expect(c.suite.sigSize).toBe(c.sigSize);
	});

	it.each(CASES)('$name advertises mldsa + sha3 + slhdsa', (c) => {
		expect(Array.from(c.suite.wasmModules)).toEqual(c.wasmModules);
	});

	it.each(CASES)('$name wasmModules array is frozen', (c) => {
		expect(Object.isFrozen(c.suite.wasmModules)).toBe(true);
	});

	it.each(CASES)('$name advertises prehash algorithm + size', (c) => {
		expect(c.suite.prehashAlgorithm).toBe(c.prehashAlgorithm);
		expect(c.suite.prehashSize).toBe(c.prehashSize);
	});
});

// ── Round-trip per suite ───────────────────────────────────────────────────

const TEST_MSG  = new Uint8Array(64).map((_, i) => (i * 17 + 3) & 0xff);
const EMPTY_CTX = new Uint8Array(0);
const SMALL_CTX = utf8ToBytes('hello');
const LARGE_CTX = new Uint8Array(200).map((_, i) => (i * 31 + 5) & 0xff);
const OVER_CTX  = new Uint8Array(201);

describe.each(CASES)('$name round-trip', (c) => {
	it('keygen returns correctly-sized composite pk/sk', () => {
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

	it('sign + verify with short ctx', () => {
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

	it('hedged sign produces two distinct sigs for the same (sk,msg)', () => {
		const { sk } = c.suite.keygen();
		const a = c.suite.sign(sk, TEST_MSG, EMPTY_CTX);
		const b = c.suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(a).not.toEqual(b);
		// Both still verify under the same pk.
	});

	it('hedged sigs verify under the original pk', () => {
		const { pk, sk } = c.suite.keygen();
		const a = c.suite.sign(sk, TEST_MSG, EMPTY_CTX);
		const b = c.suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(c.suite.verify(pk, TEST_MSG, a, EMPTY_CTX)).toBe(true);
		expect(c.suite.verify(pk, TEST_MSG, b, EMPTY_CTX)).toBe(true);
	});

	it('verify under wrong pk returns false', () => {
		const { sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, SMALL_CTX);
		const other = c.suite.keygen().pk;
		expect(c.suite.verify(other, TEST_MSG, sig, SMALL_CTX)).toBe(false);
	});
});

// ── Prehash-specific contracts ─────────────────────────────────────────────

describe.each(CASES)('$name prehash digest contracts', (c) => {
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
		let caught: unknown;
		try {
			c.suite.signPrehashed(sk, new Uint8Array(c.prehashSize + 1), SMALL_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-malformed-input');
	});

	it('signPrehashed with wrong-size sk throws sig-key-size', () => {
		const { sk } = c.suite.keygen();
		const trimmed = sk.subarray(0, sk.length - 1);
		const digest = new Uint8Array(c.prehashSize);
		let caught: unknown;
		try {
			c.suite.signPrehashed(trimmed, digest, SMALL_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-key-size');
	});

	it('verifyPrehashed with wrong-size digest returns false (no throw)', () => {
		const { pk, sk } = c.suite.keygen();
		const digest = new Uint8Array(c.prehashSize)
			.map((_, i) => (i * 23 + 1) & 0xff);
		const sig = c.suite.signPrehashed(sk, digest, EMPTY_CTX);
		expect(c.suite.verifyPrehashed(pk, new Uint8Array(c.prehashSize + 1), sig, EMPTY_CTX)).toBe(false);
	});
});
