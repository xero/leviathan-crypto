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
// test/unit/sign/sign-hybrid-classical-suites.test.ts
//
// Surface and round-trip coverage for the four exported classical+PQ
// hybrid suite consts (MlDsa44Ed25519Suite / MlDsa65Ed25519Suite /
// MlDsa44EcdsaP256Suite / MlDsa65EcdsaP256Suite). Asserts catalog format
// bytes, ctxDomain naming, wasmModules immutability, composite key + sig
// sizes per composite-sigs Appendix A Table 4, prehash configuration,
// 255-byte ctx contract (composite-sigs §3.2 step 1), hedged-sign byte
// uniqueness, and sign/verify round-trip across empty / small / cap-boundary
// ctx shapes.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, utf8ToBytes } from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm }   from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }    from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm }    from '../../../src/ts/sha2/embedded.js';
import { ed25519Wasm } from '../../../src/ts/ed25519/embedded.js';
import { p256Wasm }    from '../../../src/ts/ecdsa/embedded.js';
import { CTX_DOMAIN_MAX } from '../../../src/ts/sign/index.js';
import {
	MlDsa44Ed25519Suite,
	MlDsa65Ed25519Suite,
	MlDsa44EcdsaP256Suite,
	MlDsa65EcdsaP256Suite,
} from '../../../src/ts/sign/suites/hybrid-classical.js';
import type { StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import { MLDSA44, MLDSA65 } from '../../../src/ts/mldsa/index.js';

beforeAll(async () => {
	_resetForTesting();
	await init({
		mldsa: mldsaWasm,
		sha3: sha3Wasm,
		sha2: sha2Wasm,
		ed25519: ed25519Wasm,
		p256: p256Wasm,
	});
});

interface HybridCase {
	name:             string;
	suite:            StreamableSignatureSuite;
	formatEnum:       number;
	formatName:       string;
	ctxDomain:        string;
	pkSize:           number;
	skSize:           number;
	sigMaxSize:       number;
	wasmModules:      readonly string[];
	prehashAlgorithm: 'sha-256' | 'sha-512';
	prehashSize:      number;
	// Variable-length trad sig means the actual signature byte count can
	// fall below sigMaxSize (composite ECDSA suites; Appendix A Table 4 *).
	variableSig:      boolean;
}

const CASES: HybridCase[] = [
	{
		name: 'MlDsa44Ed25519Suite', suite: MlDsa44Ed25519Suite,
		formatEnum: 0x20, formatName: 'mldsa44-ed25519',
		ctxDomain: 'mldsa44-ed25519-envelope-v3',
		pkSize: MLDSA44.pkBytes + 32,
		skSize: 64,
		sigMaxSize: MLDSA44.sigBytes + 64,
		wasmModules: ['mldsa', 'sha3', 'curve25519', 'sha2'],
		prehashAlgorithm: 'sha-512', prehashSize: 64,
		variableSig: false,
	},
	{
		name: 'MlDsa65Ed25519Suite', suite: MlDsa65Ed25519Suite,
		formatEnum: 0x21, formatName: 'mldsa65-ed25519',
		ctxDomain: 'mldsa65-ed25519-envelope-v3',
		pkSize: MLDSA65.pkBytes + 32,
		skSize: 64,
		sigMaxSize: MLDSA65.sigBytes + 64,
		wasmModules: ['mldsa', 'sha3', 'curve25519', 'sha2'],
		prehashAlgorithm: 'sha-512', prehashSize: 64,
		variableSig: false,
	},
	{
		name: 'MlDsa44EcdsaP256Suite', suite: MlDsa44EcdsaP256Suite,
		formatEnum: 0x22, formatName: 'mldsa44-ecdsa-p256',
		ctxDomain: 'mldsa44-ecdsa-p256-envelope-v3',
		pkSize: MLDSA44.pkBytes + 65,
		skSize: 83,
		sigMaxSize: MLDSA44.sigBytes + 72,
		wasmModules: ['mldsa', 'sha3', 'p256', 'sha2'],
		prehashAlgorithm: 'sha-256', prehashSize: 32,
		variableSig: true,
	},
	{
		name: 'MlDsa65EcdsaP256Suite', suite: MlDsa65EcdsaP256Suite,
		formatEnum: 0x23, formatName: 'mldsa65-ecdsa-p256',
		ctxDomain: 'mldsa65-ecdsa-p256-envelope-v3',
		pkSize: MLDSA65.pkBytes + 65,
		skSize: 83,
		sigMaxSize: MLDSA65.sigBytes + 72,
		wasmModules: ['mldsa', 'sha3', 'p256', 'sha2'],
		prehashAlgorithm: 'sha-512', prehashSize: 64,
		variableSig: true,
	},
];

// GATE: catalog numeric sanity against the spec-derived sizes
// (composite-sigs Appendix A Table 4: pk / sk / sig maxes).
describe('hybrid-classical catalog numeric gates', () => {
	it('0x20 sizes match composite-sigs Appendix A: 1344 / 64 / 2484', () => {
		expect(CASES[0].pkSize).toBe(1344);
		expect(CASES[0].skSize).toBe(64);
		expect(CASES[0].sigMaxSize).toBe(2484);
	});
	it('0x21 sizes match composite-sigs Appendix A: 1984 / 64 / 3373', () => {
		expect(CASES[1].pkSize).toBe(1984);
		expect(CASES[1].skSize).toBe(64);
		expect(CASES[1].sigMaxSize).toBe(3373);
	});
	it('0x22 sizes match composite-sigs Appendix A: 1377 / 83 / 2492', () => {
		expect(CASES[2].pkSize).toBe(1377);
		expect(CASES[2].skSize).toBe(83);
		expect(CASES[2].sigMaxSize).toBe(2492);
	});
	it('0x23 sizes match composite-sigs Appendix A: 2017 / 83 / 3381', () => {
		expect(CASES[3].pkSize).toBe(2017);
		expect(CASES[3].skSize).toBe(83);
		expect(CASES[3].sigMaxSize).toBe(3381);
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

	it.each(CASES)('$name pk/sk/sigMax sizes equal the catalog values', (c) => {
		expect(c.suite.pkSize).toBe(c.pkSize);
		expect(c.suite.skSize).toBe(c.skSize);
		expect(c.suite.sigMaxSize).toBe(c.sigMaxSize);
	});

	it.each(CASES)('$name advertises the right wasm module set', (c) => {
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
// composite-sigs §3.2 step 1: 255 is the spec's user_ctx ceiling. The
// composite suites enforce this inline, not via buildEffectiveCtx (which
// has a tighter combined-cap rule for buildEffectiveCtx-using suites).
const MAX_CTX   = new Uint8Array(255).map((_, i) => (i * 31 + 5) & 0xff);
// One past the spec cap. Trips `sig-ctx-too-long`.
const OVER_CTX  = new Uint8Array(256);

describe.each(CASES)('$name round-trip', (c) => {
	it('keygen returns correctly-sized composite pk/sk', () => {
		const { pk, sk } = c.suite.keygen();
		expect(pk.length).toBe(c.pkSize);
		expect(sk.length).toBe(c.skSize);
	});

	it('sign + verify with empty ctx', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, EMPTY_CTX);
		if (c.variableSig)
			expect(sig.length).toBeLessThanOrEqual(c.sigMaxSize);
		else
			expect(sig.length).toBe(c.sigMaxSize);
		expect(c.suite.verify(pk, TEST_MSG, sig, EMPTY_CTX)).toBe(true);
	});

	it('sign + verify with short ctx', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, SMALL_CTX);
		expect(c.suite.verify(pk, TEST_MSG, sig, SMALL_CTX)).toBe(true);
	});

	it('sign + verify with 255-byte ctx (composite-sigs §3.2 step 1 cap)', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, TEST_MSG, MAX_CTX);
		expect(c.suite.verify(pk, TEST_MSG, sig, MAX_CTX)).toBe(true);
	});

	it('256-byte ctx throws sig-ctx-too-long', () => {
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
		if (c.variableSig)
			expect(sig.length).toBeLessThanOrEqual(c.sigMaxSize);
		else
			expect(sig.length).toBe(c.sigMaxSize);
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

	it('verifyPrehashed with wrong-size digest throws sig-malformed-input', () => {
		const { pk, sk } = c.suite.keygen();
		const digest = new Uint8Array(c.prehashSize)
			.map((_, i) => (i * 23 + 1) & 0xff);
		const sig = c.suite.signPrehashed(sk, digest, EMPTY_CTX);
		let caught: unknown;
		try {
			c.suite.verifyPrehashed(pk, new Uint8Array(c.prehashSize + 1), sig, EMPTY_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-malformed-input');
	});
});
