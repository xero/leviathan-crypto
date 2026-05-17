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
// test/unit/sign/sign-ecdsa-p256-suites.test.ts
//
// Surface and round-trip coverage for the EcdsaP256Suite catalog entry.
// Asserts the locked format byte / ctxDomain / sizes, the wasmModules
// immutability, the ctx-unsupported lock on every entry point, the
// prehash digest-size validation, hedged-by-default sign behaviour (two
// signs of the same (sk, msg) produce DIFFERENT signatures), and basic
// sign / verify round-trip across empty / 64-byte / 1024-byte messages.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, utf8ToBytes } from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { WASM_GZ_BASE64 as p256Wasm } from '../../../src/ts/embedded/p256.js';
import { WASM_GZ_BASE64 as sha2Wasm } from '../../../src/ts/embedded/sha2.js';
import {
	EcdsaP256Suite,
	CTX_DOMAIN_MAX,
} from '../../../src/ts/sign/index.js';
import type {
	SignatureSuite,
	StreamableSignatureSuite,
} from '../../../src/ts/sign/index.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ p256: p256Wasm, sha2: sha2Wasm });
});

// ── Catalog assignments, locked at suite construction ──────────────────────

describe('EcdsaP256Suite surface', () => {
	it('has formatEnum 0x02 and formatName "ecdsa-p256"', () => {
		expect(EcdsaP256Suite.formatEnum).toBe(0x02);
		expect(EcdsaP256Suite.formatName).toBe('ecdsa-p256');
	});

	it('has ctxDomain "ecdsa-p256-envelope-v3" within CTX_DOMAIN_MAX', () => {
		expect(EcdsaP256Suite.ctxDomain).toBe('ecdsa-p256-envelope-v3');
		expect(utf8ToBytes(EcdsaP256Suite.ctxDomain).length)
			.toBeLessThanOrEqual(CTX_DOMAIN_MAX);
	});

	it('has 33-byte pk, 32-byte sk, 64-byte sig', () => {
		expect(EcdsaP256Suite.pkSize).toBe(33);
		expect(EcdsaP256Suite.skSize).toBe(32);
		expect(EcdsaP256Suite.sigMaxSize).toBe(64);
	});

	it('advertises ["p256","sha2"] wasmModules, frozen', () => {
		expect(Array.from(EcdsaP256Suite.wasmModules)).toEqual(['p256', 'sha2']);
		expect(Object.isFrozen(EcdsaP256Suite.wasmModules)).toBe(true);
	});

	it('locks prehashAlgorithm to "sha-256" and prehashSize 32', () => {
		expect(EcdsaP256Suite.prehashAlgorithm).toBe('sha-256');
		expect(EcdsaP256Suite.prehashSize).toBe(32);
	});

	it('type-level: conforms to StreamableSignatureSuite (and thus SignatureSuite)', () => {
		const ss: StreamableSignatureSuite = EcdsaP256Suite;
		const _ss: SignatureSuite = ss;
		expect(ss.prehashAlgorithm).toBe('sha-256');
		expect(_ss.formatEnum).toBe(0x02);
	});
});

// ── Helpers ────────────────────────────────────────────────────────────────

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

const EMPTY_CTX  = new Uint8Array(0);
const SMALL_CTX  = new Uint8Array(10).map((_, i) => (i * 13 + 7) & 0xff);
const TEST_MSG   = new Uint8Array(64).map((_, i) => (i * 17 + 3) & 0xff);
const TINY_MSG   = new Uint8Array(0);
const BIG_MSG    = new Uint8Array(1024).map((_, i) => (i * 31 + 5) & 0xff);

// ── ctx-rejection lock on every entry point ────────────────────────────────

describe('EcdsaP256Suite ctx-rejection lock', () => {
	it('sign with non-empty user_ctx throws sig-ctx-unsupported', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const err = captureSigningError(
			() => EcdsaP256Suite.sign(sk, TEST_MSG, SMALL_CTX),
		);
		expect(err.discriminator).toBe('sig-ctx-unsupported');
	});

	it('verify with non-empty user_ctx throws sig-ctx-unsupported', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const sig = EcdsaP256Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		const err = captureSigningError(
			() => EcdsaP256Suite.verify(pk, TEST_MSG, sig, SMALL_CTX),
		);
		expect(err.discriminator).toBe('sig-ctx-unsupported');
	});

	it('signPrehashed with non-empty user_ctx throws sig-ctx-unsupported', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const digest = new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff);
		const err = captureSigningError(
			() => EcdsaP256Suite.signPrehashed(sk, digest, SMALL_CTX),
		);
		expect(err.discriminator).toBe('sig-ctx-unsupported');
	});

	it('verifyPrehashed with non-empty user_ctx throws sig-ctx-unsupported', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const digest = new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff);
		const sig = EcdsaP256Suite.signPrehashed(sk, digest, EMPTY_CTX);
		const err = captureSigningError(
			() => EcdsaP256Suite.verifyPrehashed(pk, digest, sig, SMALL_CTX),
		);
		expect(err.discriminator).toBe('sig-ctx-unsupported');
	});
});

// ── Prehash digest-size contract ───────────────────────────────────────────

describe('EcdsaP256Suite digest contract', () => {
	it('signPrehashed with correct-size digest verifies', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const digest = new Uint8Array(32).map((_, i) => (i * 19 + 11) & 0xff);
		const sig = EcdsaP256Suite.signPrehashed(sk, digest, EMPTY_CTX);
		expect(sig.length).toBe(64);
		expect(EcdsaP256Suite.verifyPrehashed(pk, digest, sig, EMPTY_CTX))
			.toBe(true);
	});

	it('signPrehashed with 31-byte digest throws sig-malformed-input', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const bad = new Uint8Array(31);
		const err = captureSigningError(
			() => EcdsaP256Suite.signPrehashed(sk, bad, EMPTY_CTX),
		);
		expect(err.discriminator).toBe('sig-malformed-input');
	});

	it('signPrehashed with 33-byte digest throws sig-malformed-input', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const bad = new Uint8Array(33);
		const err = captureSigningError(
			() => EcdsaP256Suite.signPrehashed(sk, bad, EMPTY_CTX),
		);
		expect(err.discriminator).toBe('sig-malformed-input');
	});

	it('verifyPrehashed with 31-byte digest throws sig-malformed-input', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const digest = new Uint8Array(32).map((_, i) => (i * 23 + 1) & 0xff);
		const sig = EcdsaP256Suite.signPrehashed(sk, digest, EMPTY_CTX);
		const bad = new Uint8Array(31);
		const err = captureSigningError(
			() => EcdsaP256Suite.verifyPrehashed(pk, bad, sig, EMPTY_CTX),
		);
		expect(err.discriminator).toBe('sig-malformed-input');
	});

	it('verifyPrehashed with 33-byte digest throws sig-malformed-input', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const digest = new Uint8Array(32).map((_, i) => (i * 23 + 1) & 0xff);
		const sig = EcdsaP256Suite.signPrehashed(sk, digest, EMPTY_CTX);
		const bad = new Uint8Array(33);
		const err = captureSigningError(
			() => EcdsaP256Suite.verifyPrehashed(pk, bad, sig, EMPTY_CTX),
		);
		expect(err.discriminator).toBe('sig-malformed-input');
	});
});

// ── Round trip across message sizes ────────────────────────────────────────

describe('EcdsaP256Suite round-trip', () => {
	it('keygen returns 33-byte pk and 32-byte sk', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		expect(pk.length).toBe(33);
		expect(sk.length).toBe(32);
	});

	it('sign + verify with empty msg', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const sig = EcdsaP256Suite.sign(sk, TINY_MSG, EMPTY_CTX);
		expect(sig.length).toBe(64);
		expect(EcdsaP256Suite.verify(pk, TINY_MSG, sig, EMPTY_CTX)).toBe(true);
	});

	it('sign + verify with 64-byte msg', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const sig = EcdsaP256Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(EcdsaP256Suite.verify(pk, TEST_MSG, sig, EMPTY_CTX)).toBe(true);
	});

	it('sign + verify with 1024-byte msg', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const sig = EcdsaP256Suite.sign(sk, BIG_MSG, EMPTY_CTX);
		expect(EcdsaP256Suite.verify(pk, BIG_MSG, sig, EMPTY_CTX)).toBe(true);
	});

	it('verify under wrong pk returns false', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const otherPk = EcdsaP256Suite.keygen().pk;
		const sig = EcdsaP256Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(EcdsaP256Suite.verify(otherPk, TEST_MSG, sig, EMPTY_CTX)).toBe(false);
	});

	it('verify against tampered msg returns false', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const sig = EcdsaP256Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		const tampered = TEST_MSG.slice();
		tampered[7] ^= 0x80;
		expect(EcdsaP256Suite.verify(pk, tampered, sig, EMPTY_CTX)).toBe(false);
	});
});

// ── Hedged-by-default sign behaviour ───────────────────────────────────────

describe('EcdsaP256Suite hedged-by-default', () => {
	// ECDSA-P256 suite-level sign generates fresh randomBytes(32) per call.
	// FIPS 186-5 §6.4 + draft-irtf-cfrg-det-sigs-with-noise-05: per-call
	// entropy hardens against fault-injection on the k derivation; two
	// signs of the same (sk, msg) produce different (r, s) pairs because
	// the noise input changes per call. This is the inverse of Ed25519's
	// determinism check (RFC 8032 §5.1.6 mandates pure determinism).

	it('two signs of the same (sk, msg) produce DIFFERENT signatures', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const a = EcdsaP256Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		const b = EcdsaP256Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(Array.from(a)).not.toEqual(Array.from(b));
		// Both must verify; hedging only affects sign output, not validity.
		expect(EcdsaP256Suite.verify(pk, TEST_MSG, a, EMPTY_CTX)).toBe(true);
		expect(EcdsaP256Suite.verify(pk, TEST_MSG, b, EMPTY_CTX)).toBe(true);
	});

	it('two signPrehashed of the same (sk, digest) produce DIFFERENT signatures', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const digest = new Uint8Array(32).map((_, i) => (i * 41 + 9) & 0xff);
		const a = EcdsaP256Suite.signPrehashed(sk, digest, EMPTY_CTX);
		const b = EcdsaP256Suite.signPrehashed(sk, digest, EMPTY_CTX);
		expect(Array.from(a)).not.toEqual(Array.from(b));
		expect(EcdsaP256Suite.verifyPrehashed(pk, digest, a, EMPTY_CTX)).toBe(true);
		expect(EcdsaP256Suite.verifyPrehashed(pk, digest, b, EMPTY_CTX)).toBe(true);
	});
});
