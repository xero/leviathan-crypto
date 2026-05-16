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
// test/unit/sign/sign-ed25519-suites.test.ts
//
// Surface and round-trip coverage for the two exported Ed25519 suite
// consts (Ed25519Suite, Ed25519PreHashSuite). Asserts catalog format
// bytes, ctxDomain naming, wasmModules immutability, key and signature
// sizes, the pure-suite ctx-rejection lock, prehash digest-size
// validation, deterministic-sign byte-stability, and basic
// sign/verify round-trip with empty, small, and USER_CTX_MAX ctx.
// Mirrors sign-mldsa-suites.test.ts adapted for Ed25519's determinism
// and the pure-mode ctx-unsupported lock.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, utf8ToBytes } from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { WASM_GZ_BASE64 as curve25519Wasm } from '../../../src/ts/embedded/curve25519.js';
import { WASM_GZ_BASE64 as sha2Wasm } from '../../../src/ts/embedded/sha2.js';
import {
	Ed25519Suite, Ed25519PreHashSuite,
	CTX_DOMAIN_MAX,
} from '../../../src/ts/sign/index.js';
import type {
	SignatureSuite,
	StreamableSignatureSuite,
} from '../../../src/ts/sign/index.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ ed25519: curve25519Wasm, sha2: sha2Wasm });
});

// ── Catalog assignments, locked at suite construction ──────────────────────

describe('Ed25519Suite surface', () => {
	it('has formatEnum 0x01 and formatName "ed25519"', () => {
		expect(Ed25519Suite.formatEnum).toBe(0x01);
		expect(Ed25519Suite.formatName).toBe('ed25519');
	});

	it('has ctxDomain "ed25519-envelope-v3" within CTX_DOMAIN_MAX', () => {
		expect(Ed25519Suite.ctxDomain).toBe('ed25519-envelope-v3');
		expect(utf8ToBytes(Ed25519Suite.ctxDomain).length)
			.toBeLessThanOrEqual(CTX_DOMAIN_MAX);
	});

	it('has 32-byte pk/sk and 64-byte sig', () => {
		expect(Ed25519Suite.pkSize).toBe(32);
		expect(Ed25519Suite.skSize).toBe(32);
		expect(Ed25519Suite.sigSize).toBe(64);
	});

	it('advertises ["curve25519"] wasmModules, frozen', () => {
		expect(Array.from(Ed25519Suite.wasmModules)).toEqual(['curve25519']);
		expect(Object.isFrozen(Ed25519Suite.wasmModules)).toBe(true);
	});

	it('does NOT advertise prehashAlgorithm / prehashSize (pure suite)', () => {
		const asAny = Ed25519Suite as unknown as Record<string, unknown>;
		expect(asAny.prehashAlgorithm).toBeUndefined();
		expect(asAny.prehashSize).toBeUndefined();
		expect(asAny.signPrehashed).toBeUndefined();
		expect(asAny.verifyPrehashed).toBeUndefined();
	});
});

describe('Ed25519PreHashSuite surface', () => {
	it('has formatEnum 0x11 and formatName "ed25519-prehash"', () => {
		expect(Ed25519PreHashSuite.formatEnum).toBe(0x11);
		expect(Ed25519PreHashSuite.formatName).toBe('ed25519-prehash');
	});

	it('has ctxDomain "ed25519-prehash-envelope-v3" within CTX_DOMAIN_MAX', () => {
		expect(Ed25519PreHashSuite.ctxDomain).toBe('ed25519-prehash-envelope-v3');
		expect(utf8ToBytes(Ed25519PreHashSuite.ctxDomain).length)
			.toBeLessThanOrEqual(CTX_DOMAIN_MAX);
	});

	it('has 32-byte pk/sk and 64-byte sig', () => {
		expect(Ed25519PreHashSuite.pkSize).toBe(32);
		expect(Ed25519PreHashSuite.skSize).toBe(32);
		expect(Ed25519PreHashSuite.sigSize).toBe(64);
	});

	it('advertises ["curve25519","sha2"] wasmModules, frozen', () => {
		expect(Array.from(Ed25519PreHashSuite.wasmModules))
			.toEqual(['curve25519', 'sha2']);
		expect(Object.isFrozen(Ed25519PreHashSuite.wasmModules)).toBe(true);
	});

	it('locks prehashAlgorithm to "sha-512" and prehashSize 64', () => {
		expect(Ed25519PreHashSuite.prehashAlgorithm).toBe('sha-512');
		expect(Ed25519PreHashSuite.prehashSize).toBe(64);
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

const EMPTY_CTX = new Uint8Array(0);
const SMALL_CTX = new Uint8Array(10).map((_, i) => (i * 13 + 7) & 0xff);
const LARGE_CTX = new Uint8Array(200).map((_, i) => (i * 31 + 5) & 0xff);
const OVER_CTX  = new Uint8Array(201).map((_, i) => (i * 17 + 1) & 0xff);
const TEST_MSG  = new Uint8Array(64).map((_, i) => (i * 17 + 3) & 0xff);

// ── Pure suite: ctx rejection lock + round-trip ────────────────────────────

describe('Ed25519Suite pure-mode lock', () => {
	it('sign(sk, msg, empty_ctx) succeeds', () => {
		const { pk, sk } = Ed25519Suite.keygen();
		const sig = Ed25519Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(sig.length).toBe(64);
		expect(Ed25519Suite.verify(pk, TEST_MSG, sig, EMPTY_CTX)).toBe(true);
	});

	it('sign with non-empty user_ctx throws sig-ctx-unsupported', () => {
		const { sk } = Ed25519Suite.keygen();
		const err = captureSigningError(
			() => Ed25519Suite.sign(sk, TEST_MSG, SMALL_CTX),
		);
		expect(err.discriminator).toBe('sig-ctx-unsupported');
	});

	it('verify with non-empty user_ctx throws sig-ctx-unsupported', () => {
		const { pk, sk } = Ed25519Suite.keygen();
		const sig = Ed25519Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		const err = captureSigningError(
			() => Ed25519Suite.verify(pk, TEST_MSG, sig, SMALL_CTX),
		);
		expect(err.discriminator).toBe('sig-ctx-unsupported');
	});

	it('keygen returns 32-byte pk and 32-byte sk', () => {
		const { pk, sk } = Ed25519Suite.keygen();
		expect(pk.length).toBe(32);
		expect(sk.length).toBe(32);
	});

	it('sign is deterministic per RFC 8032 §5.1.6', () => {
		const { sk } = Ed25519Suite.keygen();
		const a = Ed25519Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		const b = Ed25519Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(Array.from(a)).toEqual(Array.from(b));
	});

	it('verify under wrong pk returns false', () => {
		const { sk } = Ed25519Suite.keygen();
		const otherPk = Ed25519Suite.keygen().pk;
		const sig = Ed25519Suite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(Ed25519Suite.verify(otherPk, TEST_MSG, sig, EMPTY_CTX)).toBe(false);
	});
});

// ── Prehash suite: round-trip + ctx binding + digest contract ──────────────

describe('Ed25519PreHashSuite round-trip', () => {
	it('sign + verify with empty ctx', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const sig = Ed25519PreHashSuite.sign(sk, TEST_MSG, EMPTY_CTX);
		expect(sig.length).toBe(64);
		expect(Ed25519PreHashSuite.verify(pk, TEST_MSG, sig, EMPTY_CTX)).toBe(true);
	});

	it('sign + verify with 10-byte ctx', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const sig = Ed25519PreHashSuite.sign(sk, TEST_MSG, SMALL_CTX);
		expect(Ed25519PreHashSuite.verify(pk, TEST_MSG, sig, SMALL_CTX)).toBe(true);
	});

	it('sign + verify with 200-byte ctx (USER_CTX_MAX)', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const sig = Ed25519PreHashSuite.sign(sk, TEST_MSG, LARGE_CTX);
		expect(Ed25519PreHashSuite.verify(pk, TEST_MSG, sig, LARGE_CTX)).toBe(true);
	});

	it('domain separation: same (sk, msg), different ctx → different sig', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const sigA = Ed25519PreHashSuite.sign(sk, TEST_MSG, EMPTY_CTX);
		const sigB = Ed25519PreHashSuite.sign(sk, TEST_MSG, SMALL_CTX);
		expect(Array.from(sigA)).not.toEqual(Array.from(sigB));
		expect(Ed25519PreHashSuite.verify(pk, TEST_MSG, sigA, SMALL_CTX)).toBe(false);
		expect(Ed25519PreHashSuite.verify(pk, TEST_MSG, sigB, EMPTY_CTX)).toBe(false);
	});

	it('sign is deterministic per RFC 8032 §5.1.7', () => {
		const { sk } = Ed25519PreHashSuite.keygen();
		const a = Ed25519PreHashSuite.sign(sk, TEST_MSG, SMALL_CTX);
		const b = Ed25519PreHashSuite.sign(sk, TEST_MSG, SMALL_CTX);
		expect(Array.from(a)).toEqual(Array.from(b));
	});

	it('sign with 201-byte ctx throws sig-ctx-too-long', () => {
		const { sk } = Ed25519PreHashSuite.keygen();
		const err = captureSigningError(
			() => Ed25519PreHashSuite.sign(sk, TEST_MSG, OVER_CTX),
		);
		expect(err.discriminator).toBe('sig-ctx-too-long');
	});
});

describe('Ed25519PreHashSuite digest contract', () => {
	it('signPrehashed with correct-size digest verifies', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const digest = new Uint8Array(64).map((_, i) => (i * 19 + 11) & 0xff);
		const sig = Ed25519PreHashSuite.signPrehashed(sk, digest, SMALL_CTX);
		expect(sig.length).toBe(64);
		expect(Ed25519PreHashSuite.verifyPrehashed(pk, digest, sig, SMALL_CTX))
			.toBe(true);
	});

	it('signPrehashed with wrong-size digest throws sig-malformed-input', () => {
		const { sk } = Ed25519PreHashSuite.keygen();
		const bad = new Uint8Array(65);
		const err = captureSigningError(
			() => Ed25519PreHashSuite.signPrehashed(sk, bad, SMALL_CTX),
		);
		expect(err.discriminator).toBe('sig-malformed-input');
	});

	it('verifyPrehashed with wrong-size digest throws sig-malformed-input', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const digest = new Uint8Array(64).map((_, i) => (i * 23 + 1) & 0xff);
		const sig = Ed25519PreHashSuite.signPrehashed(sk, digest, EMPTY_CTX);
		const bad = new Uint8Array(65);
		const err = captureSigningError(
			() => Ed25519PreHashSuite.verifyPrehashed(pk, bad, sig, EMPTY_CTX),
		);
		expect(err.discriminator).toBe('sig-malformed-input');
	});

	it('type-level: Ed25519PreHashSuite conforms to StreamableSignatureSuite', () => {
		const ss: StreamableSignatureSuite = Ed25519PreHashSuite;
		const _ss: SignatureSuite = ss;
		expect(ss.prehashAlgorithm).toBe('sha-512');
		expect(_ss.formatEnum).toBe(0x11);
	});
});
