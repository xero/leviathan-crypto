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
// test/unit/sign/helpers.ts
//
// Fixture SignatureSuite used by envelope/stream tests that don't need a
// real cryptographic primitive. The envelope wire format is what's under
// test. Deterministic, no WASM, no cryptographic strength.

import { constantTimeEqual } from '../../../src/ts/utils.js';
import { SigningError } from '../../../src/ts/errors.js';
import { SHA3_256 } from '../../../src/ts/sha3/index.js';
import type {
	SignatureSuite, StreamableSignatureSuite,
} from '../../../src/ts/sign/index.js';

export const FIXTURE_PK_SIZE = 32;
export const FIXTURE_SK_SIZE = 32;
export const FIXTURE_SIG_SIZE = 64;
export const FIXTURE_FORMAT_ENUM = 0xff;
export const FIXTURE_USER_CTX_MAX = 255;

/**
 * Deterministic mock signature.
 * sig[i] = sk[i mod 32]
 *        ^ (msg.length > 0 ? msg[i mod msg.length] : 0)
 *        ^ (ctx.length > 0 ? ctx[i mod ctx.length] : 0)
 *        ^ (i & 0xff)
 */
function fixtureSign(
	sk: Uint8Array,
	msg: Uint8Array,
	ctx: Uint8Array,
): Uint8Array {
	if (sk.length !== FIXTURE_SK_SIZE)
		throw new SigningError(
			'sig-key-size',
			`fixture sk length ${sk.length} != ${FIXTURE_SK_SIZE}`,
		);
	if (ctx.length > FIXTURE_USER_CTX_MAX)
		throw new SigningError(
			'sig-ctx-too-long',
			`fixture ctx length ${ctx.length} > ${FIXTURE_USER_CTX_MAX}`,
		);
	const sig = new Uint8Array(FIXTURE_SIG_SIZE);
	for (let i = 0; i < FIXTURE_SIG_SIZE; i++) {
		const s = sk[i % FIXTURE_SK_SIZE];
		const m = msg.length > 0 ? msg[i % msg.length] : 0;
		const c = ctx.length > 0 ? ctx[i % ctx.length] : 0;
		sig[i] = (s ^ m ^ c ^ (i & 0xff)) & 0xff;
	}
	return sig;
}

function fixtureVerify(
	pk: Uint8Array,
	msg: Uint8Array,
	sig: Uint8Array,
	ctx: Uint8Array,
): boolean {
	if (pk.length !== FIXTURE_PK_SIZE)
		throw new SigningError(
			'sig-key-size',
			`fixture pk length ${pk.length} != ${FIXTURE_PK_SIZE}`,
		);
	if (ctx.length > FIXTURE_USER_CTX_MAX)
		throw new SigningError(
			'sig-ctx-too-long',
			`fixture ctx length ${ctx.length} > ${FIXTURE_USER_CTX_MAX}`,
		);
	if (sig.length !== FIXTURE_SIG_SIZE) return false;
	const expected = fixtureSign(pk, msg, ctx);
	return constantTimeEqual(expected, sig);
}

/**
 * Construct a fresh fixture suite. Each call returns a new object so tests
 * that mutate (e.g. spy on sign) don't bleed into each other.
 */
export function makeFixtureSuite(): SignatureSuite {
	return {
		formatEnum: FIXTURE_FORMAT_ENUM,
		formatName: 'fixture',
		ctxDomain: 'fixture-envelope-v3',
		pkSize: FIXTURE_PK_SIZE,
		skSize: FIXTURE_SK_SIZE,
		sigMaxSize: FIXTURE_SIG_SIZE,
		wasmModules: [],
		sign: fixtureSign,
		verify: fixtureVerify,
		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			// pk === sk for the fixture so verify can reproduce sig.
			const sk = new Uint8Array(FIXTURE_SK_SIZE);
			for (let i = 0; i < FIXTURE_SK_SIZE; i++) sk[i] = i;
			return { pk: sk.slice(), sk };
		},
	};
}

/** Deterministic 32-byte fixture sk = pk = [0x00, 0x01, ..., 0x1f]. */
export function fixtureSk(): Uint8Array {
	const sk = new Uint8Array(FIXTURE_SK_SIZE);
	for (let i = 0; i < FIXTURE_SK_SIZE; i++) sk[i] = i;
	return sk;
}

// ── Streamable fixture suite ────────────────────────────────────────────────

/** Wire byte for the streamable fixture (distinct from the pure fixture). */
export const FIXTURE_STREAM_FORMAT_ENUM = 0xfe;

/** Prehash size for the streamable fixture (SHA3-256). */
export const FIXTURE_STREAM_PREHASH_SIZE = 32;

function sha3_256(msg: Uint8Array): Uint8Array {
	const h = new SHA3_256();
	try {
		return h.hash(msg);
	} finally {
		h.dispose();
	}
}

function fixtureSignPrehashed(
	sk: Uint8Array,
	digest: Uint8Array,
	ctx: Uint8Array,
): Uint8Array {
	if (sk.length !== FIXTURE_SK_SIZE)
		throw new SigningError(
			'sig-key-size',
			`fixture sk length ${sk.length} != ${FIXTURE_SK_SIZE}`,
		);
	if (digest.length !== FIXTURE_STREAM_PREHASH_SIZE)
		throw new SigningError(
			'sig-malformed-input',
			`fixture digest length ${digest.length} != ${FIXTURE_STREAM_PREHASH_SIZE}`,
		);
	if (ctx.length > FIXTURE_USER_CTX_MAX)
		throw new SigningError(
			'sig-ctx-too-long',
			`fixture ctx length ${ctx.length} > ${FIXTURE_USER_CTX_MAX}`,
		);
	const sig = new Uint8Array(FIXTURE_SIG_SIZE);
	for (let i = 0; i < FIXTURE_SIG_SIZE; i++) {
		const s = sk[i % FIXTURE_SK_SIZE];
		const d = digest[i % digest.length];
		const c = ctx.length > 0 ? ctx[i % ctx.length] : 0;
		sig[i] = (s ^ d ^ c ^ (i & 0xff)) & 0xff;
	}
	return sig;
}

function fixtureVerifyPrehashed(
	pk: Uint8Array,
	digest: Uint8Array,
	sig: Uint8Array,
	ctx: Uint8Array,
): boolean {
	if (pk.length !== FIXTURE_PK_SIZE)
		throw new SigningError(
			'sig-key-size',
			`fixture pk length ${pk.length} != ${FIXTURE_PK_SIZE}`,
		);
	if (ctx.length > FIXTURE_USER_CTX_MAX)
		throw new SigningError(
			'sig-ctx-too-long',
			`fixture ctx length ${ctx.length} > ${FIXTURE_USER_CTX_MAX}`,
		);
	if (digest.length !== FIXTURE_STREAM_PREHASH_SIZE) return false;
	if (sig.length !== FIXTURE_SIG_SIZE) return false;
	const expected = fixtureSignPrehashed(pk, digest, ctx);
	return constantTimeEqual(expected, sig);
}

/**
 * Streamable fixture suite. `sign(sk, msg, ctx)` is implemented as
 * `signPrehashed(sk, sha3-256(msg), ctx)` so SignStream output is
 * byte-identical to Sign.sign output for the same inputs.
 */
export function makeStreamableFixtureSuite(): StreamableSignatureSuite {
	return {
		formatEnum: FIXTURE_STREAM_FORMAT_ENUM,
		formatName: 'fixture-prehash',
		ctxDomain: 'fixture-prehash-envelope-v3',
		pkSize: FIXTURE_PK_SIZE,
		skSize: FIXTURE_SK_SIZE,
		sigMaxSize: FIXTURE_SIG_SIZE,
		wasmModules: ['sha3'],
		prehashAlgorithm: 'sha3-256',
		prehashSize: FIXTURE_STREAM_PREHASH_SIZE,
		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			return fixtureSignPrehashed(sk, sha3_256(msg), ctx);
		},
		verify(
			pk: Uint8Array, msg: Uint8Array,
			sig: Uint8Array, ctx: Uint8Array,
		): boolean {
			return fixtureVerifyPrehashed(pk, sha3_256(msg), sig, ctx);
		},
		signPrehashed: fixtureSignPrehashed,
		verifyPrehashed: fixtureVerifyPrehashed,
		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const sk = new Uint8Array(FIXTURE_SK_SIZE);
			for (let i = 0; i < FIXTURE_SK_SIZE; i++) sk[i] = i;
			return { pk: sk.slice(), sk };
		},
	};
}
