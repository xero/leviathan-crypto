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
// test/unit/sign/sign-ed25519-integration.test.ts
//
// Envelope + stream integration for Ed25519Suite / Ed25519PreHashSuite,
// with RFC 8032 §7.1 + ACVP §7.3 spot-checks. See
// docs/ed25519.md#suite-integration.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, hexToBytes, concat } from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { WASM_GZ_BASE64 as curve25519Wasm } from '../../../src/ts/embedded/curve25519.js';
import { WASM_GZ_BASE64 as sha2Wasm } from '../../../src/ts/embedded/sha2.js';
import {
	Sign, SignStream, VerifyStream,
	Ed25519Suite, Ed25519PreHashSuite,
} from '../../../src/ts/sign/index.js';
import { ed25519Vectors } from '../../vectors/ed25519.js';
import {
	ed25519_siggen_tg1, ed25519_siggen_tg2,
} from '../../vectors/ed25519_siggen.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ ed25519: curve25519Wasm, sha2: sha2Wasm });
});

const EMPTY = new Uint8Array(0);
const CTX   = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
const MSG   = new Uint8Array(128).map((_, i) => (i * 37 + 9) & 0xff);

// ── Envelope round-trip, both suites ───────────────────────────────────────

describe('Sign envelope, Ed25519Suite (pure)', () => {
	it('round-trips msg through real Ed25519 sign/verify (empty ctx)', () => {
		const { pk, sk } = Ed25519Suite.keygen();
		const blob = Sign.sign(Ed25519Suite, sk, MSG, EMPTY);
		const out  = Sign.verify(Ed25519Suite, pk, blob, EMPTY);
		expect(Array.from(out)).toEqual(Array.from(MSG));
	});

	it('peek matches envelope structure', () => {
		const { sk } = Ed25519Suite.keygen();
		const blob = Sign.sign(Ed25519Suite, sk, MSG, EMPTY);
		const peek = Sign.peek(blob, Ed25519Suite);
		expect(peek.suiteByte).toBe(0x01);
		expect(peek.payloadLength).toBe(MSG.length);
		expect(peek.ctx.length).toBe(0);
		expect(peek.sigOffset).toBe(blob.length - 64);
	});
});

describe('Sign envelope, Ed25519PreHashSuite (Ed25519ph)', () => {
	it('round-trips msg through real Ed25519ph + SHA-512 prehash', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const blob = Sign.sign(Ed25519PreHashSuite, sk, MSG, CTX);
		const out  = Sign.verify(Ed25519PreHashSuite, pk, blob, CTX);
		expect(Array.from(out)).toEqual(Array.from(MSG));
	});

	it('verify with wrong ctx throws sig-ctx-mismatch', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const blob = Sign.sign(Ed25519PreHashSuite, sk, MSG, CTX);
		const wrongCtx = new Uint8Array([0x01, 0x02, 0x03]);
		let caught: unknown;
		try {
			Sign.verify(Ed25519PreHashSuite, pk, blob, wrongCtx);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-ctx-mismatch');
	});
});

// ── SignStream + VerifyStream round-trip (prehash) ─────────────────────────

describe('SignStream + VerifyStream, Ed25519PreHashSuite', () => {
	it('streaming sign output verifies via Sign.verify', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const s = new SignStream(Ed25519PreHashSuite, sk, CTX);
		try {
			s.update(MSG.subarray(0, 32));
			s.update(MSG.subarray(32, 96));
			s.update(MSG.subarray(96));
			const sig = s.finalize();
			const blob = concat(s.buildPreamble(MSG.length), MSG, sig);
			const out  = Sign.verify(Ed25519PreHashSuite, pk, blob, CTX);
			expect(Array.from(out)).toEqual(Array.from(MSG));
		} finally {
			s.dispose();
		}
	});

	it('VerifyStream consumes the streamed blob and returns the msg', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const s = new SignStream(Ed25519PreHashSuite, sk, CTX);
		let blob: Uint8Array;
		try {
			s.update(MSG);
			const sig = s.finalize();
			blob = concat(s.buildPreamble(MSG.length), MSG, sig);
		} finally {
			s.dispose();
		}

		const v = new VerifyStream(Ed25519PreHashSuite, pk, CTX);
		try {
			v.update(blob.subarray(0, 1));
			v.update(blob.subarray(1));
			const out = v.finalize();
			expect(Array.from(out)).toEqual(Array.from(MSG));
		} finally {
			v.dispose();
		}
	});
});

// ── RFC 8032 §7.1 cross-check: pure suite reproduces the spec sigs ─────────

const RFC_PURE = ed25519Vectors.filter((v) => v.mode === 'pure');

describe('RFC 8032 §7.1 cross-check (Ed25519Suite)', () => {
	it.each(RFC_PURE)(
		'pure record with sk=$skHex round-trips against the suite',
		(v) => {
			const sk  = hexToBytes(v.skHex);
			const pk  = hexToBytes(v.pkHex);
			const msg = hexToBytes(v.msgHex);
			const expectedSig = hexToBytes(v.sigHex);
			const blob = Sign.sign(Ed25519Suite, sk, msg, EMPTY);
			// Envelope = [0x01, 0x00, msg..., sig...]; the last 64 bytes are sig.
			const sig = blob.subarray(blob.length - 64);
			expect(Array.from(sig)).toEqual(Array.from(expectedSig));
			const out = Sign.verify(Ed25519Suite, pk, blob, EMPTY);
			expect(Array.from(out)).toEqual(Array.from(msg));
		},
	);
});

// ── ACVP sigGen spot-check, pure records with empty context ────────────────

const ACVP_PURE_EMPTY = ed25519_siggen_tg1.filter((v) => v.context === '').slice(0, 4);

describe('ACVP sigGen spot-check, Ed25519Suite (preHash=null, empty ctx)', () => {
	it.each(ACVP_PURE_EMPTY)(
		'tcId=$tcId round-trips against the suite',
		(v) => {
			const sk  = hexToBytes(v.sk);
			const pk  = hexToBytes(v.pk);
			const msg = hexToBytes(v.message);
			const expectedSig = hexToBytes(v.signature);
			const blob = Sign.sign(Ed25519Suite, sk, msg, EMPTY);
			const sig = blob.subarray(blob.length - 64);
			expect(Array.from(sig)).toEqual(Array.from(expectedSig));
			const out = Sign.verify(Ed25519Suite, pk, blob, EMPTY);
			expect(Array.from(out)).toEqual(Array.from(msg));
		},
	);
});

// ── ACVP sigGen spot-check, prehash records ────────────────────────────────
//
// ACVP Ed25519ph records feed `context` directly into dom2; the v3 suite
// instead wraps user_ctx into effective_ctx with the ctxDomain prefix
// before passing it to dom2. So we can't compare suite output to ACVP
// `signature` bytes directly. We can still confirm that a sig produced by
// the suite verifies through the suite for the same (sk, msg, ctx).

const ACVP_PH = ed25519_siggen_tg2.slice(0, 3);

describe('ACVP sigGen spot-check, Ed25519PreHashSuite (preHash=SHA-512)', () => {
	it.each(ACVP_PH)(
		'tcId=$tcId round-trips through the suite (suite-bound ctx)',
		(v) => {
			const sk  = hexToBytes(v.sk);
			const pk  = hexToBytes(v.pk);
			const msg = hexToBytes(v.message);
			const ctx = hexToBytes(v.context);
			// Ed25519PreHashSuite's effective per-call user_ctx ceiling is
			// 226 = 253 - len('ed25519-prehash-envelope-v3' 27 bytes), set by
			// buildEffectiveCtx's combined-length cap (FIPS 204 §3.6.1).
			// Longer ACVP context strings still meet USER_CTX_MAX = 255 in the
			// abstract but trip the combined cap when wrapped by this suite.
			if (ctx.length > 226) return;
			const blob = Sign.sign(Ed25519PreHashSuite, sk, msg, ctx);
			const out  = Sign.verify(Ed25519PreHashSuite, pk, blob, ctx);
			expect(Array.from(out)).toEqual(Array.from(msg));
		},
	);
});

// ── Cross-mode tamper: 0x01 ↔ 0x11 suite-byte flip rejected ────────────────
//
// Two-axis cross-check: a flipped suite_byte is caught either by the
// envelope's catalog gate (`sig-suite-mismatch` when the wire byte
// disagrees with the configured suite) or by the underlying primitive
// (`verify-failed` when the wire byte matches the chosen suite but the
// sig was produced under a different mode). Both failure modes are
// in-spec rejections; the test just confirms there is no path through.

describe('cross-mode tamper rejection (formatEnum 0x01 ↔ 0x11)', () => {
	it('pure blob with tampered 0x11 byte, verify with pure suite → sig-suite-mismatch', () => {
		const { pk, sk } = Ed25519Suite.keygen();
		const blob = Sign.sign(Ed25519Suite, sk, MSG, EMPTY);
		const tampered = blob.slice();
		tampered[0] = 0x11;
		let caught: unknown;
		try {
			Sign.verify(Ed25519Suite, pk, tampered, EMPTY);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-suite-mismatch');
	});

	it('pure blob with tampered 0x11 byte, verify with prehash suite → verify-failed', () => {
		const { sk } = Ed25519Suite.keygen();
		const blob = Sign.sign(Ed25519Suite, sk, MSG, EMPTY);
		const tampered = blob.slice();
		tampered[0] = 0x11;
		const phPk = Ed25519PreHashSuite.keygen().pk;
		let caught: unknown;
		try {
			Sign.verify(Ed25519PreHashSuite, phPk, tampered, EMPTY);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('verify-failed');
	});

	it('prehash blob with tampered 0x01 byte, verify with prehash suite → sig-suite-mismatch', () => {
		const { pk, sk } = Ed25519PreHashSuite.keygen();
		const blob = Sign.sign(Ed25519PreHashSuite, sk, MSG, EMPTY);
		const tampered = blob.slice();
		tampered[0] = 0x01;
		let caught: unknown;
		try {
			Sign.verify(Ed25519PreHashSuite, pk, tampered, EMPTY);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-suite-mismatch');
	});

	it('prehash blob with tampered 0x01 byte, verify with pure suite → verify-failed', () => {
		const { sk } = Ed25519PreHashSuite.keygen();
		const blob = Sign.sign(Ed25519PreHashSuite, sk, MSG, EMPTY);
		const tampered = blob.slice();
		tampered[0] = 0x01;
		const purePk = Ed25519Suite.keygen().pk;
		let caught: unknown;
		try {
			Sign.verify(Ed25519Suite, purePk, tampered, EMPTY);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('verify-failed');
	});
});
