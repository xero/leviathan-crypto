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
// test/unit/sign/sign-ecdsa-p256-integration.test.ts
//
// Envelope + stream integration coverage for EcdsaP256Suite. The suite
// is hedged-by-default, so the suite-level KAT records carry only the
// RECEIVED rnd at generation time; we cannot expect byte-exact envelope
// reproduction through `Sign.sign`. Instead the integration grades
// round-trip behaviour: `Sign.verify` accepts every recorded blob,
// `Sign.peek` reports the documented offsets, and a fresh suite-level
// sign+verify cycle on the same (sk, msg) succeeds for every vector.
//
// Also exercises the detached path (`Sign.signDetached` /
// `Sign.verifyDetached`), cross-suite tamper (a flipped suite_byte
// rejects with sig-suite-mismatch), and the suite-bound ctx rejection
// at the envelope layer.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, hexToBytes } from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { WASM_GZ_BASE64 as p256Wasm } from '../../../src/ts/embedded/p256.js';
import { WASM_GZ_BASE64 as sha2Wasm } from '../../../src/ts/embedded/sha2.js';
import { WASM_GZ_BASE64 as curve25519Wasm } from '../../../src/ts/embedded/curve25519.js';
import {
	Sign,
	EcdsaP256Suite,
	Ed25519Suite,
} from '../../../src/ts/sign/index.js';
import { signEcdsaP256Vectors } from '../../vectors/sign_ecdsa_p256.js';

beforeAll(async () => {
	_resetForTesting();
	await init({
		p256: p256Wasm,
		sha2: sha2Wasm,
		ed25519: curve25519Wasm,
	});
});

const EMPTY_CTX = new Uint8Array(0);
const SMALL_CTX = new Uint8Array(10).map((_, i) => (i * 13 + 1) & 0xff);
const MSG       = new Uint8Array(128).map((_, i) => (i * 37 + 9) & 0xff);

// ── Envelope round-trip ────────────────────────────────────────────────────

describe('Sign envelope, EcdsaP256Suite', () => {
	it('Sign.sign + Sign.verify round-trips a fresh (sk, msg)', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const blob = Sign.sign(EcdsaP256Suite, sk, MSG, EMPTY_CTX);
		const out  = Sign.verify(EcdsaP256Suite, pk, blob, EMPTY_CTX);
		expect(Array.from(out)).toEqual(Array.from(MSG));
	});

	it('Sign.peek reports the documented offsets', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const blob = Sign.sign(EcdsaP256Suite, sk, MSG, EMPTY_CTX);
		const peek = Sign.peek(blob, EcdsaP256Suite);
		expect(peek.suiteByte).toBe(0x02);
		expect(peek.payloadLength).toBe(MSG.length);
		expect(peek.ctx.length).toBe(0);
		expect(peek.sigOffset).toBe(blob.length - 64);
	});

	it('blob layout is [0x02][0x00][payload][sig]', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const blob = Sign.sign(EcdsaP256Suite, sk, MSG, EMPTY_CTX);
		expect(blob[0]).toBe(0x02);
		expect(blob[1]).toBe(0x00);
		expect(blob.length).toBe(2 + MSG.length + 64);
	});
});

// ── Detached path ──────────────────────────────────────────────────────────

describe('Sign detached, EcdsaP256Suite', () => {
	it('Sign.signDetached returns 64 bytes raw r||s', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const sig = Sign.signDetached(EcdsaP256Suite, sk, MSG, EMPTY_CTX);
		expect(sig.length).toBe(64);
	});

	it('Sign.verifyDetached returns true for a fresh sig', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const sig = Sign.signDetached(EcdsaP256Suite, sk, MSG, EMPTY_CTX);
		expect(Sign.verifyDetached(EcdsaP256Suite, pk, MSG, sig, EMPTY_CTX))
			.toBe(true);
	});

	it('Sign.verifyDetached returns false under a wrong sig', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const sig = Sign.signDetached(EcdsaP256Suite, sk, MSG, EMPTY_CTX);
		const tampered = sig.slice();
		tampered[7] ^= 0x01;
		expect(Sign.verifyDetached(EcdsaP256Suite, pk, MSG, tampered, EMPTY_CTX))
			.toBe(false);
	});
});

// ── Suite-level KAT vector replay (round-trip, not byte-exact) ─────────────
//
// The suite is hedged-by-default: `Sign.sign(EcdsaP256Suite, sk, msg,
// ctx)` re-runs the underlying primitive with a fresh `randomBytes(32)`
// per call, so the wire bytes differ from the KAT-recorded `blobHex`.
// The KAT records exist to lock the WIRE FORMAT (envelope framing); the
// suite-level integration grades round-trip behaviour.

describe('sign_ecdsa_p256 KAT round-trip through EcdsaP256Suite', () => {
	it('has 7 vectors all at formatEnum 0x02', () => {
		expect(signEcdsaP256Vectors.length).toBe(7);
		for (const v of signEcdsaP256Vectors) expect(v.formatEnum).toBe(0x02);
	});

	it.each(signEcdsaP256Vectors)(
		'$id $description: recorded blob verifies + Sign.peek matches',
		(v) => {
			const pk   = hexToBytes(v.pkHex);
			const blob = hexToBytes(v.blobHex);
			const msg  = hexToBytes(v.msgHex);

			// 1) The recorded blob verifies through Sign.verify.
			const out = Sign.verify(EcdsaP256Suite, pk, blob, EMPTY_CTX);
			expect(Array.from(out)).toEqual(Array.from(msg));

			// 2) Sign.peek reports the documented offsets.
			const peek = Sign.peek(blob, EcdsaP256Suite);
			expect(peek.suiteByte).toBe(0x02);
			expect(peek.payloadLength).toBe(msg.length);
			expect(peek.ctx.length).toBe(0);
			expect(peek.payloadOffset).toBe(2);
			expect(peek.sigOffset).toBe(blob.length - 64);

			// 3) A fresh suite-level sign on the recorded (sk, msg) still
			//    round-trips (hedged: bytes differ, semantics identical).
			const sk = hexToBytes(v.skHex);
			const freshBlob = Sign.sign(EcdsaP256Suite, sk, msg, EMPTY_CTX);
			const freshOut  = Sign.verify(EcdsaP256Suite, pk, freshBlob, EMPTY_CTX);
			expect(Array.from(freshOut)).toEqual(Array.from(msg));
		},
	);
});

// ── ctx-rejection at the envelope layer ────────────────────────────────────

describe('Sign envelope ctx-rejection lock, EcdsaP256Suite', () => {
	it('Sign.sign with non-empty user_ctx propagates sig-ctx-unsupported', () => {
		const { sk } = EcdsaP256Suite.keygen();
		let caught: unknown;
		try {
			Sign.sign(EcdsaP256Suite, sk, MSG, SMALL_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-ctx-unsupported');
	});

	it('Sign.signDetached with non-empty user_ctx propagates sig-ctx-unsupported', () => {
		const { sk } = EcdsaP256Suite.keygen();
		let caught: unknown;
		try {
			Sign.signDetached(EcdsaP256Suite, sk, MSG, SMALL_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-ctx-unsupported');
	});
});

// ── Cross-suite tamper: 0x02 ↔ 0x01 ────────────────────────────────────────

describe('cross-suite tamper rejection (EcdsaP256Suite ↔ Ed25519Suite)', () => {
	it('ecdsa blob with suite_byte flipped to 0x01 fails Sign.verify(Ed25519Suite) or rejects', () => {
		// The wire byte determines which suite the verifier matches; flipping
		// the byte yields sig-suite-mismatch when the verifier was configured
		// with EcdsaP256Suite, and verify-failed when configured with
		// Ed25519Suite (the wire byte matches but the sig was produced
		// under different rules). Either rejection is in-spec.
		const { sk } = EcdsaP256Suite.keygen();
		const blob = Sign.sign(EcdsaP256Suite, sk, MSG, EMPTY_CTX);
		const tampered = blob.slice();
		tampered[0] = 0x01;
		let caught: unknown;
		try {
			Sign.verify(EcdsaP256Suite, hexToBytes('02' + '00'.repeat(32)), tampered, EMPTY_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-suite-mismatch');
	});

	it('ed25519 blob verified with EcdsaP256Suite rejects with sig-suite-mismatch', () => {
		const { sk } = Ed25519Suite.keygen();
		const blob = Sign.sign(Ed25519Suite, sk, MSG, EMPTY_CTX);
		// blob[0] === 0x01; verifier expects 0x02.
		let caught: unknown;
		try {
			Sign.verify(EcdsaP256Suite, hexToBytes('02' + '00'.repeat(32)), blob, EMPTY_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-suite-mismatch');
	});

	it('ecdsa blob with random pk on a different keypair returns verify-failed', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const blob = Sign.sign(EcdsaP256Suite, sk, MSG, EMPTY_CTX);
		// Verify with a different pk (still valid compressed P-256 pk) under
		// the same suite; sig won't validate.
		const otherPk = EcdsaP256Suite.keygen().pk;
		let caught: unknown;
		try {
			Sign.verify(EcdsaP256Suite, otherPk, blob, EMPTY_CTX);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('verify-failed');
	});
});
