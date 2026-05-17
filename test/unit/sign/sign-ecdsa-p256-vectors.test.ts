//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▒ ▄▀▄ █▀▄
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
// test/unit/sign/sign-ecdsa-p256-vectors.test.ts
//
// Tier 1 ECDSA-P256 corpus replay through the suite layer.
//
//   - RFC 6979 §A.2.5: drives EcdsaP256.signDeterministic with the
//     RFC-prescribed key and SHA-256 digest of the per-record message;
//     compares (r || s) byte-for-byte to the RFC expected. The suite
//     itself is hedged-by-default, so this side drops to the primitive
//     class for byte-exact reproduction. The suite still verifies the
//     resulting sig through `verifyPrehashed`.
//
//   - ACVP keyGen: drops to `EcdsaP256.keygenDerand(seed=d)` and asserts
//     the derived pk matches (qx, qy). The suite-level `keygen()` is
//     hedged from `randomBytes(32)`, so keygen KAT reproduction is the
//     primitive-class job; the suite is graded for round-trip behaviour.
//
//   - ACVP sigVer: drives `EcdsaP256Suite.verifyPrehashed(pk, hash, sig,
//     EMPTY_CTX)` and compares the boolean against ACVP's `testPassed`.
//     The library's strict-S posture (FIPS 186-5 §6.4.4 + RFC 6979 §3.5)
//     rejects high-S even on otherwise-valid records, so test-side
//     adjusts `testPassed` accordingly.
//
//   - Wycheproof: drives `verifyPrehashed` on every record and grades
//     against the 'valid' / 'invalid' / 'acceptable' discriminator. The
//     library is strict on signature malleability (low-S enforced and
//     non-canonical (r, s) encodings rejected), so records flagged
//     `BER` / `SignatureMalleability` etc. with `result='valid'` are
//     expected to REJECT under the strict-gate posture; the test
//     normalises the expectation to match leviathan-crypto's strict
//     stance.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, hexToBytes } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { WASM_GZ_BASE64 as p256Wasm } from '../../../src/ts/embedded/p256.js';
import { WASM_GZ_BASE64 as sha2Wasm } from '../../../src/ts/embedded/sha2.js';
import { EcdsaP256Suite } from '../../../src/ts/sign/index.js';
import { EcdsaP256 } from '../../../src/ts/ecdsa/index.js';
import { SHA256 } from '../../../src/ts/sha2/index.js';
import {
	RFC6979_P256_KEY,
	ecdsa_p256_rfc6979,
} from '../../vectors/ecdsa_p256.js';
import {
	ecdsa_p256_keygen_tg3,
	ecdsa_p256_keygen_tg4,
} from '../../vectors/ecdsa_p256_keygen.js';
import {
	ecdsa_p256_sigver_tg8,
} from '../../vectors/ecdsa_p256_sigver.js';
import {
	ecdsa_p256_wycheproof,
} from '../../vectors/ecdsa_p256_wycheproof.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ p256: p256Wasm, sha2: sha2Wasm });
});

const EMPTY_CTX = new Uint8Array(0);
const ZERO_RND  = new Uint8Array(32);
const utf8Enc   = new TextEncoder();

// P-256 group order n (SP 800-186 §3.2.1.3), used for strict-S detection.
const N_HEX =
	'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';

function sha256(msg: Uint8Array): Uint8Array {
	const h = new SHA256();
	try {
		return h.hash(msg);
	} finally {
		h.dispose();
	}
}

function compressedPk(qxHex: string, qyHex: string): Uint8Array {
	const qx = hexToBytes(qxHex);
	const qy = hexToBytes(qyHex);
	const out = new Uint8Array(33);
	out[0] = (qy[31] & 1) ? 0x03 : 0x02;
	out.set(qx, 1);
	return out;
}

function rsToSig(rHex: string, sHex: string): Uint8Array {
	const out = new Uint8Array(64);
	out.set(hexToBytes(rHex), 0);
	out.set(hexToBytes(sHex), 32);
	return out;
}

function isHighS(sHex: string): boolean {
	const n = BigInt('0x' + N_HEX);
	const s = BigInt('0x' + sHex);
	return s > (n >> 1n);
}

// ── RFC 6979 §A.2.5 deterministic-K replay ─────────────────────────────────
//
// The RFC's expected (r, s) is the canonical deterministic ECDSA result
// for SHA-256 over the literal-ASCII per-record message and the
// RFC §A.2.5 keypair. Reproducing it requires the deterministic-K path,
// which the EcdsaP256 class selects when rnd is all-zero (FIPS 186-5
// §6.4.1's conforming construction). The suite is hedged-only at the
// public API; dropping to the class is the only way to reproduce a
// byte-exact RFC 6979 r||s. The resulting sig still round-trips through
// the suite's `verifyPrehashed`.

// Compute the low-S form of s. The library enforces low-S on the sign
// side per RFC 6979 §3.5, so the s byte block in the produced sig is
// the canonical (s ≤ n/2) representative; RFC 6979 §A.2.5 records the
// high-S form for some messages, so the test normalises the RFC's s
// to its low-S equivalent before comparing.
function normaliseLowS(sHexBE: string): string {
	const n = BigInt('0x' + N_HEX);
	let s = BigInt('0x' + sHexBE);
	if (s > (n >> 1n)) s = n - s;
	const hex = s.toString(16).padStart(64, '0');
	return hex;
}

describe('RFC 6979 §A.2.5 replay through EcdsaP256Suite', () => {
	it.each(ecdsa_p256_rfc6979)(
		'$id: primitive reproduces RFC (r, low-S); suite verifyPrehashed accepts',
		(v) => {
			const skBytes = hexToBytes(RFC6979_P256_KEY.xHex);
			const inst = new EcdsaP256();
			let pkBytes: Uint8Array;
			let sig: Uint8Array;
			const msg = utf8Enc.encode(v.msgUtf8);
			const digest = sha256(msg);
			try {
				pkBytes = inst.keygenDerand(skBytes).publicKey;
				sig = inst._signInternalPk(skBytes, digest, ZERO_RND);
			} finally {
				inst.dispose();
			}
			const expectedSig = rsToSig(
				v.rHex.toLowerCase(),
				normaliseLowS(v.sHex.toLowerCase()),
			);
			expect(Array.from(sig)).toEqual(Array.from(expectedSig));
			expect(
				EcdsaP256Suite.verifyPrehashed(pkBytes, digest, sig, EMPTY_CTX),
			).toBe(true);
			expect(
				EcdsaP256Suite.verify(pkBytes, msg, sig, EMPTY_CTX),
			).toBe(true);
		},
	);
});

// ── ACVP keyGen: pk derivation through the primitive class ────────────────

const ACVP_KEYGEN = [...ecdsa_p256_keygen_tg3, ...ecdsa_p256_keygen_tg4];

describe('ACVP ECDSA-P256 keyGen replay through EcdsaP256 (suite-adjacent)', () => {
	it.each(ACVP_KEYGEN)(
		'tcId $tcId: keygenDerand(d) produces (qx, qy)',
		(v) => {
			const seed = hexToBytes(v.d.toLowerCase());
			const inst = new EcdsaP256();
			let pk: Uint8Array;
			try {
				pk = inst.keygenDerand(seed).publicKey;
			} finally {
				inst.dispose();
			}
			const expected = compressedPk(v.qx.toLowerCase(), v.qy.toLowerCase());
			expect(Array.from(pk)).toEqual(Array.from(expected));
		},
	);
});

// ── ACVP sigVer replay through the suite ──────────────────────────────────

describe('ACVP ECDSA-P256 sigVer replay through EcdsaP256Suite.verifyPrehashed', () => {
	it.each(ecdsa_p256_sigver_tg8)(
		'tcId $tcId "$reason": suite verifyPrehashed matches ACVP testPassed (strict-S)',
		(v) => {
			const pk     = compressedPk(v.qx.toLowerCase(), v.qy.toLowerCase());
			const digest = sha256(hexToBytes(v.message));
			const sig    = rsToSig(v.r.toLowerCase(), v.s.toLowerCase());
			// FIPS 186-5 §6.4.4 + RFC 6979 §3.5: strict-S rejects high-S sigs
			// that ACVP marks testPassed. Adjust expectation to match the
			// library's posture.
			const expected = v.testPassed && !isHighS(v.s);
			expect(
				EcdsaP256Suite.verifyPrehashed(pk, digest, sig, EMPTY_CTX),
			).toBe(expected);
		},
	);
});

// ── Wycheproof replay through the suite (strict gate) ─────────────────────
//
// Strict posture: leviathan-crypto rejects high-S, non-canonical (r, s)
// encodings, and any sig whose byte length is not exactly 64. Wycheproof
// flags records under malleability / range-check categories as
// `result='valid'` when a non-strict oracle would accept them, so the
// expected boolean is adjusted: a 'valid' record passes only if its
// (r, s) are canonical AND s is low-S AND the sig is exactly 64 bytes.
// An 'invalid' record must always fail. 'acceptable' records (none in
// the p1363 file at this writing, but accepted by the parser schema)
// are LOGGED only, no assertion.

describe('Wycheproof ECDSA-P256 replay through EcdsaP256Suite.verifyPrehashed (strict gate)', () => {
	it.each(ecdsa_p256_wycheproof)(
		'tcId $tcId "$comment" (result=$result)',
		(v) => {
			if (v.result === 'acceptable') return;
			const pk = compressedPk(v.qx.toLowerCase(), v.qy.toLowerCase());
			const digest = sha256(hexToBytes(v.msgHex));

			// Strict-gate normalisation: a sig that is not exactly 64 bytes
			// is rejected at the primitive-level validation throw. The suite
			// re-throws as a contract violation, not a verification false.
			// Catch that and treat it as a boolean false for grading.
			const sigBytes = hexToBytes(v.sigHex);
			let actual: boolean;
			try {
				if (sigBytes.length !== 64) {
					actual = false;
				} else {
					actual = EcdsaP256Suite.verifyPrehashed(pk, digest, sigBytes, EMPTY_CTX);
				}
			} catch {
				actual = false;
			}

			// Compute strict-posture expectation:
			// - 'invalid': must be false.
			// - 'valid':   true only if sig is 64 bytes and s is low-S.
			let expected: boolean;
			if (v.result === 'invalid') {
				expected = false;
			} else {
				// 'valid' under strict posture
				if (sigBytes.length !== 64) {
					expected = false;
				} else {
					const sHex = v.sigHex.toLowerCase().slice(64, 128);
					expected = !isHighS(sHex);
				}
			}
			expect(actual).toBe(expected);
		},
	);
});
