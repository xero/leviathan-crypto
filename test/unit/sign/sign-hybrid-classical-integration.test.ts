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
// test/unit/sign/sign-hybrid-classical-integration.test.ts
//
// Envelope + stream integration for the four classical+PQ composite
// hybrid suites (draft-ietf-lamps-pq-composite-sigs-19; composite-sigs
// §10.5 external prehash, §6 Pre-Hash, §2.2 / §3.2 M', §4.3 PQ-first).
// See docs/signaturesuite.md#hybrid-classicalpq-integration.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, utf8ToBytes, concat } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm }   from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }    from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm }    from '../../../src/ts/sha2/embedded.js';
import { ed25519Wasm } from '../../../src/ts/ed25519/embedded.js';
import { p256Wasm }    from '../../../src/ts/ecdsa/embedded.js';
import {
	Sign, SignStream, VerifyStream,
} from '../../../src/ts/sign/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import type { StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import {
	MlDsa44Ed25519Suite,
	MlDsa65Ed25519Suite,
	MlDsa44EcdsaP256Suite,
	MlDsa65EcdsaP256Suite,
} from '../../../src/ts/sign/suites/hybrid-classical.js';
import {
	MlDsa44, MlDsa65, MLDSA44, MLDSA65,
} from '../../../src/ts/mldsa/index.js';
import type { MlDsaParams } from '../../../src/ts/mldsa/index.js';
import { Ed25519 } from '../../../src/ts/ed25519/index.js';
import { EcdsaP256, decodeEcPrivateKey } from '../../../src/ts/ecdsa/index.js';
import { ecdsaSignatureToDer } from '../../../src/ts/ecdsa/der.js';
import { SHA256, SHA512 } from '../../../src/ts/sha2/index.js';

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

type MlDsaCtor = typeof MlDsa44 | typeof MlDsa65;
type TradFamily = 'ed25519' | 'ecdsa-p256';

interface HybridCase {
	name:                 string;
	suite:                StreamableSignatureSuite;
	MlDsaClass:           MlDsaCtor;
	mldsaParams:          MlDsaParams;
	tradFamily:           TradFamily;
	prehashAlgorithm:     'sha-256' | 'sha-512';
	prehashSize:          number;
	// composite-sigs §6 per-suite Label, ASCII bytes (no length prefix, no
	// terminator). Identical to the suite-internal constants in
	// `src/ts/sign/suites/hybrid-classical.ts`; re-derived here to keep the
	// test independent of suite-internal exports.
	label:                Uint8Array;
	// composite-sigs Appendix A Table 4 ECDSA composite signatures carry a
	// `*` indicating variable length (RFC 3279 §2.2.3 Ecdsa-Sig-Value DER
	// strips leading zeros from r/s INTEGER content; typical 70-72 bytes).
	isTradVariableLength: boolean;
}

// composite-sigs §2.2, Prefix: ASCII 'CompositeAlgorithmSignatures2025'
// (32 bytes). Fixed across every Composite ML-DSA suite from draft v17+.
const COMPOSITE_PREFIX = utf8ToBytes('CompositeAlgorithmSignatures2025');

// composite-sigs §6 per-suite Label table.
const LABEL_MLDSA44_ED25519    = utf8ToBytes('COMPSIG-MLDSA44-Ed25519-SHA512');
const LABEL_MLDSA65_ED25519    = utf8ToBytes('COMPSIG-MLDSA65-Ed25519-SHA512');
const LABEL_MLDSA44_ECDSA_P256 = utf8ToBytes('COMPSIG-MLDSA44-ECDSA-P256-SHA256');
const LABEL_MLDSA65_ECDSA_P256 = utf8ToBytes('COMPSIG-MLDSA65-ECDSA-P256-SHA512');

const CASES: HybridCase[] = [
	{
		name: 'MlDsa44Ed25519Suite',     suite: MlDsa44Ed25519Suite,
		MlDsaClass: MlDsa44,             mldsaParams: MLDSA44,
		tradFamily: 'ed25519',
		prehashAlgorithm: 'sha-512',     prehashSize: 64,
		label: LABEL_MLDSA44_ED25519,    isTradVariableLength: false,
	},
	{
		name: 'MlDsa65Ed25519Suite',     suite: MlDsa65Ed25519Suite,
		MlDsaClass: MlDsa65,             mldsaParams: MLDSA65,
		tradFamily: 'ed25519',
		prehashAlgorithm: 'sha-512',     prehashSize: 64,
		label: LABEL_MLDSA65_ED25519,    isTradVariableLength: false,
	},
	{
		name: 'MlDsa44EcdsaP256Suite',   suite: MlDsa44EcdsaP256Suite,
		MlDsaClass: MlDsa44,             mldsaParams: MLDSA44,
		tradFamily: 'ecdsa-p256',
		prehashAlgorithm: 'sha-256',     prehashSize: 32,
		label: LABEL_MLDSA44_ECDSA_P256, isTradVariableLength: true,
	},
	{
		name: 'MlDsa65EcdsaP256Suite',   suite: MlDsa65EcdsaP256Suite,
		MlDsaClass: MlDsa65,             mldsaParams: MLDSA65,
		tradFamily: 'ecdsa-p256',
		prehashAlgorithm: 'sha-512',     prehashSize: 64,
		label: LABEL_MLDSA65_ECDSA_P256, isTradVariableLength: true,
	},
];

const CTX = utf8ToBytes('hybrid-classical-integration');
const MSG = new Uint8Array(128).map((_, i) => (i * 37 + 9) & 0xff);

function sha2OneShot(algo: 'sha-256' | 'sha-512', msg: Uint8Array): Uint8Array {
	if (algo === 'sha-256') {
		const h = new SHA256();
		try {
			return h.hash(msg);
		} finally {
			h.dispose();
		}
	}
	const h = new SHA512();
	try {
		return h.hash(msg);
	} finally {
		h.dispose();
	}
}

// composite-sigs §3.2 step 2: M' = Prefix || Label || len(ctx) || ctx || PH(M).
// len(ctx) is a single unsigned byte (Appendix D worked example confirms
// `len(ctx) == 0x00` for empty context, single byte for non-empty).
function buildMPrime(
	label:  Uint8Array,
	ctx:    Uint8Array,
	digest: Uint8Array,
): Uint8Array {
	const out = new Uint8Array(
		COMPOSITE_PREFIX.length + label.length + 1 + ctx.length + digest.length,
	);
	let p = 0;
	out.set(COMPOSITE_PREFIX, p); p += COMPOSITE_PREFIX.length;
	out.set(label, p);            p += label.length;
	out[p++] = ctx.length;
	out.set(ctx, p);              p += ctx.length;
	out.set(digest, p);
	return out;
}

// ── Sign envelope round-trip + peek ────────────────────────────────────────

describe.each(CASES)('Sign envelope, $name', (c) => {
	it('Sign.sign / Sign.verify round-trip', () => {
		const { pk, sk } = c.suite.keygen();
		const blob = Sign.sign(c.suite, sk, MSG, CTX);
		const out  = Sign.verify(c.suite, pk, blob, CTX);
		expect(out).toEqual(MSG);
	});

	it('Sign.peek reports correct offsets under v3 wire', () => {
		const { sk } = c.suite.keygen();
		const blob = Sign.sign(c.suite, sk, MSG, CTX);
		const peek = Sign.peek(blob, c.suite);
		expect(peek.suiteByte).toBe(c.suite.formatEnum);
		expect(peek.payloadLength).toBe(MSG.length);
		expect(Array.from(peek.ctx)).toEqual(Array.from(CTX));
		// v3 envelope: [suite:1][ctx_len:1][ctx][payload_len u32 BE:4][payload][sig].
		expect(peek.payloadOffset).toBe(2 + CTX.length + 4);
		// For fixed-length sigs (Ed25519 halves) sigOffset == blob.length -
		// sigMaxSize. For variable-length sigs (ECDSA DER halves) the sig
		// fills the tail and sigOffset == payloadOffset + payloadLen.
		expect(peek.sigOffset).toBe(peek.payloadOffset + peek.payloadLength);
		if (!c.isTradVariableLength) {
			expect(peek.sigOffset).toBe(blob.length - c.suite.sigMaxSize);
		} else {
			// Variable sig: total bytes from sigOffset to blob.length must
			// not exceed sigMaxSize (composite-sigs Appendix A Table 4 *).
			expect(blob.length - peek.sigOffset).toBeLessThanOrEqual(c.suite.sigMaxSize);
			expect(blob.length - peek.sigOffset).toBeGreaterThan(c.mldsaParams.sigBytes);
		}
	});
});

// ── SignStream + VerifyStream round-trip ───────────────────────────────────

describe.each(CASES)('SignStream + VerifyStream, $name', (c) => {
	it('streaming sign output verifies via Sign.verify', () => {
		const { pk, sk } = c.suite.keygen();
		const s = new SignStream(c.suite, sk, CTX);
		try {
			s.update(MSG.subarray(0, 32));
			s.update(MSG.subarray(32, 96));
			s.update(MSG.subarray(96));
			const sig = s.finalize();
			const blob = concat(s.buildPreamble(MSG.length), MSG, sig);
			const out  = Sign.verify(c.suite, pk, blob, CTX);
			expect(out).toEqual(MSG);
		} finally {
			s.dispose();
		}
	});

	it('VerifyStream consumes split bytes and returns the msg', () => {
		const { pk, sk } = c.suite.keygen();
		const s = new SignStream(c.suite, sk, CTX);
		let blob: Uint8Array;
		try {
			s.update(MSG);
			const sig = s.finalize();
			blob = concat(s.buildPreamble(MSG.length), MSG, sig);
		} finally {
			s.dispose();
		}
		const v = new VerifyStream(c.suite, pk, CTX);
		try {
			v.update(blob.subarray(0, 1));
			v.update(blob.subarray(1, 33));
			v.update(blob.subarray(33));
			const out = v.finalize();
			expect(out).toEqual(MSG);
		} finally {
			v.dispose();
		}
	});

	it('dispose after partial update is safe (no throw)', () => {
		const { sk } = c.suite.keygen();
		const s = new SignStream(c.suite, sk, CTX);
		s.update(MSG.subarray(0, 16));
		// Idempotent dispose without finalize.
		expect(() => s.dispose()).not.toThrow();
		expect(() => s.dispose()).not.toThrow();
	});

	it('double finalize throws sig-stream-finalized', () => {
		const { sk } = c.suite.keygen();
		const s = new SignStream(c.suite, sk, CTX);
		try {
			s.update(MSG);
			s.finalize();
			let caught: unknown;
			try {
				s.finalize();
			} catch (e) {
				caught = e;
			}
			expect(caught).toBeInstanceOf(SigningError);
			expect((caught as SigningError).discriminator).toBe('sig-stream-finalized');
		} finally {
			s.dispose();
		}
	});
});

// ── Deterministic sub-sign equivalence ─────────────────────────────────────
// Hand-build M' (composite-sigs §2.2 / §3.2 step 2), drive each half's
// deterministic primitive, concat per §4.3 PQ-first, verify through the suite.
// ML-DSA: signDeterministic rnd<-0^32 (FIPS 204 §3.4).
// Ed25519: deterministic-by-construction (RFC 8032 §5.1.6).
// ECDSA: rnd<-0^32 selects RFC 6979 §3.2.

describe.each(CASES)('$name deterministic sub-sign equivalence', (c) => {
	it('hand-driven composite via det. sub-signs verifies through the suite', () => {
		const { pk, sk } = c.suite.keygen();
		// composite-sigs §4.2: composite sk = mldsaSeed (32) || tradSK.
		// For Ed25519 tradSK is the 32-byte raw seed; for ECDSA-P256
		// tradSK is the 51-byte RFC 5915 DER ECPrivateKey carrying the
		// 32-byte scalar.
		const seedMldsa = sk.subarray(0, 32);
		const tradSk    = sk.subarray(32);

		// composite PH applied to the user message (composite-sigs §6).
		const digest = sha2OneShot(c.prehashAlgorithm, MSG);
		const mPrime = buildMPrime(c.label, CTX, digest);

		// ML-DSA half. composite-sigs §3.2 step 3: re-derive expanded sk
		// from the seed via FIPS 204 §6.1 KeyGen_internal. Step 4 then
		// signs M' with mldsa_ctx=Label (FIPS 204 §5.2 Algorithm 2 pure,
		// NOT HashML-DSA per composite-sigs §2.1).
		let sigMldsa: Uint8Array;
		{
			const inst = new c.MlDsaClass();
			try {
				const kp = inst.keygenDerand(seedMldsa);
				sigMldsa = inst.signDeterministic(kp.signingKey, mPrime, c.label);
			} finally {
				inst.dispose();
			}
		}

		// Traditional half. composite-sigs §3.2 step 4:
		// `tradSig = Trad.Sign(tradSK, M')`. No additional wrapping at the
		// composite layer; whatever hashing the traditional primitive does
		// happens inside its own specification (RFC 8032 §5.1.6 for
		// Ed25519, FIPS 186-5 §6.4 `ecdsa-with-SHA256` for ECDSA).
		let sigTrad: Uint8Array;
		if (c.tradFamily === 'ed25519') {
			const inst = new Ed25519();
			try {
				sigTrad = inst._signInternalPk(tradSk, mPrime);
			} finally {
				inst.dispose();
			}
		} else {
			// composite-sigs §6 `ecdsa-with-SHA256` for both 0x22 and 0x23
			// regardless of composite PH: the ECDSA-internal hash is always
			// SHA-256(M'). composite-sigs §10.1 explains the deployment-fit
			// rationale.
			const ecDigest = sha2OneShot('sha-256', mPrime);
			const scalar = decodeEcPrivateKey(tradSk);
			let sigRaw: Uint8Array;
			const inst = new EcdsaP256();
			try {
				// rnd = zeros → RFC 6979 §3.2 deterministic K. The WASM-side
				// ecdsaSign normalises s to low-S per FIPS 186-5 §6.5 /
				// RFC 6979 §3.5, so the produced 64-byte raw r||s is
				// already low-S regardless of the K-bit-flip rule.
				sigRaw = inst._signInternalPk(scalar, ecDigest, new Uint8Array(32));
			} finally {
				inst.dispose();
				scalar.fill(0);
			}
			// composite-sigs §4.3 carries the DER-encoded ECDSA half on the
			// wire (RFC 3279 §2.2.3 Ecdsa-Sig-Value).
			sigTrad = ecdsaSignatureToDer(sigRaw);
		}

		// composite-sigs §4.3 SerializeSignatureValue: PQ-first.
		const sigComposite = concat(sigMldsa, sigTrad);

		// suite.verifyPrehashed is the lower entry; suite.verify computes
		// the same digest internally and reaches verifyPrehashed by the
		// same path. Both must accept the hand-driven sig.
		expect(c.suite.verifyPrehashed(pk, digest, sigComposite, CTX)).toBe(true);
		expect(c.suite.verify(pk, MSG, sigComposite, CTX)).toBe(true);
	});
});
