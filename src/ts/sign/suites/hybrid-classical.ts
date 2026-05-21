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
// src/ts/sign/suites/hybrid-classical.ts
//
// Composite classical+PQ hybrid suites,
// draft-ietf-lamps-pq-composite-sigs-19 (composite-sigs). Two internal
// factories (Ed25519, ECDSA-P256) build the four exported
// StreamableSignatureSuite consts 0x20..0x23:
//
//   0x20  MlDsa44Ed25519Suite     OID 1.3.6.1.5.5.7.6.39
//   0x21  MlDsa65Ed25519Suite     OID 1.3.6.1.5.5.7.6.48
//   0x22  MlDsa44EcdsaP256Suite   OID 1.3.6.1.5.5.7.6.40
//   0x23  MlDsa65EcdsaP256Suite   OID 1.3.6.1.5.5.7.6.45
//
// composite-sigs §2.2 / §3.2 construction:
//   M'       = Prefix || Label || len(ctx) || ctx || PH(M)
//   sig_pq   = ML-DSA.Sign(sk_pq_expanded, M', ctx=Label)
//              pure (FIPS 204 §5.2 Algorithm 2), NOT HashML-DSA
//              (composite-sigs §2.1)
//   sig_trad = Trad.Sign(sk_trad, M')
//              Ed25519: RFC 8032 §5.1.6.
//              ECDSA-P256: FIPS 186-5 §6.4 over SHA-256(M'),
//              composite-sigs §6 `ecdsa-with-SHA256`.
//   sig      = sig_pq || sig_trad (composite-sigs §4.3, PQ-first).
//
// sk_pq is the 32-byte ML-DSA seed only; expanded sk is re-derived
// per sign via FIPS 204 §6.1 KeyGen_internal (composite-sigs §4.2).
// user_ctx cap = 255 (composite-sigs §3.2 step 1, FIPS 204 §3.6.1
// match); overflow throws SigningError('sig-ctx-too-long').
//
// verifyPrehashed runs BOTH sub-verifies before AND-reducing.
// composite-sigs §3.3 permits early-fail on the ML-DSA half;
// leviathan declines for parity with hybrid-pq.ts.
//
// Wire layout, OID table, M' breakdown, hedged posture, and
// constant-time discipline:
// docs/signaturesuite.md#classicalpq-hybrid-composite-encoding.

import { concat, randomBytes, utf8ToBytes, wipe } from '../../utils.js';
import { SigningError } from '../../errors.js';
import {
	MlDsa44, MlDsa65,
	MLDSA44, MLDSA65,
} from '../../mldsa/index.js';
import type { MlDsaParams } from '../../mldsa/index.js';
import { Ed25519 } from '../../ed25519/index.js';
import {
	EcdsaP256,
	encodeEcPrivateKey,
	decodeEcPrivateKey,
} from '../../ecdsa/index.js';
import { ecdsaSignatureToDer, ecdsaSignatureFromDer } from '../../ecdsa/der.js';
import { CTX_DOMAIN_MAX } from '../ctx.js';
import { sha256OneShot, sha512OneShot } from '../hasher.js';
import type {
	StreamableSignatureSuite,
	PrehashAlgorithm,
} from '../types.js';

type MlDsaCtor = typeof MlDsa44 | typeof MlDsa65;

// ── Module-level constants ─────────────────────────────────────────────────

// composite-sigs §2.2, Prefix wedged at the head of every M'.
const COMPOSITE_PREFIX = utf8ToBytes('CompositeAlgorithmSignatures2025');

const COMPOSITE_USER_CTX_MAX = 255;

const LABEL_MLDSA44_ED25519     = utf8ToBytes('COMPSIG-MLDSA44-Ed25519-SHA512');
const LABEL_MLDSA65_ED25519     = utf8ToBytes('COMPSIG-MLDSA65-Ed25519-SHA512');
const LABEL_MLDSA44_ECDSA_P256  = utf8ToBytes('COMPSIG-MLDSA44-ECDSA-P256-SHA256');
const LABEL_MLDSA65_ECDSA_P256  = utf8ToBytes('COMPSIG-MLDSA65-ECDSA-P256-SHA512');

// secp256r1 group order n (SP 800-186 §3.2.1.3). Used by the composite
// ECDSA verify path to normalise high-S to low-S before delegating to
// EcdsaP256.verify (composite-sigs §3.3 permits both s and n - s under
// FIPS 186-5 §6.5; leviathan's standalone verify is strict low-S).
// Rationale: docs/signaturesuite.md#composite-ecdsa-low-s.
const SECP256R1_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const SECP256R1_HALF_N = SECP256R1_N >> 1n;

function be32ToBig(b: Uint8Array): bigint {
	let x = 0n;
	for (const v of b) x = (x << 8n) | BigInt(v);
	return x;
}

function bigToBe32(x: bigint): Uint8Array {
	const out = new Uint8Array(32);
	for (let i = 31; i >= 0; i--) {
		out[i] = Number(x & 0xFFn);
		x >>= 8n;
	}
	return out;
}

/**
 * Normalise raw 64-byte (r, s) to low-S (FIPS 186-5 §6.5).
 * Rationale: docs/signaturesuite.md#composite-ecdsa-low-s.
 */
function normaliseEcdsaSigLowS(raw64: Uint8Array): Uint8Array {
	const s = be32ToBig(raw64.subarray(32, 64));
	if (s <= SECP256R1_HALF_N) return raw64;
	const sLow = SECP256R1_N - s;
	const out = new Uint8Array(64);
	out.set(raw64.subarray(0, 32), 0);
	out.set(bigToBe32(sLow), 32);
	return out;
}

// ── M' construction ────────────────────────────────────────────────────────

/**
 * composite-sigs §3.2 step 2:
 *   M' := Prefix || Label || len(ctx) || ctx || PH(M)
 *
 * `len(ctx)` is encoded as a single unsigned byte (composite-sigs §3.2
 * step 2; Appendix D worked example confirms `len(ctx) == 0x00` for empty
 * context and a single byte for non-empty). The caller is responsible for
 * the `ctx.length <= COMPOSITE_USER_CTX_MAX` check.
 */
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

// ── ML-DSA + Ed25519 factory ───────────────────────────────────────────────

function MldsaEd25519HybridSuite(
	MlDsaClass:  MlDsaCtor,
	mldsaParams: MlDsaParams,
	formatEnum:  number,
	formatName:  string,
	ctxDomain:   string,
	label:       Uint8Array,
): StreamableSignatureSuite {
	if (utf8ToBytes(ctxDomain).length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' too long for ${formatName}`,
		);

	const wasmModules = Object.freeze(['mldsa', 'sha3', 'curve25519', 'sha2'] as const);
	const prehashAlgorithm: PrehashAlgorithm = 'sha-512';
	const prehashSize = 64;

	const pkSize     = mldsaParams.pkBytes + 32;
	const skSize     = 32 + 32;
	// composite-sigs Appendix A Table 4 + RFC 8032 §5.1.6: fixed 64-byte Ed25519 sig.
	const sigMaxSize = mldsaParams.sigBytes + 64;

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize,
		skSize,
		sigMaxSize,
		wasmModules,
		prehashAlgorithm,
		prehashSize,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			// One-shot SHA-512 over the message; the composite PH for these
			// two suites is SHA-512 (composite-sigs §6).
			const digest = sha512OneShot(msg);
			try {
				return this.signPrehashed(sk, digest, ctx);
			} finally {
				wipe(digest);
			}
		},

		verify(
			pk:  Uint8Array,
			msg: Uint8Array,
			sig: Uint8Array,
			ctx: Uint8Array,
		): boolean {
			const digest = sha512OneShot(msg);
			try {
				return this.verifyPrehashed(pk, digest, sig, ctx);
			} finally {
				wipe(digest);
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const seedMldsa = randomBytes(32);
			let mldsaPk: Uint8Array;
			const mldsaInst = new MlDsaClass();
			try {
				const kp = mldsaInst.keygenDerand(seedMldsa);
				mldsaPk = kp.verificationKey;
				wipe(kp.signingKey);
			} finally {
				mldsaInst.dispose();
			}

			const edInst = new Ed25519();
			let edPk: Uint8Array;
			let seedEd: Uint8Array;
			try {
				const kp = edInst.keygen();
				edPk = kp.publicKey;
				seedEd = kp.secretKey;
			} finally {
				edInst.dispose();
			}

			try {
				return {
					pk: concat(mldsaPk, edPk),
					sk: concat(seedMldsa, seedEd),
				};
			} finally {
				wipe(seedMldsa);
				wipe(seedEd);
			}
		},

		signPrehashed(
			sk:     Uint8Array,
			digest: Uint8Array,
			ctx:    Uint8Array,
		): Uint8Array {
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != ${prehashSize} for ${formatName}`,
				);
			if (sk.length !== skSize)
				throw new SigningError(
					'sig-key-size',
					`sk length ${sk.length} != ${skSize} for ${formatName}`,
				);
			if (ctx.length > COMPOSITE_USER_CTX_MAX)
				throw new SigningError(
					'sig-ctx-too-long',
					`user_ctx length ${ctx.length} > ${COMPOSITE_USER_CTX_MAX} `
					+ '(composite-sigs §3.2 step 1)',
				);

			const seedMldsa = sk.subarray(0, 32);
			const seedEd    = sk.subarray(32, 64);
			const mPrime    = buildMPrime(label, ctx, digest);

			try {
				// composite-sigs §4.2: re-derive expanded sk from 32-byte
				// seed (FIPS 204 §6.1 KeyGen_internal); sign with
				// mldsa_ctx = Label (composite-sigs §3.2 step 4).
				let sigMldsa: Uint8Array;
				const mldsaInst = new MlDsaClass();
				let expandedSk: Uint8Array | null = null;
				try {
					const kp = mldsaInst.keygenDerand(seedMldsa);
					expandedSk = kp.signingKey;
					wipe(kp.verificationKey);
					sigMldsa = mldsaInst.sign(expandedSk, mPrime, label);
				} finally {
					if (expandedSk) wipe(expandedSk);
					mldsaInst.dispose();
				}

				// Ed25519 half: pure sign over M', composite-sigs §3.2 step 4 + RFC 8032 §5.1.6.
				let sigEd: Uint8Array;
				const edInst = new Ed25519();
				try {
					sigEd = edInst._signInternalPk(seedEd, mPrime);
				} finally {
					edInst.dispose();
				}

				// composite-sigs §4.3 SerializeSignatureValue: PQ-first,
				// no length prefix.
				return concat(sigMldsa, sigEd);
			} finally {
				wipe(mPrime);
			}
		},

		verifyPrehashed(
			pk:     Uint8Array,
			digest: Uint8Array,
			sig:    Uint8Array,
			ctx:    Uint8Array,
		): boolean {
			// Wire-shape rejects → false (attacker-observable bytes;
			// composite-sigs §3.3 returns "Invalid signature").
			if (pk.length  !== pkSize)     return false;
			if (sig.length !== sigMaxSize) return false;

			// Caller-side contract violations throw, symmetric with the
			// sign side: digest length and ctx length are properties of
			// the caller's input shape, not signature validity.
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != ${prehashSize} for ${formatName}`,
				);
			if (ctx.length > COMPOSITE_USER_CTX_MAX)
				throw new SigningError(
					'sig-ctx-too-long',
					`user_ctx length ${ctx.length} > ${COMPOSITE_USER_CTX_MAX} `
					+ '(composite-sigs §3.2 step 1)',
				);

			const pkMldsa  = pk.subarray(0, mldsaParams.pkBytes);
			const pkEd     = pk.subarray(mldsaParams.pkBytes);
			const sigMldsa = sig.subarray(0, mldsaParams.sigBytes);
			const sigEd    = sig.subarray(mldsaParams.sigBytes);
			const mPrime   = buildMPrime(label, ctx, digest);

			// Both sub-verifies must run before AND-reduce
			// (constant-time gate).
			let mldsaOk: boolean;
			let edOk:    boolean;

			try {
				const mldsaInst = new MlDsaClass();
				try {
					mldsaOk = mldsaInst.verify(pkMldsa, mPrime, sigMldsa, label);
				} finally {
					mldsaInst.dispose();
				}

				const edInst = new Ed25519();
				try {
					edOk = edInst.verify(pkEd, mPrime, sigEd);
				} finally {
					edInst.dispose();
				}
			} finally {
				wipe(mPrime);
			}

			// Do NOT wipe sub-sig / sub-pk subarrays; they alias caller-owned buffers.
			return mldsaOk && edOk;
		},
	};
}

// ── ML-DSA + ECDSA-P256 factory ────────────────────────────────────────────

function MldsaEcdsaP256HybridSuite(
	MlDsaClass:       MlDsaCtor,
	mldsaParams:      MlDsaParams,
	formatEnum:       number,
	formatName:       string,
	ctxDomain:        string,
	label:            Uint8Array,
	prehashAlgorithm: PrehashAlgorithm,
	prehashSize:      number,
): StreamableSignatureSuite {
	if (utf8ToBytes(ctxDomain).length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' too long for ${formatName}`,
		);

	// 'p256' drives ECDSA; 'sha2' covers both the composite PH (SHA-256
	// for 0x22, SHA-512 for 0x23) and ECDSA's internal SHA-256(M').
	const wasmModules = Object.freeze(['mldsa', 'sha3', 'p256', 'sha2'] as const);

	const pkSize     = mldsaParams.pkBytes + 65;
	const skSize     = 32 + 51;
	// composite-sigs Appendix A Table 4 + RFC 3279 §2.2.3, 72-byte DER ceiling.
	const sigMaxSize = mldsaParams.sigBytes + 72;

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize,
		skSize,
		sigMaxSize,
		wasmModules,
		prehashAlgorithm,
		prehashSize,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			const digest = prehashAlgorithm === 'sha-256'
				? sha256OneShot(msg)
				: sha512OneShot(msg);
			try {
				return this.signPrehashed(sk, digest, ctx);
			} finally {
				wipe(digest);
			}
		},

		verify(
			pk:  Uint8Array,
			msg: Uint8Array,
			sig: Uint8Array,
			ctx: Uint8Array,
		): boolean {
			const digest = prehashAlgorithm === 'sha-256'
				? sha256OneShot(msg)
				: sha512OneShot(msg);
			try {
				return this.verifyPrehashed(pk, digest, sig, ctx);
			} finally {
				wipe(digest);
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const seedMldsa = randomBytes(32);
			let mldsaPk: Uint8Array;
			const mldsaInst = new MlDsaClass();
			try {
				const kp = mldsaInst.keygenDerand(seedMldsa);
				mldsaPk = kp.verificationKey;
				wipe(kp.signingKey);
			} finally {
				mldsaInst.dispose();
			}

			// ECDSA-P256 half: 65-byte uncompressed pk (SEC 1 §2.3.4,
			// composite-sigs §4) and 51-byte DER ECPrivateKey
			// (RFC 5915 §3, composite-sigs §4.2).
			let ecPk: Uint8Array;
			let ecScalar: Uint8Array;
			const ecInst = new EcdsaP256();
			try {
				const kp = ecInst.keygenUncompressed();
				ecPk = kp.publicKey;
				ecScalar = kp.secretKey;
			} finally {
				ecInst.dispose();
			}

			let ecDer: Uint8Array;
			try {
				ecDer = encodeEcPrivateKey(ecScalar);
			} finally {
				wipe(ecScalar);
			}

			try {
				return {
					pk: concat(mldsaPk, ecPk),
					sk: concat(seedMldsa, ecDer),
				};
			} finally {
				wipe(seedMldsa);
				wipe(ecDer);
			}
		},

		signPrehashed(
			sk:     Uint8Array,
			digest: Uint8Array,
			ctx:    Uint8Array,
		): Uint8Array {
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != ${prehashSize} for ${formatName}`,
				);
			if (sk.length !== skSize)
				throw new SigningError(
					'sig-key-size',
					`sk length ${sk.length} != ${skSize} for ${formatName}`,
				);
			if (ctx.length > COMPOSITE_USER_CTX_MAX)
				throw new SigningError(
					'sig-ctx-too-long',
					`user_ctx length ${ctx.length} > ${COMPOSITE_USER_CTX_MAX} `
					+ '(composite-sigs §3.2 step 1)',
				);

			const seedMldsa = sk.subarray(0, 32);
			const ecDer     = sk.subarray(32, 83);
			// RFC 5915 §3 ECPrivateKey decode; strict DER per the codec's
			// X.690 §10 hygiene rules. Throws on syntax violation.
			const ecScalar  = decodeEcPrivateKey(ecDer);
			const mPrime    = buildMPrime(label, ctx, digest);
			// composite-sigs §6, ECDSA half is SHA-256(M') for both 0x22 and 0x23.
			const ecDigest  = sha256OneShot(mPrime);
			const rnd       = randomBytes(32);

			try {
				let sigMldsa: Uint8Array;
				const mldsaInst = new MlDsaClass();
				let expandedSk: Uint8Array | null = null;
				try {
					const kp = mldsaInst.keygenDerand(seedMldsa);
					expandedSk = kp.signingKey;
					wipe(kp.verificationKey);
					sigMldsa = mldsaInst.sign(expandedSk, mPrime, label);
				} finally {
					if (expandedSk) wipe(expandedSk);
					mldsaInst.dispose();
				}

				let sigEcRaw: Uint8Array;
				const ecInst = new EcdsaP256();
				try {
					sigEcRaw = ecInst._signInternalPk(ecScalar, ecDigest, rnd);
				} finally {
					ecInst.dispose();
				}

				let sigEcDer: Uint8Array;
				try {
					// composite-sigs §4.3, DER on the wire.
					sigEcDer = ecdsaSignatureToDer(sigEcRaw);
				} finally {
					wipe(sigEcRaw);
				}

				return concat(sigMldsa, sigEcDer);
			} finally {
				wipe(rnd);
				wipe(ecScalar);
				wipe(ecDigest);
				wipe(mPrime);
			}
		},

		verifyPrehashed(
			pk:     Uint8Array,
			digest: Uint8Array,
			sig:    Uint8Array,
			ctx:    Uint8Array,
		): boolean {
			// Wire-shape rejects → false. 8-byte DER floor per RFC 3279 §2.2.3.
			if (pk.length !== pkSize)                            return false;
			if (sig.length < mldsaParams.sigBytes + 8)           return false;
			if (sig.length > sigMaxSize)                         return false;

			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != ${prehashSize} for ${formatName}`,
				);
			if (ctx.length > COMPOSITE_USER_CTX_MAX)
				throw new SigningError(
					'sig-ctx-too-long',
					`user_ctx length ${ctx.length} > ${COMPOSITE_USER_CTX_MAX} `
					+ '(composite-sigs §3.2 step 1)',
				);

			const pkMldsa = pk.subarray(0, mldsaParams.pkBytes);
			const pkEc    = pk.subarray(mldsaParams.pkBytes, mldsaParams.pkBytes + 65);
			const sigMldsa = sig.subarray(0, mldsaParams.sigBytes);
			const sigEcDer = sig.subarray(mldsaParams.sigBytes);
			const mPrime   = buildMPrime(label, ctx, digest);
			const ecDigest = sha256OneShot(mPrime);

			let mldsaOk: boolean;
			let ecOk:    boolean;

			try {
				const mldsaInst = new MlDsaClass();
				try {
					mldsaOk = mldsaInst.verify(pkMldsa, mPrime, sigMldsa, label);
				} finally {
					mldsaInst.dispose();
				}

				let sigEcRaw: Uint8Array | null = null;
				try {
					sigEcRaw = ecdsaSignatureFromDer(sigEcDer);
				} catch {
					sigEcRaw = null;
				}

				if (sigEcRaw === null) {
					ecOk = false;
				} else {
					const sigEcLowS = normaliseEcdsaSigLowS(sigEcRaw);
					const ecInst = new EcdsaP256();
					try {
						ecOk = ecInst.verify(pkEc, ecDigest, sigEcLowS);
					} finally {
						ecInst.dispose();
					}
					wipe(sigEcLowS);
					wipe(sigEcRaw);
				}
			} finally {
				wipe(mPrime);
				wipe(ecDigest);
			}

			return mldsaOk && ecOk;
		},
	};
}

// ── Exported suite consts ──────────────────────────────────────────────────

/**
 * Composite ML-DSA-44 + Ed25519 with SHA-512 prehash.
 * composite-sigs §6, id-MLDSA44-Ed25519-SHA512 (OID 1.3.6.1.5.5.7.6.39).
 */
export const MlDsa44Ed25519Suite: StreamableSignatureSuite =
	MldsaEd25519HybridSuite(
		MlDsa44, MLDSA44,
		0x20, 'mldsa44-ed25519',
		'mldsa44-ed25519-envelope-v3',
		LABEL_MLDSA44_ED25519,
	);

/**
 * Composite ML-DSA-65 + Ed25519 with SHA-512 prehash.
 * composite-sigs §6, id-MLDSA65-Ed25519-SHA512 (OID 1.3.6.1.5.5.7.6.48).
 */
export const MlDsa65Ed25519Suite: StreamableSignatureSuite =
	MldsaEd25519HybridSuite(
		MlDsa65, MLDSA65,
		0x21, 'mldsa65-ed25519',
		'mldsa65-ed25519-envelope-v3',
		LABEL_MLDSA65_ED25519,
	);

/**
 * Composite ML-DSA-44 + ECDSA-P256 with SHA-256 prehash.
 * composite-sigs §6, id-MLDSA44-ECDSA-P256-SHA256 (OID 1.3.6.1.5.5.7.6.40).
 */
export const MlDsa44EcdsaP256Suite: StreamableSignatureSuite =
	MldsaEcdsaP256HybridSuite(
		MlDsa44, MLDSA44,
		0x22, 'mldsa44-ecdsa-p256',
		'mldsa44-ecdsa-p256-envelope-v3',
		LABEL_MLDSA44_ECDSA_P256,
		'sha-256', 32,
	);

/**
 * Composite ML-DSA-65 + ECDSA-P256 with SHA-512 prehash on the composite
 * layer; the ECDSA half still hashes M' with SHA-256 per composite-sigs §6
 * `ecdsa-with-SHA256` and §10.1 (deployment-fit rationale).
 * composite-sigs §6, id-MLDSA65-ECDSA-P256-SHA512 (OID 1.3.6.1.5.5.7.6.45).
 */
export const MlDsa65EcdsaP256Suite: StreamableSignatureSuite =
	MldsaEcdsaP256HybridSuite(
		MlDsa65, MLDSA65,
		0x23, 'mldsa65-ecdsa-p256',
		'mldsa65-ecdsa-p256-envelope-v3',
		LABEL_MLDSA65_ECDSA_P256,
		'sha-512', 64,
	);
