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
// Composite classical+PQ hybrid suites, draft-ietf-lamps-pq-composite-sigs-19
// (Composite Module-Lattice-Based Digital Signature Algorithm), shortened
// to `composite-sigs` below. Two internal factories (Ed25519, ECDSA-P256)
// build the four exported `StreamableSignatureSuite` consts:
//
//   0x20  MlDsa44Ed25519Suite     id-MLDSA44-Ed25519-SHA512       (1.3.6.1.5.5.7.6.39)
//   0x21  MlDsa65Ed25519Suite     id-MLDSA65-Ed25519-SHA512       (1.3.6.1.5.5.7.6.48)
//   0x22  MlDsa44EcdsaP256Suite   id-MLDSA44-ECDSA-P256-SHA256    (1.3.6.1.5.5.7.6.40)
//   0x23  MlDsa65EcdsaP256Suite   id-MLDSA65-ECDSA-P256-SHA512    (1.3.6.1.5.5.7.6.45)
//
// Construction (composite-sigs §2.2 / §3.2):
//
//   Prefix   = ASCII 'CompositeAlgorithmSignatures2025'        (32 bytes)
//   Label    = ASCII 'COMPSIG-<MLDSA-VARIANT>-<TRAD>-<PH>'     (30-32 bytes)
//   M'       = Prefix || Label || len(ctx) || ctx || PH(M)
//   sig_pq   = ML-DSA.Sign(sk_pq_expanded, M', mldsa_ctx=Label)   (pure mode,
//              FIPS 204 §5.2 Algorithm 2; NOT HashML-DSA; composite-sigs §2.1)
//   sig_trad = Trad.Sign(sk_trad, M')                              (Ed25519:
//              RFC 8032 §5.1.6 pure; ECDSA-P256: FIPS 186-5 §6.4 over
//              SHA-256(M') regardless of composite PH, per composite-sigs §6
//              `ecdsa-with-SHA256`)
//   sig      = sig_pq || sig_trad                                  (PQ-first,
//              composite-sigs §4.3)
//
// Wire format (composite-sigs §4):
//
//   pk = pk_pq || pk_trad                pk_trad = 32 raw Ed25519
//                                          OR 65-byte SEC 1 §2.3.4 uncompressed
//                                          ECDSA-P256
//   sk = seed_pq || sk_trad              seed_pq = 32-byte ML-DSA seed only
//                                          (composite-sigs §4.2 forbids
//                                          serialising the expanded sk;
//                                          sign-time re-derives via
//                                          FIPS 204 §6.1 KeyGen_internal).
//                                          sk_trad = 32 raw Ed25519 seed OR
//                                          51-byte RFC 5915 DER ECPrivateKey
//                                          for ECDSA-P256.
//
// ctxDomain: each suite carries a built-in `mldsa{XX}-{trad}-envelope-v3`
// string for catalog symmetry, but the string is NEVER fed to either
// sub-signer and `buildEffectiveCtx` from `../ctx.ts` is NOT on the call
// path. User-context binding is fully specified by composite-sigs §3.2 via
// the M' construction; wrapping ctx with a `{ctxDomain}|{user_ctx}` prefix
// before placing it inside M' would produce a wire incompatible with every
// other Composite ML-DSA implementation. Per-call user_ctx cap is 255 bytes
// (composite-sigs §3.2 step 1), enforced inline below; the leviathan-wide
// `USER_CTX_MAX` raised to 255 to match. Discriminator on overflow is
// `sig-ctx-too-long`, uniform with the rest of the catalog.
//
// Constant-time discipline: `verifyPrehashed` runs BOTH sub-verifies on
// every call, declares `mldsaOk` and `tradOk` without initial value, and
// AND-reduces only after both have returned. composite-sigs §3.3 explicitly
// permits early-fail on the ML-DSA half ("no private keys are involved in a
// signature verification, there are no timing attacks to consider"); the
// library declines that permission for parity with `hybrid-pq.ts`. The wire
// format is identical, and the accept/reject decision is identical on every
// well-formed input. The only observable difference is timing on the
// invalid-ML-DSA / valid-trad case.
//
// Per-call WASM lifecycle: each method instantiates fresh primitive classes
// inside try / finally + dispose blocks; secret material is wiped on every
// exit path. The factories are NOT exported: catalog format bytes are
// reserved and exposing factories would invite custom suites with unmanaged
// bytes.
//
// The ML-DSA composite sk is seed-only by spec. Every composite sign call
// re-derives the expanded sk via `keygenDerand(seed)` (FIPS 204 §6.1
// Algorithm 6, KeyGen_internal). One extra ML-DSA keygen per sign is the
// price of the seed-only sk encoding composite-sigs §4.2 mandates.

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

// composite-sigs §2.2, Prefix, Label, and CTX. The 32-byte ASCII string
// 'CompositeAlgorithmSignatures2025' wedged at the head of every M' fixes
// the construction across every conforming implementation. Hex
// 43 6F 6D 70 6F 73 69 74 65 41 6C 67 6F 72 69 74 68 6D 53 69 67 6E 61 74
// 75 72 65 73 32 30 32 35.
const COMPOSITE_PREFIX = utf8ToBytes('CompositeAlgorithmSignatures2025');

// composite-sigs §3.2 step 1: "If len(ctx) > 255: return error". Per-call
// cap on the user-supplied context. Matches the FIPS 204 §3.6.1 native ctx
// cap that the underlying ML-DSA sub-signer enforces on its own (Label)
// ctx parameter.
const COMPOSITE_USER_CTX_MAX = 255;

// composite-sigs §6, per-suite Label table. ASCII byte encoding, no
// length prefix, no terminator. Inserted into M' immediately after the
// Prefix and also fed verbatim as the FIPS 204 §5.2 Algorithm 2 ctx
// parameter to the ML-DSA sub-signer (composite-sigs §3.2 step 4).
const LABEL_MLDSA44_ED25519     = utf8ToBytes('COMPSIG-MLDSA44-Ed25519-SHA512');
const LABEL_MLDSA65_ED25519     = utf8ToBytes('COMPSIG-MLDSA65-Ed25519-SHA512');
const LABEL_MLDSA44_ECDSA_P256  = utf8ToBytes('COMPSIG-MLDSA44-ECDSA-P256-SHA256');
const LABEL_MLDSA65_ECDSA_P256  = utf8ToBytes('COMPSIG-MLDSA65-ECDSA-P256-SHA512');

// secp256r1 group order n, SP 800-186 §3.2.1.3. Used by the composite
// ECDSA verify path to normalise high-S signatures into the equivalent
// low-S representation before delegating to `EcdsaP256.verify`. The
// composite-sigs draft is silent on low-S (composite-sigs §3.2 / §3.3
// invoke `Trad.Sign` / `Trad.Verify` per FIPS 186-5 §6.4 / §6.5, which
// accept both s and (n - s)), so conforming implementations may emit
// either; Appendix E's reference signatures include high-S cases. The
// standalone `EcdsaP256Suite` is strict (FIPS 186-5 verify outcome is
// unchanged by the s ↔ n-s flip, but leviathan's WASM-side `ecdsaVerify`
// enforces low-S by design). Normalising at the composite boundary
// preserves the suite's interop without weakening the standalone surface.
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
 * Normalise a 64-byte raw r || s ECDSA signature to its low-S form:
 * if s > n/2, replace s with (n - s). r is untouched. (r, s) and
 * (r, n - s) verify identically under FIPS 186-5 §6.5 because the verify
 * equation depends on s only through s⁻¹ mod n, and (n - s)⁻¹ ≡ -s⁻¹.
 * The composite ECDSA verify path always runs sigs through this so that
 * high-S signatures emitted by non-leviathan signers (e.g. the
 * composite-sigs Appendix E reference impl) accept under leviathan's
 * strict-S `EcdsaP256.verify`.
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

	// 'sha3' drives the ML-DSA internals; 'sha2' drives the composite PH
	// (SHA-512 here) and 'curve25519' is the Ed25519 substrate (the
	// 'curve25519' module slot covers both Ed25519 and X25519, see
	// `init({ ed25519 / x25519 })`).
	const wasmModules = Object.freeze(['mldsa', 'sha3', 'curve25519', 'sha2'] as const);
	const prehashAlgorithm: PrehashAlgorithm = 'sha-512';
	const prehashSize = 64;

	const pkSize     = mldsaParams.pkBytes + 32;
	const skSize     = 32 + 32;
	// composite-sigs Appendix A Table 4: id-MLDSA{44|65}-Ed25519-SHA512
	// signature is exactly mldsaParams.sigBytes + 64 bytes (Ed25519
	// R||S fixed-length per RFC 8032 §5.1.6). Fixed for these two suites.
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
			// composite-sigs §4.2: composite sk is the 32-byte ML-DSA seed
			// concatenated with the Ed25519 32-byte raw seed. We generate
			// the ML-DSA seed directly so we can store it in the composite
			// sk; `keygenDerand` derives the matching pk without us holding
			// the expanded sk (which composite-sigs forbids serialising).
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
				// ML-DSA half: re-derive expanded sk from the 32-byte seed
				// (composite-sigs §4.2 / §3.2 step 3), then sign M' with
				// mldsa_ctx = Label (composite-sigs §3.2 step 4). Pure
				// ML-DSA (FIPS 204 §5.2 Algorithm 2), NOT HashML-DSA
				// (composite-sigs §2.1).
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

				// Ed25519 half: pure Ed25519 sign over M' (composite-sigs
				// §3.2 step 4 `tradSig = Trad.Sign(tradSK, M')`; RFC 8032
				// §5.1.6). `_signInternalPk` re-derives pk inside the same
				// WASM call and skips the fault-injection cross-check; the
				// suite holds only the 32-byte seed, so the caller-supplied
				// pk path is unavailable here.
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
			// Wire-derived length checks return false (attacker-observable
			// bytes; composite-sigs §3.3 verify returns "Invalid signature"
			// on every structural mismatch). The composite sig for these
			// two suites is fixed-length (ML-DSA sig + 64 Ed25519).
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

			// Declare without initial value: both sub-verifies must run
			// and assign before the AND reduction at the tail. If a WASM
			// call throws (only on contract violations, never on bad-sig
			// outcomes), the exception propagates and these are never
			// read.
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

			// Both sub-verifies have returned by this point; the && is a
			// pure boolean reduction with nothing left to short-circuit.
			// Do NOT wipe sigMldsa / sigEd / pkMldsa / pkEd: they are
			// subarrays of caller-owned buffers.
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
	// composite-sigs Appendix A Table 4 marks the ECDSA composite sig
	// sizes with `*` for variability: the RFC 3279 §2.2.3 Ecdsa-Sig-Value
	// DER encoding strips leading zero bytes from r and s INTEGER
	// content, so a typical signature is 70-72 bytes and the maximum is
	// 72 bytes. sigMaxSize is the catalog-reserved upper bound.
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
			// Compute the composite PH over the message. The one-shot
			// helpers are byte-identical to the SignStream prehash shim
			// (`sha256Buffered` / `sha512Buffered` in `../hasher.ts`).
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
			// ML-DSA half: seed-only sk (composite-sigs §4.2), derive pk
			// via FIPS 204 §6.1 Algorithm 6 KeyGen_internal.
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
			// composite-sigs §6 names the ECDSA half `ecdsa-with-SHA256`
			// for BOTH 0x22 and 0x23, regardless of composite PH. The
			// ECDSA-internal hash is SHA-256(M') in both cases; only the
			// composite-layer PH varies (SHA-256 at 0x22, SHA-512 at
			// 0x23). composite-sigs §10.1 calls this out: ecdsa-with-
			// SHA256 over secp256r1 is overwhelmingly the deployed pair.
			const ecDigest  = sha256OneShot(mPrime);
			// Per-call entropy for the hedged-by-default path
			// (draft-irtf-cfrg-det-sigs-with-noise-05). All-zero rnd
			// would select RFC 6979 §3.2 deterministic; the leviathan
			// default is fresh randomBytes(32).
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
					// `_signInternalPk(sk, msgHash, rnd)` derives pk
					// internally and skips the fault-injection cross-
					// check; the suite holds only the scalar.
					sigEcRaw = ecInst._signInternalPk(ecScalar, ecDigest, rnd);
				} finally {
					ecInst.dispose();
				}

				let sigEcDer: Uint8Array;
				try {
					// RFC 3279 §2.2.3 Ecdsa-Sig-Value DER. Variable length
					// (8-72 bytes). The composite wire carries the DER
					// form per composite-sigs §4.3.
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
			// Soft-fail on attacker-observable structural mismatches:
			// pk is fixed length (mldsaPk + 65-byte uncompressed), sig
			// is variable below the upper bound. Floor at the absolute
			// minimum for a non-degenerate ECDSA DER (8 bytes,
			// RFC 3279 §2.2.3); anything shorter cannot represent two
			// non-empty INTEGER components.
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

				// DER decode is part of verify, not a contract violation:
				// the sig bytes are attacker-supplied. A malformed DER
				// half folds into `ecOk = false` and the verify continues
				// to keep the constant-time discipline (don't propagate
				// the throw, don't skip the ML-DSA half on the strength
				// of trad-half being malformed).
				let sigEcRaw: Uint8Array | null = null;
				try {
					sigEcRaw = ecdsaSignatureFromDer(sigEcDer);
				} catch {
					sigEcRaw = null;
				}

				if (sigEcRaw === null) {
					ecOk = false;
				} else {
					// composite-sigs does not require low-S; the Appendix E
					// reference signatures include high-S cases that
					// leviathan's strict `EcdsaP256.verify` would reject.
					// FIPS 186-5 §6.5 accepts both s and (n - s) under the
					// same pk, so normalising at the composite boundary
					// preserves spec semantics while keeping the standalone
					// EcdsaP256Suite's strict-S posture intact.
					const sigEcLowS = normaliseEcdsaSigLowS(sigEcRaw);
					const ecInst = new EcdsaP256();
					try {
						// `EcdsaP256.verify` accepts compressed (33) or
						// uncompressed (65) pk; pkEc is the 65-byte
						// uncompressed form per composite-sigs §4.
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
