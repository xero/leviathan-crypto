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
// src/ts/sign/suites/hybrid-pq.ts
//
// MldsaSlhdsaHybridSuite factory (internal, not exported) plus the three
// exported PQ-only hybrid suite consts:
//   0x30  MlDsa44SlhDsa128fSuite   (cat-1, ML-DSA-44 || SLH-DSA-128f)
//   0x31  MlDsa65SlhDsa192fSuite   (cat-3, ML-DSA-65 || SLH-DSA-192f)
//   0x32  MlDsa87SlhDsa256fSuite   (cat-5, ML-DSA-87 || SLH-DSA-256f)
//
// Wire format is leviathan-defined (no composite-sigs draft entry covers
// PQ-only pairs): keys and signatures concatenate ML-DSA half first, no
// length prefixes because each component size is catalog-known per hybrid.
//
//   pk_combined  = pk_mldsa  || pk_slhdsa
//   sk_combined  = sk_mldsa  || sk_slhdsa
//   sig_combined = sig_mldsa || sig_slhdsa
//
// The two halves sign the SAME prehash digest under the SAME effective_ctx.
// FIPS 204 §5.4 Alg 4 and FIPS 205 §10.2 Alg 22 produce byte-identical
// M' = toByte(1,1) || toByte(|ctx|,1) || ctx || OID(ph) || PH_M given a
// common (digest, ph, ctx), and SHAKE128 / SHAKE256 share OIDs across the
// two specs (FIPS 204 §5.4.1 Table 1 = FIPS 205 §10.2 Table 11). The two
// sub-signers therefore see byte-identical inputs while the underlying
// primitives differ.
//
// `verifyPrehashed` is constant-time-shaped: it ALWAYS invokes both
// sub-verifies regardless of intermediate boolean outcomes; no early
// return on the first half. The `mldsaOk && slhdsaOk` at the tail is a
// boolean AND on values that have already been computed, so JavaScript's
// short-circuit operator has nothing to short-circuit. Each sub-verify
// is itself constant-time per its FIPS contract.
//
// Domain separation: each hybrid carries a unique ctxDomain string
// ('mldsa{XX}-slhdsa{YYY}f-envelope-v3'), used by BOTH sub-signers. No
// per-half suffix is needed because ML-DSA and SLH-DSA are distinct
// primitives (a sig produced for one cannot verify under the other's pk).
// The hybrid-level uniqueness prevents both cross-suite forgery (an
// ML-DSA half of standalone MlDsa44Suite under 'mldsa44-envelope-v3'
// cannot pass as the ML-DSA half of hybrid 0x30) and cross-hybrid forgery
// (one hybrid's ML-DSA half cannot be reused as another's).

import { concat } from '../../utils.js';
import { wipe, utf8ToBytes } from '../../utils.js';
import { SigningError } from '../../errors.js';
import {
	MlDsa44, MlDsa65, MlDsa87,
	MLDSA44, MLDSA65, MLDSA87,
} from '../../mldsa/index.js';
import type { MlDsaParams } from '../../mldsa/index.js';
import {
	SlhDsa128f, SlhDsa192f, SlhDsa256f,
	SLHDSA128F, SLHDSA192F, SLHDSA256F,
} from '../../slhdsa/index.js';
import type { SlhDsaParams } from '../../slhdsa/index.js';
import type { PreHashAlgorithm as MlDsaPreHashAlgorithm } from '../../mldsa/hashvariant.js';
import type { PreHashAlgorithm as SlhPreHashAlgorithm } from '../../slhdsa/prehash.js';
import { buildEffectiveCtx, CTX_DOMAIN_MAX } from '../ctx.js';
import { createRunningHash } from '../hasher.js';
import type {
	StreamableSignatureSuite,
	PrehashAlgorithm,
} from '../types.js';

type MlDsaCtor  = typeof MlDsa44   | typeof MlDsa65   | typeof MlDsa87;
type SlhDsaCtor = typeof SlhDsa128f | typeof SlhDsa192f | typeof SlhDsa256f;

// Lowercase public sign-surface → uppercase ML-DSA-side algorithm name.
// Mirrors prehashAlgoToMldsa in ctx.ts but only covers the two SHAKE
// entries actually used by hybrid suites; the hybrid catalog is locked
// to shake-128 (cat-1) and shake-256 (cat-3 / cat-5).
function prehashAlgoToMldsaLocal(algo: PrehashAlgorithm): MlDsaPreHashAlgorithm {
	switch (algo) {
	case 'shake-128': return 'SHAKE128';
	case 'shake-256': return 'SHAKE256';
	case 'sha-256':   return 'SHA2-256';
	case 'sha-512':   return 'SHA2-512';
	case 'sha3-256':  return 'SHA3-256';
	case 'sha3-512':  return 'SHA3-512';
	default: {
		const _exhaustive: never = algo;
		throw new Error(
			`leviathan-crypto: unknown prehash algorithm ${_exhaustive as string}`,
		);
	}
	}
}

function prehashAlgoToSlhdsaLocal(algo: PrehashAlgorithm): SlhPreHashAlgorithm {
	switch (algo) {
	case 'shake-128': return 'SHAKE128';
	case 'shake-256': return 'SHAKE256';
	case 'sha-256':   return 'SHA2-256';
	case 'sha-512':   return 'SHA2-512';
	case 'sha3-256':  return 'SHA3-256';
	case 'sha3-512':  return 'SHA3-512';
	default: {
		const _exhaustive: never = algo;
		throw new Error(
			`leviathan-crypto: unknown prehash algorithm ${_exhaustive as string}`,
		);
	}
	}
}

// ── Factory ─────────────────────────────────────────────────────────────────

function MldsaSlhdsaHybridSuite(
	MlDsaClass:       MlDsaCtor,
	mldsaParams:      MlDsaParams,
	SlhDsaClass:      SlhDsaCtor,
	slhdsaParams:     SlhDsaParams,
	formatEnum:       number,
	formatName:       string,
	ctxDomain:        string,
	prehashAlgorithm: PrehashAlgorithm,
	prehashSize:      number,
): StreamableSignatureSuite {
	if (utf8ToBytes(ctxDomain).length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' too long for ${formatName}`,
		);

	const pkSize     = mldsaParams.pkBytes  + slhdsaParams.pkBytes;
	const skSize     = mldsaParams.skBytes  + slhdsaParams.skBytes;
	const sigMaxSize = mldsaParams.sigBytes + slhdsaParams.sigBytes;

	const wasmModules   = Object.freeze(['mldsa', 'sha3', 'slhdsa'] as const);
	const mldsaHashAlgo = prehashAlgoToMldsaLocal(prehashAlgorithm);
	const slhdsaHashAlgo = prehashAlgoToSlhdsaLocal(prehashAlgorithm);

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
			// Hash → signPrehashed. `h.finalize()` disposes the hasher; the
			// belt-and-suspenders `h.dispose()` in catch handles the "throw
			// before finalize" path (dispose is idempotent so a redundant
			// post-finalize call is harmless).
			const h = createRunningHash(prehashAlgorithm);
			try {
				h.update(msg);
				const digest = h.finalize();
				try {
					return this.signPrehashed(sk, digest, ctx);
				} finally {
					wipe(digest);
				}
			} catch (e) {
				h.dispose();
				throw e;
			}
		},

		verify(
			pk:  Uint8Array,
			msg: Uint8Array,
			sig: Uint8Array,
			ctx: Uint8Array,
		): boolean {
			const h = createRunningHash(prehashAlgorithm);
			try {
				h.update(msg);
				const digest = h.finalize();
				try {
					return this.verifyPrehashed(pk, digest, sig, ctx);
				} finally {
					wipe(digest);
				}
			} catch (e) {
				h.dispose();
				throw e;
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const mldsaInst = new MlDsaClass();
			let mldsaKp;
			try {
				mldsaKp = mldsaInst.keygen();
			} finally {
				mldsaInst.dispose();
			}

			const slhdsaInst = new SlhDsaClass();
			let slhdsaKp;
			try {
				slhdsaKp = slhdsaInst.keygen();
			} finally {
				slhdsaInst.dispose();
			}

			return {
				pk: concat(mldsaKp.verificationKey, slhdsaKp.verificationKey),
				sk: concat(mldsaKp.signingKey,      slhdsaKp.signingKey),
			};
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

			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const skMldsa  = sk.subarray(0, mldsaParams.skBytes);
			const skSlhdsa = sk.subarray(mldsaParams.skBytes);

			const mldsaInst = new MlDsaClass();
			let sigMldsa: Uint8Array;
			try {
				sigMldsa = mldsaInst.signHashPrehashed(
					skMldsa, digest, mldsaHashAlgo, effectiveCtx,
				);
			} finally {
				mldsaInst.dispose();
			}

			const slhdsaInst = new SlhDsaClass();
			let sigSlhdsa: Uint8Array;
			try {
				sigSlhdsa = slhdsaInst.signHashPrehashed(
					skSlhdsa, digest, slhdsaHashAlgo, effectiveCtx,
				);
			} finally {
				slhdsaInst.dispose();
			}

			try {
				return concat(sigMldsa, sigSlhdsa);
			} finally {
				wipe(effectiveCtx);
			}
		},

		verifyPrehashed(
			pk:     Uint8Array,
			digest: Uint8Array,
			sig:    Uint8Array,
			ctx:    Uint8Array,
		): boolean {
			// Structural rejects: wrong-size inputs short-circuit before any
			// WASM is touched. Wire-derived lengths (pk_combined and the
			// composite sig) map to false because they depend on
			// attacker-observable bytes, not secret state. Digest length
			// is a caller-side contract (the caller computed it via the
			// suite's locked prehash algorithm) and throws symmetrically
			// with `signPrehashed`.
			if (pk.length  !== pkSize)     return false;
			if (sig.length !== sigMaxSize) return false;
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != ${prehashSize} for ${formatName}`,
				);

			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const pkMldsa   = pk.subarray(0, mldsaParams.pkBytes);
			const pkSlhdsa  = pk.subarray(mldsaParams.pkBytes);
			const sigMldsa  = sig.subarray(0, mldsaParams.sigBytes);
			const sigSlhdsa = sig.subarray(mldsaParams.sigBytes);

			// Compute both sub-verifies before combining. Do NOT early-return
			// on the first half's result; the timing-side gate the audit
			// will measure depends on neither half being skipped. Declare
			// without an initial value: if either WASM call throws (only
			// possible on a contract violation, never on bad-sig outcomes),
			// the exception propagates and `mldsaOk` / `slhdsaOk` are never
			// read.
			let mldsaOk:  boolean;
			let slhdsaOk: boolean;

			try {
				const mldsaInst = new MlDsaClass();
				try {
					mldsaOk = mldsaInst.verifyHashPrehashed(
						pkMldsa, digest, sigMldsa, mldsaHashAlgo, effectiveCtx,
					);
				} finally {
					mldsaInst.dispose();
				}

				const slhdsaInst = new SlhDsaClass();
				try {
					slhdsaOk = slhdsaInst.verifyHashPrehashed(
						pkSlhdsa, digest, sigSlhdsa, slhdsaHashAlgo, effectiveCtx,
					);
				} finally {
					slhdsaInst.dispose();
				}
			} finally {
				wipe(effectiveCtx);
			}

			// Both sub-verifies have already returned by this point; the &&
			// is a pure boolean reduction with nothing left to short-circuit.
			// Do NOT wipe sigMldsa / sigSlhdsa; they are subarrays of the
			// caller's `sig` buffer.
			return mldsaOk && slhdsaOk;
		},
	};
}

// ── Exported suite consts ───────────────────────────────────────────────────

export const MlDsa44SlhDsa128fSuite = MldsaSlhdsaHybridSuite(
	MlDsa44,  MLDSA44,    SlhDsa128f, SLHDSA128F,
	0x30, 'mldsa44-slhdsa128f',  'mldsa44-slhdsa128f-envelope-v3',
	'shake-128', 32,
);

export const MlDsa65SlhDsa192fSuite = MldsaSlhdsaHybridSuite(
	MlDsa65,  MLDSA65,    SlhDsa192f, SLHDSA192F,
	0x31, 'mldsa65-slhdsa192f',  'mldsa65-slhdsa192f-envelope-v3',
	'shake-256', 64,
);

export const MlDsa87SlhDsa256fSuite = MldsaSlhdsaHybridSuite(
	MlDsa87,  MLDSA87,    SlhDsa256f, SLHDSA256F,
	0x32, 'mldsa87-slhdsa256f',  'mldsa87-slhdsa256f-envelope-v3',
	'shake-256', 64,
);
