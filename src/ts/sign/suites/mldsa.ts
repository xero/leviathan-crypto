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
// src/ts/sign/suites/mldsa.ts
//
// MldsaPureSuite and MldsaPrehashSuite factories (internal, not exported).
// Six exported const objects produced by factory calls cover the FIPS 204
// parameter sets in both pure and prehash variants:
//   0x03  MlDsa44Suite              (pure)
//   0x04  MlDsa65Suite              (pure)
//   0x05  MlDsa87Suite              (pure)
//   0x13  MlDsa44PreHashSuite       (SHA3-256 prehash)
//   0x14  MlDsa65PreHashSuite       (SHA3-256 prehash)
//   0x15  MlDsa87PreHashSuite       (SHA3-512 prehash)
//
// Each method instantiates a fresh MlDsa{44,65,87} per call inside a
// try/finally + dispose pattern so WASM key material is wiped on every
// path. The factories are NOT exported: catalog format bytes are reserved
// and exposing factories would invite custom suites with unmanaged bytes.

import { utf8ToBytes } from '../../utils.js';
import { SigningError } from '../../errors.js';
import {
	MlDsa44, MlDsa65, MlDsa87,
	MLDSA44, MLDSA65, MLDSA87,
} from '../../mldsa/index.js';
import type { MlDsaParams } from '../../mldsa/index.js';
import {
	buildEffectiveCtx,
	prehashAlgoToMldsa,
	CTX_DOMAIN_MAX,
} from '../ctx.js';
import type {
	SignatureSuite,
	StreamableSignatureSuite,
	PrehashAlgorithm,
} from '../types.js';

type MlDsaCtor = typeof MlDsa44 | typeof MlDsa65 | typeof MlDsa87;

// ── Pure-mode factory ───────────────────────────────────────────────────────

function MldsaPureSuite(
	MlDsaClass: MlDsaCtor,
	params:     MlDsaParams,
	formatEnum: number,
	formatName: string,
	ctxDomain:  string,
): SignatureSuite {
	if (utf8ToBytes(ctxDomain).length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' too long for ${formatName}`,
		);

	const wasmModules = Object.freeze(['mldsa', 'sha3'] as const);

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize: params.pkBytes,
		skSize: params.skBytes,
		sigSize: params.sigBytes,
		wasmModules,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new MlDsaClass();
			try {
				return inst.sign(sk, msg, effectiveCtx);
			} finally {
				inst.dispose();
			}
		},

		verify(
			pk:  Uint8Array,
			msg: Uint8Array,
			sig: Uint8Array,
			ctx: Uint8Array,
		): boolean {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new MlDsaClass();
			try {
				return inst.verify(pk, msg, sig, effectiveCtx);
			} finally {
				inst.dispose();
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const inst = new MlDsaClass();
			try {
				const kp = inst.keygen();
				return { pk: kp.verificationKey, sk: kp.signingKey };
			} finally {
				inst.dispose();
			}
		},
	};
}

// ── Prehash-mode factory ────────────────────────────────────────────────────

function MldsaPrehashSuite(
	MlDsaClass:       MlDsaCtor,
	params:           MlDsaParams,
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

	const wasmModules   = Object.freeze(['mldsa', 'sha3'] as const);
	const mldsaHashAlgo = prehashAlgoToMldsa(prehashAlgorithm);

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize: params.pkBytes,
		skSize: params.skBytes,
		sigSize: params.sigBytes,
		wasmModules,
		prehashAlgorithm,
		prehashSize,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new MlDsaClass();
			try {
				return inst.signHash(sk, msg, mldsaHashAlgo, effectiveCtx);
			} finally {
				inst.dispose();
			}
		},

		verify(
			pk:  Uint8Array,
			msg: Uint8Array,
			sig: Uint8Array,
			ctx: Uint8Array,
		): boolean {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new MlDsaClass();
			try {
				return inst.verifyHash(pk, msg, sig, mldsaHashAlgo, effectiveCtx);
			} finally {
				inst.dispose();
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const inst = new MlDsaClass();
			try {
				const kp = inst.keygen();
				return { pk: kp.verificationKey, sk: kp.signingKey };
			} finally {
				inst.dispose();
			}
		},

		signPrehashed(
			sk:     Uint8Array,
			digest: Uint8Array,
			ctx:    Uint8Array,
		): Uint8Array {
			// Belt-and-suspenders: MlDsaBase.signHashPrehashed also validates
			// digest length, but checking here keeps the suite's contract
			// surface self-contained and produces the same discriminator.
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != expected ${prehashSize} for ${formatName}`,
				);
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new MlDsaClass();
			try {
				return inst.signHashPrehashed(
					sk, digest, mldsaHashAlgo, effectiveCtx,
				);
			} finally {
				inst.dispose();
			}
		},

		verifyPrehashed(
			pk:     Uint8Array,
			digest: Uint8Array,
			sig:    Uint8Array,
			ctx:    Uint8Array,
		): boolean {
			if (digest.length !== prehashSize) return false;
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new MlDsaClass();
			try {
				return inst.verifyHashPrehashed(
					pk, digest, sig, mldsaHashAlgo, effectiveCtx,
				);
			} finally {
				inst.dispose();
			}
		},
	};
}

// ── Exported suite consts ───────────────────────────────────────────────────

export const MlDsa44Suite = MldsaPureSuite(
	MlDsa44, MLDSA44, 0x03, 'mldsa44', 'mldsa44-envelope-v3',
);
export const MlDsa65Suite = MldsaPureSuite(
	MlDsa65, MLDSA65, 0x04, 'mldsa65', 'mldsa65-envelope-v3',
);
export const MlDsa87Suite = MldsaPureSuite(
	MlDsa87, MLDSA87, 0x05, 'mldsa87', 'mldsa87-envelope-v3',
);

export const MlDsa44PreHashSuite = MldsaPrehashSuite(
	MlDsa44, MLDSA44, 0x13, 'mldsa44-prehash',
	'mldsa44-prehash-envelope-v3', 'sha3-256', 32,
);
export const MlDsa65PreHashSuite = MldsaPrehashSuite(
	MlDsa65, MLDSA65, 0x14, 'mldsa65-prehash',
	'mldsa65-prehash-envelope-v3', 'sha3-256', 32,
);
export const MlDsa87PreHashSuite = MldsaPrehashSuite(
	MlDsa87, MLDSA87, 0x15, 'mldsa87-prehash',
	'mldsa87-prehash-envelope-v3', 'sha3-512', 64,
);
