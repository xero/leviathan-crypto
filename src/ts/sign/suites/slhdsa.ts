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
// src/ts/sign/suites/slhdsa.ts
//
// Pure (0x06/0x07/0x08) and prehash (0x16/0x17/0x18) SLH-DSA SHAKE-family
// fast suites, FIPS 205. Hash pinning per §10.2.2: 128f→SHAKE128 cat 1,
// 192f→SHAKE256 cat 3, 256f→SHAKE256 cat 5.
//
// Catalog + prehash mapping: docs/signaturesuite.md, docs/slhdsa.md.

import { utf8ToBytes, wipe } from '../../utils.js';
import { SigningError } from '../../errors.js';
import {
	SlhDsa128f, SlhDsa192f, SlhDsa256f,
	SLHDSA128F, SLHDSA192F, SLHDSA256F,
} from '../../slhdsa/index.js';
import type { SlhDsaParams } from '../../slhdsa/index.js';
import type { PreHashAlgorithm as SlhPreHashAlgorithm } from '../../slhdsa/prehash.js';
import { buildEffectiveCtx, CTX_DOMAIN_MAX } from '../ctx.js';
import type {
	SignatureSuite,
	StreamableSignatureSuite,
	PrehashAlgorithm,
} from '../types.js';

type SlhDsaCtor = typeof SlhDsa128f | typeof SlhDsa192f | typeof SlhDsa256f;

function prehashAlgoToSlhdsa(algo: PrehashAlgorithm): SlhPreHashAlgorithm {
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

// ── Pure-mode factory ───────────────────────────────────────────────────────

function SlhdsaPureSuite(
	SlhDsaClass: SlhDsaCtor,
	params:     SlhDsaParams,
	formatEnum: number,
	formatName: string,
	ctxDomain:  string,
): SignatureSuite {
	if (utf8ToBytes(ctxDomain).length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' too long for ${formatName}`,
		);

	const wasmModules = Object.freeze(['slhdsa'] as const);

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize: params.pkBytes,
		skSize: params.skBytes,
		sigMaxSize: params.sigBytes,
		wasmModules,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new SlhDsaClass();
			try {
				return inst.sign(sk, msg, effectiveCtx);
			} finally {
				inst.dispose();
				wipe(effectiveCtx);
			}
		},

		verify(
			pk:  Uint8Array,
			msg: Uint8Array,
			sig: Uint8Array,
			ctx: Uint8Array,
		): boolean {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new SlhDsaClass();
			try {
				return inst.verify(pk, msg, sig, effectiveCtx);
			} finally {
				inst.dispose();
				wipe(effectiveCtx);
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const inst = new SlhDsaClass();
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

function SlhdsaPrehashSuite(
	SlhDsaClass:      SlhDsaCtor,
	params:           SlhDsaParams,
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

	const wasmModules = Object.freeze(['slhdsa', 'sha3'] as const);
	const slhHashAlgo = prehashAlgoToSlhdsa(prehashAlgorithm);

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize: params.pkBytes,
		skSize: params.skBytes,
		sigMaxSize: params.sigBytes,
		wasmModules,
		prehashAlgorithm,
		prehashSize,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new SlhDsaClass();
			try {
				return inst.signHash(sk, msg, slhHashAlgo, effectiveCtx);
			} finally {
				inst.dispose();
				wipe(effectiveCtx);
			}
		},

		verify(
			pk:  Uint8Array,
			msg: Uint8Array,
			sig: Uint8Array,
			ctx: Uint8Array,
		): boolean {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new SlhDsaClass();
			try {
				return inst.verifyHash(pk, msg, sig, slhHashAlgo, effectiveCtx);
			} finally {
				inst.dispose();
				wipe(effectiveCtx);
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const inst = new SlhDsaClass();
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
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != expected ${prehashSize} for ${formatName}`,
				);
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new SlhDsaClass();
			try {
				return inst.signHashPrehashed(sk, digest, slhHashAlgo, effectiveCtx);
			} finally {
				inst.dispose();
				wipe(effectiveCtx);
			}
		},

		verifyPrehashed(
			pk:     Uint8Array,
			digest: Uint8Array,
			sig:    Uint8Array,
			ctx:    Uint8Array,
		): boolean {
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != expected ${prehashSize} for ${formatName}`,
				);
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new SlhDsaClass();
			try {
				return inst.verifyHashPrehashed(
					pk, digest, sig, slhHashAlgo, effectiveCtx,
				);
			} finally {
				inst.dispose();
				wipe(effectiveCtx);
			}
		},
	};
}

// ── Exported suite consts ───────────────────────────────────────────────────

export const SlhDsa128fSuite = SlhdsaPureSuite(
	SlhDsa128f, SLHDSA128F, 0x06, 'slhdsa128f', 'slhdsa128f-envelope-v3',
);
export const SlhDsa192fSuite = SlhdsaPureSuite(
	SlhDsa192f, SLHDSA192F, 0x07, 'slhdsa192f', 'slhdsa192f-envelope-v3',
);
export const SlhDsa256fSuite = SlhdsaPureSuite(
	SlhDsa256f, SLHDSA256F, 0x08, 'slhdsa256f', 'slhdsa256f-envelope-v3',
);

export const SlhDsa128fPreHashSuite = SlhdsaPrehashSuite(
	SlhDsa128f, SLHDSA128F, 0x16, 'slhdsa128f-prehash',
	'slhdsa128f-prehash-envelope-v3', 'shake-128', 32,
);
export const SlhDsa192fPreHashSuite = SlhdsaPrehashSuite(
	SlhDsa192f, SLHDSA192F, 0x17, 'slhdsa192f-prehash',
	'slhdsa192f-prehash-envelope-v3', 'shake-256', 64,
);
export const SlhDsa256fPreHashSuite = SlhdsaPrehashSuite(
	SlhDsa256f, SLHDSA256F, 0x18, 'slhdsa256f-prehash',
	'slhdsa256f-prehash-envelope-v3', 'shake-256', 64,
);
