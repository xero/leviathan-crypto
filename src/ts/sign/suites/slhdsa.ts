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
// SlhdsaPureSuite and SlhdsaPrehashSuite factories (internal, not exported).
// Six exported const objects produced by factory calls cover the FIPS 205
// SHAKE-family fast parameter sets in both pure and prehash variants:
//   0x06  SlhDsa128fSuite              (pure)
//   0x07  SlhDsa192fSuite              (pure)
//   0x08  SlhDsa256fSuite              (pure)
//   0x16  SlhDsa128fPreHashSuite       (SHAKE128 prehash, 32-byte digest)
//   0x17  SlhDsa192fPreHashSuite       (SHAKE256 prehash, 64-byte digest)
//   0x18  SlhDsa256fPreHashSuite       (SHAKE256 prehash, 64-byte digest)
//
// Each method instantiates a fresh SlhDsa{128f,192f,256f} per call inside a
// try/finally + dispose pattern so WASM key material is wiped on every
// path. The factories are NOT exported: catalog format bytes are reserved
// and exposing factories would invite custom suites with unmanaged bytes.
//
// Pure variants advertise wasmModules: ['slhdsa']. Prehash variants
// advertise ['slhdsa', 'sha3'] because the running prehash inside the
// SignStream layer drives sha3's SHAKE128Stream / SHAKE256Stream. The
// slhdsa WASM module embeds its own Keccak permutation for internal
// F / H / T_l / PRF / PRFmsg / Hmsg primitives, so pure mode never
// touches sha3 directly.
//
// Hash-algorithm pinning per FIPS 205 §10.2.2:
//   128f-prehash → SHAKE128, only valid for category 1
//   192f-prehash → SHAKE256, valid for category 3 (and 5)
//   256f-prehash → SHAKE256, valid for category 5

import { utf8ToBytes } from '../../utils.js';
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

// Lowercase public sign-surface → uppercase SLH-DSA internal algorithm name.
// Phase 2 only wires the two SHAKE variants; remaining slh-dsa pre-hash
// names will join when a hybrid or non-SHAKE suite needs them.
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
		sigSize: params.sigBytes,
		wasmModules,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const inst = new SlhDsaClass();
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
			const inst = new SlhDsaClass();
			try {
				return inst.verify(pk, msg, sig, effectiveCtx);
			} finally {
				inst.dispose();
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
		sigSize: params.sigBytes,
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
			// Belt-and-suspenders: SlhDsaBase.signHashPrehashed also validates
			// digest length, but checking here keeps the suite contract
			// surface self-contained and produces the same discriminator.
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
			const inst = new SlhDsaClass();
			try {
				return inst.verifyHashPrehashed(
					pk, digest, sig, slhHashAlgo, effectiveCtx,
				);
			} finally {
				inst.dispose();
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
