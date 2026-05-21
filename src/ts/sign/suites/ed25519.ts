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
// src/ts/sign/suites/ed25519.ts
//
// Ed25519Suite (0x01, RFC 8032 §5.1.6) and Ed25519PreHashSuite
// (0x11, Ed25519ph, RFC 8032 §5.1.7).
//
// Catalog + sizes: docs/signaturesuite.md. Suite reference: docs/ed25519.md.

import { utf8ToBytes, wipe } from '../../utils.js';
import { SigningError } from '../../errors.js';
import { Ed25519 } from '../../ed25519/index.js';
import {
	buildEffectiveCtx,
	CTX_DOMAIN_MAX,
} from '../ctx.js';
import { sha512OneShot } from '../hasher.js';
import type {
	SignatureSuite,
	StreamableSignatureSuite,
	PrehashAlgorithm,
} from '../types.js';

// ── Pure-mode factory ───────────────────────────────────────────────────────

function Ed25519PureSuite(
	formatEnum: number,
	formatName: string,
	ctxDomain:  string,
): SignatureSuite {
	if (utf8ToBytes(ctxDomain).length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' too long for ${formatName}`,
		);

	const wasmModules = Object.freeze(['curve25519'] as const);

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize: 32,
		skSize: 32,
		sigMaxSize: 64,
		wasmModules,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			if (ctx.length > 0)
				throw new SigningError(
					'sig-ctx-unsupported',
					`${formatName} (pure Ed25519) does not support user context; `
					+ 'use Ed25519PreHashSuite (formatEnum 0x11) for context-bound signatures',
				);
			const inst = new Ed25519();
			try {
				return inst._signInternalPk(sk, msg);
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
			if (ctx.length > 0)
				throw new SigningError(
					'sig-ctx-unsupported',
					`${formatName} (pure Ed25519) does not support user context; `
					+ 'use Ed25519PreHashSuite (formatEnum 0x11) for context-bound signatures',
				);
			const inst = new Ed25519();
			try {
				return inst.verify(pk, msg, sig);
			} finally {
				inst.dispose();
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const inst = new Ed25519();
			try {
				const kp = inst.keygen();
				return { pk: kp.publicKey, sk: kp.secretKey };
			} finally {
				inst.dispose();
			}
		},
	};
}

// ── Prehash-mode factory ────────────────────────────────────────────────────

function Ed25519PrehashSuite(
	formatEnum: number,
	formatName: string,
	ctxDomain:  string,
): StreamableSignatureSuite {
	if (utf8ToBytes(ctxDomain).length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' too long for ${formatName}`,
		);

	const wasmModules = Object.freeze(['curve25519', 'sha2'] as const);
	const prehashAlgorithm: PrehashAlgorithm = 'sha-512';
	const prehashSize = 64;

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize: 32,
		skSize: 32,
		sigMaxSize: 64,
		wasmModules,
		prehashAlgorithm,
		prehashSize,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			const effectiveCtx = buildEffectiveCtx(ctxDomain, ctx);
			const digest = sha512OneShot(msg);
			const inst = new Ed25519();
			try {
				return inst._signPrehashedInternalPk(sk, digest, effectiveCtx);
			} finally {
				inst.dispose();
				wipe(digest);
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
			const digest = sha512OneShot(msg);
			const inst = new Ed25519();
			try {
				return inst.verifyPrehashed(pk, digest, effectiveCtx, sig);
			} finally {
				inst.dispose();
				wipe(digest);
				wipe(effectiveCtx);
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const inst = new Ed25519();
			try {
				const kp = inst.keygen();
				return { pk: kp.publicKey, sk: kp.secretKey };
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
			const inst = new Ed25519();
			try {
				return inst._signPrehashedInternalPk(sk, digest, effectiveCtx);
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
			const inst = new Ed25519();
			try {
				return inst.verifyPrehashed(pk, digest, effectiveCtx, sig);
			} finally {
				inst.dispose();
				wipe(effectiveCtx);
			}
		},
	};
}

// ── Exported suite consts ───────────────────────────────────────────────────

export const Ed25519Suite: SignatureSuite = Ed25519PureSuite(
	0x01, 'ed25519', 'ed25519-envelope-v3',
);

export const Ed25519PreHashSuite: StreamableSignatureSuite = Ed25519PrehashSuite(
	0x11, 'ed25519-prehash', 'ed25519-prehash-envelope-v3',
);
