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
// src/ts/sign/suites/ecdsa-p256.ts
//
// EcdsaP256Suite (0x02, FIPS 186-5 §6.4 over SHA-256). Hedged-by-default
// per draft-irtf-cfrg-det-sigs-with-noise-05.
//
// Catalog + sizes: docs/signaturesuite.md. Suite reference: docs/ecdsa-p256.md.

import { SigningError } from '../../errors.js';
import { EcdsaP256 } from '../../ecdsa/index.js';
import { randomBytes, utf8ToBytes, wipe } from '../../utils.js';
import { CTX_DOMAIN_MAX } from '../ctx.js';
import { sha256OneShot } from '../hasher.js';
import type {
	StreamableSignatureSuite,
	PrehashAlgorithm,
} from '../types.js';

function EcdsaP256SuiteFactory(
	formatEnum: number,
	formatName: string,
	ctxDomain:  string,
): StreamableSignatureSuite {
	if (utf8ToBytes(ctxDomain).length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' too long for ${formatName}`,
		);

	const wasmModules = Object.freeze(['p256', 'sha2'] as const);
	const prehashAlgorithm: PrehashAlgorithm = 'sha-256';
	const prehashSize = 32;

	function rejectCtx(ctx: Uint8Array): void {
		if (ctx.length > 0)
			throw new SigningError(
				'sig-ctx-unsupported',
				`${formatName} does not support user context; ECDSA-P256 has `
				+ 'no native ctx parameter in FIPS 186-5 §6.4. Use the '
				+ 'classical+PQ hybrid suites (catalog 0x22 / 0x23) for '
				+ 'context-bound ECDSA-P256 signatures.',
			);
	}

	return {
		formatEnum,
		formatName,
		ctxDomain,
		pkSize: 33,
		skSize: 32,
		sigMaxSize: 64,
		wasmModules,
		prehashAlgorithm,
		prehashSize,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			rejectCtx(ctx);
			const digest = sha256OneShot(msg);
			const rnd = randomBytes(32);
			const inst = new EcdsaP256();
			try {
				return inst._signInternalPk(sk, digest, rnd);
			} finally {
				wipe(rnd);
				wipe(digest);
				inst.dispose();
			}
		},

		verify(
			pk:  Uint8Array,
			msg: Uint8Array,
			sig: Uint8Array,
			ctx: Uint8Array,
		): boolean {
			rejectCtx(ctx);
			const digest = sha256OneShot(msg);
			const inst = new EcdsaP256();
			try {
				return inst.verify(pk, digest, sig);
			} finally {
				inst.dispose();
				wipe(digest);
			}
		},

		keygen(): { pk: Uint8Array; sk: Uint8Array } {
			const inst = new EcdsaP256();
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
			rejectCtx(ctx);
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != expected ${prehashSize} for ${formatName}`,
				);
			const rnd = randomBytes(32);
			const inst = new EcdsaP256();
			try {
				return inst._signInternalPk(sk, digest, rnd);
			} finally {
				wipe(rnd);
				inst.dispose();
			}
		},

		verifyPrehashed(
			pk:     Uint8Array,
			digest: Uint8Array,
			sig:    Uint8Array,
			ctx:    Uint8Array,
		): boolean {
			rejectCtx(ctx);
			if (digest.length !== prehashSize)
				throw new SigningError(
					'sig-malformed-input',
					`digest length ${digest.length} != expected ${prehashSize} for ${formatName}`,
				);
			const inst = new EcdsaP256();
			try {
				return inst.verify(pk, digest, sig);
			} finally {
				inst.dispose();
			}
		},
	};
}

export const EcdsaP256Suite: StreamableSignatureSuite = EcdsaP256SuiteFactory(
	0x02, 'ecdsa-p256', 'ecdsa-p256-envelope-v3',
);
