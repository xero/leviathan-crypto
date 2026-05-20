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
// Ed25519PureSuite and Ed25519PrehashSuite factories (internal, not exported).
// Two exported const objects cover RFC 8032 Ed25519:
//   0x01  Ed25519Suite          (pure Ed25519, RFC 8032 §5.1.6)
//   0x11  Ed25519PreHashSuite   (Ed25519ph,   RFC 8032 §5.1.7)
//
// Each method instantiates a fresh `Ed25519` per call inside a
// try/finally + dispose pattern so WASM key material is wiped on every
// path. The factories are NOT exported: catalog format bytes are reserved
// and exposing factories would invite custom suites with unmanaged bytes.
//
// The pure-mode factory deliberately diverges from the mldsa / slhdsa
// precedents in one place: RFC 8032's pure Ed25519 has no native context
// parameter, so the suite rejects non-empty user_ctx with
// `SigningError('sig-ctx-unsupported')`. ctxDomain is set on the suite
// for `formatName` / display purposes only and is never fed to the
// underlying primitive. Callers who need context binding must use
// `Ed25519PreHashSuite`, where the dom2(F=1, ctx) construction (RFC 8032
// §5.1.7) gives a spec-defined home for it.
//
// Both suites advertise `wasmModules: ['curve25519']`; the prehash
// suite additionally requires `'sha2'` because the TS-side SHA-512
// shim in sign/hasher.ts drives the running prehash through the sha2
// WASM module. (The embedded SHA-512 inside curve25519.wasm is
// the substrate's own internal hash and is not exposed at the WASM
// ABI.)

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
			// Pure Ed25519 has no native context (RFC 8032 §5.1.6). ctxDomain
			// is set on the suite for formatName / display but is never bound
			// into the signature. Reject non-empty user_ctx; the only way to
			// bind a context with Ed25519 is the prehash mode
			// (Ed25519PreHashSuite, formatEnum 0x11) via dom2(F=1, ctx).
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

	// 'sha2' is advertised because the TS-side SHA-512 used by the
	// message-taking sign / verify paths and by SignStream's running
	// prehash both drive the sha2 WASM module. The dom2(F=1, ctx)
	// prefixing happens inside curve25519.wasm with its own embedded
	// SHA-512; sha2 is purely a TS-layer dependency.
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
