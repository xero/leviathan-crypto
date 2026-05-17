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
// EcdsaP256Suite factory (internal, not exported). One exported const
// covers FIPS 186-5 ECDSA over NIST P-256 with SHA-256:
//   0x02  EcdsaP256Suite  (single mode, SHA-256 prehash baked in)
//
// The catalog allocates 0x02 as a "single" entry distinct from 0x01
// (pure Ed25519) and 0x11 (Ed25519ph). ECDSA has no native pure mode,
// FIPS 186-5 §6.4 always signs SHA-256(M), so the suite carries one
// mode that streams its prehash. Structurally the suite conforms to
// StreamableSignatureSuite so SignStream / VerifyStream accept it.
//
// Suite-level sign is hedged-by-default per
// draft-irtf-cfrg-det-sigs-with-noise-05: every call generates a fresh
// 32-byte rnd via `randomBytes(32)` and feeds it to the underlying
// `_signInternalPk` entry point, which derives K via the noise-augmented
// RFC 6979 §3.2 construction. Callers that need deterministic signatures
// (e.g. for byte-exact KAT reproduction) must drop down to the
// `EcdsaP256` class directly and pass an all-zero rnd; the suite layer
// does not expose that knob because per-call entropy is the
// safety-by-default posture for v3 signing.
//
// ECDSA-P256 has no native context parameter (FIPS 186-5 §6.4 sign
// inputs are (d, hash, k) only). The suite carries `ctxDomain` for
// catalog symmetry and formatName display, but rejects non-empty
// user_ctx with `SigningError('sig-ctx-unsupported')` on every entry
// point. Applications that need context-bound ECDSA-P256 should reach
// for the classical+PQ hybrid suites (catalog 0x22 / 0x23), where the
// PQ half carries the ctx story via FIPS 204 / FIPS 205's native ctx
// parameter.
//
// Per-call WASM lifecycle: every method instantiates a fresh `EcdsaP256`
// inside a try/finally + dispose pattern so WASM key material is wiped
// on every path. The factory is NOT exported: the catalog format byte
// is reserved and exposing the factory would invite custom suites with
// unmanaged bytes.

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

	// 'p256' drives the ECDSA primitive; 'sha2' is required because the
	// TS-side `sha256OneShot` (message-taking sign / verify paths) and
	// `sha256Buffered` shim (SignStream running prehash) both drive the
	// sha2 WASM module. The substrate's own embedded SHA-256 (inside
	// p256.wasm, used for RFC 6979 K derivation) is internal and not
	// exposed at the WASM ABI.
	const wasmModules = Object.freeze(['p256', 'sha2'] as const);
	const prehashAlgorithm: PrehashAlgorithm = 'sha-256';
	const prehashSize = 32;

	function rejectCtx(ctx: Uint8Array): void {
		// FIPS 186-5 §6.4, ECDSA Signature Generation, parametrises sign
		// only on (d, H(m), k); there is no context input. The hybrid
		// classical+PQ suites at 0x22 / 0x23 carry the ctx story via
		// their PQ half.
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
		sigSize: 64,
		wasmModules,
		prehashAlgorithm,
		prehashSize,

		sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
			rejectCtx(ctx);
			const digest = sha256OneShot(msg);
			// Per-call entropy is secret-equivalent at sign time: knowing
			// rnd lets an attacker recover k and then d via the standard
			// ECDSA-with-known-k recovery. Wipe in the finally clause.
			const rnd = randomBytes(32);
			const inst = new EcdsaP256();
			try {
				return inst._signInternalPk(sk, digest, rnd);
			} finally {
				wipe(rnd);
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
