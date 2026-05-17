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
// src/ts/sign/types.ts
//
// SignatureSuite interface definitions for the v3 signature layer.
// Mirrors src/ts/stream/types.ts (CipherSuite) shape; signatures plug
// into Sign / SignStream / VerifyStream the way ciphers plug into
// Seal / SealStream / OpenStream.

/**
 * Prehash algorithm identifier used by StreamableSignatureSuite. The
 * lowercase, hyphenated form is the lib's public sign-surface; the
 * mldsa-internal `PreHashAlgorithm` (uppercase, no hyphen on SHAKE)
 * remains private. `prehashAlgoToMldsa` in ctx.ts is the only bridge.
 */
export type PrehashAlgorithm =
	| 'sha-256'
	| 'sha-512'
	| 'sha3-256'
	| 'sha3-512'
	| 'shake-128'
	| 'shake-256';

/**
 * Base SignatureSuite interface. All suite consts conform to this.
 * Pure-mode suites conform to SignatureSuite only; suites that support
 * streaming additionally conform to StreamableSignatureSuite.
 */
export interface SignatureSuite {
	/**
	 * Wire format byte. Bits 0-3 = suite within category;
	 * bits 4-5 = category (0x0X pure, 0x1X prehash, 0x2X classical+PQ
	 * hybrid, 0x3X PQ-only hybrid); bits 6-7 reserved.
	 */
	readonly formatEnum: number;

	/** Human label, e.g. 'mldsa65', 'mldsa65-prehash'. */
	readonly formatName: string;

	/**
	 * Built-in domain separator. Concatenated, length-prefixed, with
	 * user-supplied ctx before being fed to the underlying primitive's
	 * ctx parameter. Convention: `{scheme}-envelope-v3` for pure suites,
	 * `{scheme}-prehash-envelope-v3` for prehash variants. Max 32 bytes,
	 * validated at factory construction.
	 */
	readonly ctxDomain: string;

	/** Public key size in bytes. */
	readonly pkSize: number;

	/** Secret key size in bytes. */
	readonly skSize: number;

	/**
	 * Upper-bound signature size in bytes. For fixed-length signature
	 * schemes equals the actual size. For variable-length schemes
	 * (e.g., composite ECDSA whose `Ecdsa-Sig-Value` DER encoding per
	 * RFC 3279 §2.2.3 varies with leading-zero stripping) is the
	 * catalog-reserved upper bound, the actual sig may be shorter.
	 * Hybrid suites precompute `sig_classical + sig_pq` for clear
	 * visibility.
	 */
	readonly sigMaxSize: number;

	/** WASM modules this suite requires initialized via init(). */
	readonly wasmModules: readonly string[];

	/**
	 * Sign a message. Returns the raw signature bytes, not wrapped in
	 * the envelope wire format; that is Sign.sign's job.
	 *
	 * @param sk  Secret key, must be exactly skSize bytes.
	 * @param msg Message to sign. Any length.
	 * @param ctx User context, up to USER_CTX_MAX (255) bytes per
	 *            FIPS 204 §3.6.1. Suites that route ctx through
	 *            buildEffectiveCtx have a tighter per-call ceiling
	 *            equal to `253 - len(ctxDomain)`. Empty Uint8Array
	 *            is legal but must be passed explicitly.
	 * @throws SigningError on contract violations (wrong-size key,
	 *         ctx too long).
	 * @returns Signature bytes, length at most sigMaxSize.
	 */
	sign(sk: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array;

	/**
	 * Verify a signature. Returns boolean for all signature outcomes
	 * including malformed signature encoding. Throws SigningError on
	 * contract violations (wrong-size key, ctx too long).
	 */
	verify(
		pk: Uint8Array,
		msg: Uint8Array,
		sig: Uint8Array,
		ctx: Uint8Array,
	): boolean;

	/**
	 * Generate a fresh keypair. Returns named-field object regardless
	 * of how the underlying primitive names its keys.
	 */
	keygen(): { pk: Uint8Array; sk: Uint8Array };
}

/**
 * SignatureSuite extension for streamable signing. Suites that support
 * SignStream / VerifyStream must conform to this interface; pure-mode
 * suites do not.
 */
export interface StreamableSignatureSuite extends SignatureSuite {
	/** Prehash algorithm. Locked at suite construction. */
	readonly prehashAlgorithm: PrehashAlgorithm;

	/** Digest size in bytes for the locked prehash algorithm. */
	readonly prehashSize: number;

	/**
	 * Sign a precomputed digest. Caller is responsible for computing
	 * the digest with the prehash algorithm matching this suite, or
	 * using SignStream which does it internally.
	 *
	 * @param digest Digest bytes, must be exactly prehashSize.
	 * @throws SigningError('sig-malformed-input') on digest length
	 *         mismatch; SigningError on other contract violations.
	 */
	signPrehashed(
		sk: Uint8Array,
		digest: Uint8Array,
		ctx: Uint8Array,
	): Uint8Array;

	/**
	 * Verify a precomputed-digest signature. Returns false on signature
	 * failure (including malformed signature encoding). Throws SigningError
	 * on contract violations: wrong-size key, ctx too long, or wrong-size
	 * digest (`sig-malformed-input`). The digest length is a caller-side
	 * contract; symmetric with `signPrehashed` which throws on the same
	 * condition.
	 */
	verifyPrehashed(
		pk: Uint8Array,
		digest: Uint8Array,
		sig: Uint8Array,
		ctx: Uint8Array,
	): boolean;
}
