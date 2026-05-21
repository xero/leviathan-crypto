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
// src/ts/mldsa/validate.ts
//
// ML-DSA caller-side input validation. Pure length / type checks, no
// content validation here. Semantic content validity (e.g. malformed hint
// encoding) is handled inside Verify_internal via hint_bit_unpack's -1
// sentinel (FIPS 204 Algorithm 21 / §D.3).
//
// Length checks throw RangeError. The public verify() method intercepts
// pk/sig length mismatches and returns false instead of propagating the
// throw, that is FIPS 204 §3.6.2 protocol shape, not a contract violation.
// validateContext, validateSigningKey, validateRnd ARE contract violations
// and propagate the throw.

import type { MlDsaParams } from './params.js';
import { SigningError } from '../errors.js';
import { type PreHashAlgorithm, digestSize } from './hashvariant.js';

/**
 * FIPS 204 §5.2 / §5.3 line 1, ctx must be ≤ 255 bytes (the byte that
 * follows the domain separator in M' is ctx.length, so longer values
 * cannot be encoded).
 */
export function validateContext(ctx: Uint8Array): void {
	if (!(ctx instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ctx must be a Uint8Array');
	if (ctx.length > 255)
		throw new RangeError(`leviathan-crypto: ctx must be ≤ 255 bytes (got ${ctx.length})`);
}

/**
 * FIPS 204 §3.6.2, verification key must be exactly pkBytes long for
 * its parameter set. Throws here; the public verify() method catches
 * the throw and returns false so wrong-length pk reads as "not a valid
 * signature" rather than a caller error.
 */
export function validateVerificationKey(vk: Uint8Array, params: MlDsaParams): void {
	if (!(vk instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: verification key must be a Uint8Array');
	if (vk.length !== params.pkBytes)
		throw new RangeError(
			`leviathan-crypto: verification key must be ${params.pkBytes} bytes for ${params.paramSet} `
			+ `(got ${vk.length})`,
		);
}

/**
 * Signing key must be exactly skBytes long for its parameter set. Wrong
 * length is a caller error (the caller produced this sk via keygen* or
 * loaded it from storage they own); throw RangeError unconditionally.
 */
export function validateSigningKey(sk: Uint8Array, params: MlDsaParams): void {
	if (!(sk instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: signing key must be a Uint8Array');
	if (sk.length !== params.skBytes)
		throw new RangeError(
			`leviathan-crypto: signing key must be ${params.skBytes} bytes for ${params.paramSet} `
			+ `(got ${sk.length})`,
		);
}

/**
 * FIPS 204 §3.6.2, signature must be exactly sigBytes long for its
 * parameter set. Throws here; the public verify() method catches and
 * returns false (same protocol shape as wrong-length pk).
 */
export function validateSignature(sig: Uint8Array, params: MlDsaParams): void {
	if (!(sig instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: signature must be a Uint8Array');
	if (sig.length !== params.sigBytes)
		throw new RangeError(
			`leviathan-crypto: signature must be ${params.sigBytes} bytes for ${params.paramSet} `
			+ `(got ${sig.length})`,
		);
}

/**
 * FIPS 204 Algorithm 7 line 1, rnd must be 32 bytes. Used by signDerand
 * (the testing/CAVP API). Hedged sign supplies rnd internally; deterministic
 * sign uses zeros; only signDerand exposes rnd to the caller.
 */
export function validateRnd(rnd: Uint8Array): void {
	if (!(rnd instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: rnd must be a Uint8Array');
	if (rnd.length !== 32)
		throw new RangeError(`leviathan-crypto: rnd must be 32 bytes (got ${rnd.length})`);
}

/**
 * Confirms M is a Uint8Array. FIPS 204 places no length restriction on
 * the message, M is absorbed into a SHAKE256 sponge (μ derivation,
 * §6.2/§6.3) so any byte length is admissible. The bit-vs-byte
 * distinction visible in §5.2/§5.3 (BytesToBits in M' construction)
 * collapses at the byte boundary inside our SHAKE wrapper.
 */
export function validateMessage(M: Uint8Array): void {
	if (!(M instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: message must be a Uint8Array');
}

/**
 * FIPS 204 §5.4.1, the prehash PH_M passed to HashML-DSA Sign_internal /
 * Verify_internal must be exactly the digest size of `algo`. Used by the
 * `*Prehashed` family where the caller computes PH externally; the
 * non-prehashed family produces PH internally so this check is implicit.
 *
 * Throws `SigningError('sig-malformed-input')` on mismatch. The verify
 * surface intercepts this to return false (a wrong-size digest is a
 * structural mismatch, indistinguishable from a wrong signature), while
 * the sign surface lets the throw propagate (the caller supplied bad
 * input, that is a contract violation per the FIPS 204 §5.4 input
 * contract).
 */
export function validateDigest(digest: Uint8Array, algo: PreHashAlgorithm): void {
	if (!(digest instanceof Uint8Array))
		throw new SigningError('sig-malformed-input', 'digest must be a Uint8Array');
	const expected = digestSize(algo);
	if (digest.length !== expected)
		throw new SigningError(
			'sig-malformed-input',
			`digest length ${digest.length} != ${expected} for ${algo}`,
		);
}
