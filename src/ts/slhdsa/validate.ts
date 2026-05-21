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
// src/ts/slhdsa/validate.ts
//
// SLH-DSA caller-side input validation. Pure length / type checks. Mirrors
// `src/ts/mldsa/validate.ts`. Length checks throw RangeError; the public
// verify() / verifyHash() / verifyHashPrehashed() surfaces intercept pk /
// sig / digest length mismatches and return false instead of propagating the
// throw (FIPS 205 §3.6.2 / §10 structural-mismatch posture). ctx, sk, and
// rnd / opt_rand are caller contract violations and let the throw propagate.

import type { SlhDsaParams } from './params.js';
import { SigningError } from '../errors.js';
import { type PreHashAlgorithm, digestSize } from './prehash.js';

/**
 * FIPS 205 §10.2.1 Algorithm 22 line 1 / §10.2.2 Algorithm 23 line 1,
 * ctx must be ≤ 255 bytes (the byte that follows the domain separator in
 * M' encodes |ctx|, so longer values cannot be represented). Throws
 * `SigningError('sig-ctx-too-long')` per the SigningError discriminator contract.
 */
export function validateContext(ctx: Uint8Array): void {
	if (!(ctx instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ctx must be a Uint8Array');
	if (ctx.length > 255)
		throw new SigningError('sig-ctx-too-long', `leviathan-crypto: ctx must be ≤ 255 bytes (got ${ctx.length})`);
}

/**
 * FIPS 205 §3.6.2, public key must be exactly pkBytes long for its
 * parameter set. Throws here; the public verify*() surfaces catch the
 * throw and return false so a wrong-length pk reads as "not a valid
 * signature" rather than a caller error.
 */
export function validatePublicKey(pk: Uint8Array, params: SlhDsaParams): void {
	if (!(pk instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: public key must be a Uint8Array');
	if (pk.length !== params.pkBytes)
		throw new RangeError(
			`leviathan-crypto: public key must be ${params.pkBytes} bytes for ${params.paramSet} `
			+ `(got ${pk.length})`,
		);
}

/**
 * Signing key must be exactly skBytes long for its parameter set. Wrong
 * length is a caller error (the caller produced this sk via keygen* or
 * loaded it from storage they own); throw RangeError unconditionally.
 */
export function validateSigningKey(sk: Uint8Array, params: SlhDsaParams): void {
	if (!(sk instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: signing key must be a Uint8Array');
	if (sk.length !== params.skBytes)
		throw new RangeError(
			`leviathan-crypto: signing key must be ${params.skBytes} bytes for ${params.paramSet} `
			+ `(got ${sk.length})`,
		);
}

/**
 * FIPS 205 §3.6.2, signature must be exactly sigBytes long for its
 * parameter set. Throws here; the public verify*() surfaces catch and
 * return false (same protocol shape as wrong-length pk).
 */
export function validateSignature(sig: Uint8Array, params: SlhDsaParams): void {
	if (!(sig instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: signature must be a Uint8Array');
	if (sig.length !== params.sigBytes)
		throw new RangeError(
			`leviathan-crypto: signature must be ${params.sigBytes} bytes for ${params.paramSet} `
			+ `(got ${sig.length})`,
		);
}

/**
 * FIPS 205 §3.4 / §9.2 Algorithm 19 line 4, opt_rand (addrnd) must be
 * exactly n bytes for the parameter set. Used by signDerand (the
 * testing / CAVP API). Hedged sign supplies opt_rand internally;
 * deterministic sign substitutes PK.seed; only signDerand exposes
 * opt_rand to the caller.
 */
export function validateRnd(rnd: Uint8Array, params: SlhDsaParams): void {
	if (!(rnd instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: opt_rand must be a Uint8Array');
	if (rnd.length !== params.n)
		throw new RangeError(
			`leviathan-crypto: opt_rand must be ${params.n} bytes for ${params.paramSet} `
			+ `(got ${rnd.length})`,
		);
}

/**
 * Confirms M is a Uint8Array. FIPS 205 places no length restriction on
 * the message; M is absorbed into Hmsg via SHAKE256 / SHA-2 depending on
 * the chosen instantiation (§11.2 SHAKE family in the shipped scope), so
 * any byte length is admissible.
 */
export function validateMessage(M: Uint8Array): void {
	if (!(M instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: message must be a Uint8Array');
}

/**
 * FIPS 205 §10.2.2 Algorithm 23 lines 9-20, the prehash PH_M passed to
 * HashSLH-DSA's Sign_internal / Verify_internal must be exactly the
 * digest size of `algo`. Used by the `*Prehashed` family where the
 * caller computes PH externally; the non-prehashed family produces PH
 * internally so this check is implicit.
 *
 * Throws `SigningError('sig-malformed-input')` on mismatch. The verify
 * surface intercepts this to return false (a wrong-size digest is a
 * structural mismatch, indistinguishable from a wrong signature), while
 * the sign surface lets the throw propagate (the caller supplied bad
 * input; that is a contract violation).
 *
 * Duplicated from `src/ts/mldsa/validate.ts:validateDigest`; extraction is
 * deferred until a third consumer materialises.
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
