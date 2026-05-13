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
// src/ts/sign/ctx.ts
//
// Effective-ctx construction and prehash-algorithm mapping. Used by
// every SignatureSuite factory.

import { utf8ToBytes } from '../utils.js';
import { SigningError } from '../errors.js';
import type { PreHashAlgorithm } from '../mldsa/hashvariant.js';
import type { PrehashAlgorithm } from './types.js';

/** Maximum user_ctx length in bytes; enforced by buildEffectiveCtx. */
export const USER_CTX_MAX = 200;

/** Maximum ctxDomain length in bytes; enforced by suite factories. */
export const CTX_DOMAIN_MAX = 32;

/**
 * Construct effective_ctx from suite domain and user-supplied ctx.
 *
 * Format: [domain_len: u8][domain_bytes][user_ctx_len: u8][user_ctx_bytes]
 *
 * The result is passed to FIPS 204's ctx parameter (max 255 bytes). The
 * 1-byte prefixes plus the (32 + 200) caps stay comfortably under 234
 * bytes total.
 *
 * @throws SigningError('sig-ctx-too-long') if user_ctx exceeds USER_CTX_MAX.
 * @throws Error (not SigningError) if ctxDomain exceeds CTX_DOMAIN_MAX;
 *         that's a developer-time mistake, not a caller mistake.
 */
export function buildEffectiveCtx(
	ctxDomain: string,
	userCtx: Uint8Array,
): Uint8Array {
	if (userCtx.length > USER_CTX_MAX)
		throw new SigningError(
			'sig-ctx-too-long',
			`user_ctx length ${userCtx.length} > ${USER_CTX_MAX}`,
		);
	const domainBytes = utf8ToBytes(ctxDomain);
	if (domainBytes.length > CTX_DOMAIN_MAX)
		throw new Error(
			`leviathan-crypto: ctxDomain '${ctxDomain}' encodes to ${domainBytes.length} bytes (max ${CTX_DOMAIN_MAX})`,
		);
	const out = new Uint8Array(1 + domainBytes.length + 1 + userCtx.length);
	let pos = 0;
	out[pos++] = domainBytes.length;
	out.set(domainBytes, pos); pos += domainBytes.length;
	out[pos++] = userCtx.length;
	out.set(userCtx, pos);
	return out;
}

/**
 * Map the lib's lowercase, hyphenated PrehashAlgorithm to the identifier
 * MlDsaBase's signHash / verifyHash family accepts (FIPS 204 §5.4.1).
 * SHAKE entries deliberately use the no-hyphen spelling 'SHAKE128' /
 * 'SHAKE256' that the mldsa layer expects.
 */
export function prehashAlgoToMldsa(algo: PrehashAlgorithm): PreHashAlgorithm {
	switch (algo) {
	case 'sha-256':   return 'SHA2-256';
	case 'sha-512':   return 'SHA2-512';
	case 'sha3-256':  return 'SHA3-256';
	case 'sha3-512':  return 'SHA3-512';
	case 'shake-128': return 'SHAKE128';
	case 'shake-256': return 'SHAKE256';
	default: {
		const _exhaustive: never = algo;
		throw new Error(
			`leviathan-crypto: unknown prehash algorithm ${_exhaustive as string}`,
		);
	}
	}
}
