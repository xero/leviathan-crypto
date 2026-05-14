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
// src/ts/slhdsa/params.ts
//
// SLH-DSA (FIPS 205) parameter sets.
//
// Numeric values come from FIPS 205 §11.1 Table 2; derived sizes come from
// FIPS 205 §11.2 (pk = 2·n, sk = 4·n) and the §9 sigEncode algorithm:
//
//   sigBytes = (1 + k·(a+1) + h + d·len) · n
//
// where w = 16 (the only approved Winternitz parameter in §11.1), so
// len_1 = ⌈8·n/4⌉, len_2 = 3, len = len_1 + len_2.
//
// Phase 2 scope is the SHAKE-family fast variants (128f / 192f / 256f) only;
// the slow variants and the SHA-2 family are explicitly out of scope.
//
// `securityCategory` (NIST PQC category 1 / 3 / 5) drives the per-set
// HashSLH-DSA category gate in `validate.ts` / `index.ts`. `wasmSelector`
// runs the corresponding `slhSetParams*` thunk on the WASM module so the
// PARAMS slot reflects this set before any algorithm call.

import { getInstance } from '../init.js';
import type { SlhDsaExports } from './types.js';

export interface SlhDsaParams {
	paramSet:         'SLH-DSA-SHAKE-128f' | 'SLH-DSA-SHAKE-192f' | 'SLH-DSA-SHAKE-256f'
	n:                number   // security parameter, bytes (FIPS 205 §11.1 Table 2)
	h:                number   // total hypertree height
	d:                number   // hypertree layer count
	hPrime:           number   // XMSS subtree height, h/d
	k:                number   // number of FORS trees
	a:                number   // FORS tree height (bits per tree)
	m:                number   // Hmsg output length in bytes
	pkBytes:          number   // 2·n
	skBytes:          number   // 4·n
	sigBytes:         number   // (1 + k·(a+1) + h + d·len) · n
	securityCategory: 1 | 3 | 5
	/** Bind this parameter set into the WASM PARAMS slot. Called by every
	 *  SlhDsaBase public method before driving slh{Keygen,Sign,Verify}Internal
	 *  so the WASM dimension lookups (slhK, slhA, slhD, slhHPrime, etc.)
	 *  resolve to this set. Reads the slhdsa exports lazily so the function
	 *  reference can be shared across modules without baking in an instance. */
	wasmSelector: () => void
}

function selectorFor(name: 'slhSetParams128f' | 'slhSetParams192f' | 'slhSetParams256f'): () => void {
	return () => {
		(getInstance('slhdsa').exports as unknown as SlhDsaExports)[name]();
	};
}

/** SLH-DSA-SHAKE-128f, FIPS 205 §11.1 Table 2 (NIST security category 1). */
export const SLHDSA128F: SlhDsaParams = {
	paramSet: 'SLH-DSA-SHAKE-128f',
	n: 16, h: 66, d: 22, hPrime: 3, k: 33, a: 6, m: 34,
	pkBytes: 32, skBytes: 64, sigBytes: 17088,
	securityCategory: 1,
	wasmSelector: selectorFor('slhSetParams128f'),
};

/** SLH-DSA-SHAKE-192f, FIPS 205 §11.1 Table 2 (NIST security category 3). */
export const SLHDSA192F: SlhDsaParams = {
	paramSet: 'SLH-DSA-SHAKE-192f',
	n: 24, h: 66, d: 22, hPrime: 3, k: 33, a: 8, m: 42,
	pkBytes: 48, skBytes: 96, sigBytes: 35664,
	securityCategory: 3,
	wasmSelector: selectorFor('slhSetParams192f'),
};

/** SLH-DSA-SHAKE-256f, FIPS 205 §11.1 Table 2 (NIST security category 5). */
export const SLHDSA256F: SlhDsaParams = {
	paramSet: 'SLH-DSA-SHAKE-256f',
	n: 32, h: 68, d: 17, hPrime: 4, k: 35, a: 9, m: 49,
	pkBytes: 64, skBytes: 128, sigBytes: 49856,
	securityCategory: 5,
	wasmSelector: selectorFor('slhSetParams256f'),
};
