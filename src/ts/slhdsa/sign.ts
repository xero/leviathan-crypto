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
// src/ts/slhdsa/sign.ts
//
// SLH-DSA sign drivers, FIPS 205 §10.2 wrappers around the WASM
// slhSignInternal entry point (FIPS 205 §9.2 Algorithm 19).
//
// Two drivers:
//   • slhSignInternalTs, writes (sk ‖ M' ‖ opt_rand) into INPUT, runs
//     slhSignInternal, copies sig out of OUT, wipes INPUT scratch and
//     WASM buffers in finally. M' here is the already-domain-separated
//     bytes (constructMPrimePure for pure mode, constructMPrimeHash for
//     HashSLH-DSA mode), produced by the caller.
//   • signWithPrehash, builds the HashSLH-DSA M' from (digest, oid(ph),
//     ctx) and forwards to slhSignInternalTs. Mirrors
//     src/ts/mldsa/sign.ts:signWithPrehash.
//
// Buffer hygiene:
//   - INPUT region zeroed before return (lib wipe; sk + M' + opt_rand all
//     land there). slhdsa's WASM-side wipeBuffers() handles OUT / STATE /
//     SCRATCH but NOT INPUT (see src/asm/slhdsa/buffers.ts comment).
//   - PH_M and M' are lib-allocated TS-side buffers; wiped in finally.
//   - Lib does NOT wipe caller's sk / msg / ctx / digest / opt_rand.

import type { SlhDsaExports } from './types.js';
import type { SlhDsaParams } from './params.js';
import { wipe } from '../utils.js';
import { type PreHashAlgorithm, constructMPrimeHash } from './prehash.js';

/**
 * Drive slhSignInternal with caller-built M' bytes plus opt_rand.
 *
 * Layout written into INPUT (per src/asm/slhdsa/slh.ts §slhSignInternal):
 *   INPUT = sk (4n) ‖ M' (msgLen) ‖ opt_rand (n)
 *
 * `sk` must be exactly `params.skBytes` bytes; `optRand` must be exactly
 * `params.n` bytes. The caller is responsible for those length contracts
 * (the public surface validates before this driver runs).
 *
 * Returns a fresh `sigBytes`-long Uint8Array sliced out of OUT. The
 * finally block wipes the INPUT region (which held the secret sk and
 * potentially-secret opt_rand) and calls `wipeBuffers()` on the WASM
 * module to zero OUT, STATE, SCRATCH.
 */
export function slhSignInternalTs(
	x:       SlhDsaExports,
	params:  SlhDsaParams,
	sk:      Uint8Array,
	MPrime:  Uint8Array,
	optRand: Uint8Array,
): Uint8Array {
	const inOff  = x.getInputOffset();
	const outOff = x.getOutOffset();
	const skLen  = params.skBytes;
	const nLen   = params.n;
	const msgLen = MPrime.length;
	const inputTotal = skLen + msgLen + nLen;

	const mem = new Uint8Array(x.memory.buffer);
	try {
		// Bind active parameter set into the WASM PARAMS slot. WASM dimension
		// lookups (slhK, slhA, slhD, slhHPrime) all read from PARAMS, so this
		// must precede slhSignInternal.
		params.wasmSelector();

		mem.set(sk,      inOff);
		mem.set(MPrime,  inOff + skLen);
		mem.set(optRand, inOff + skLen + msgLen);

		x.slhSignInternal(msgLen);

		return mem.slice(outOff, outOff + params.sigBytes);
	} finally {
		// INPUT held sk (secret) + M' (caller input, includes ctx + message)
		// + opt_rand (sensitive: PK.seed in det mode, fresh randomness in
		// hedged mode, caller-owned in derand mode). The lib wipes its own
		// staging copy unconditionally so a later op cannot read these bytes.
		mem.fill(0, inOff, inOff + inputTotal);
		// OUT / STATE / SCRATCH all held secret-derived intermediates.
		x.wipeBuffers();
	}
}

/**
 * HashSLH-DSA sign, post-prehash. FIPS 205 §10.2.2 Algorithm 23 lines
 * 18-25. Builds M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(algo) ‖ prehash and drives
 * Sign_internal with the caller-supplied opt_rand.
 *
 * The caller owns `prehash` (it may be a slice of WASM memory, a
 * caller-controlled digest, or an internally-computed PH_M); this helper
 * never wipes it. The caller also owns `optRand` (hedged: caller wipes a
 * freshly-generated value; deterministic: optRand = PK.seed slice, no
 * separate wipe; derand: caller-supplied per FIPS 205 §3.4 contract).
 *
 * The 12 approved pre-hash functions (`algo`) and their OIDs are FIPS 205
 * §10.2.2's catalog (matches FIPS 204 §5.4.1 byte-for-byte). Domain-sep
 * byte 0x01 inside the M' construction separates HashSLH-DSA signatures
 * from pure-SLH-DSA signatures on the same key per the §10.2 narrative.
 *
 * signWithPrehash is duplicated from `src/ts/mldsa/sign.ts:signWithPrehash`;
 * extraction is deferred until a third consumer materialises.
 */
export function signWithPrehash(
	x:       SlhDsaExports,
	params:  SlhDsaParams,
	sk:      Uint8Array,
	prehash: Uint8Array,
	algo:    PreHashAlgorithm,
	ctx:     Uint8Array,
	optRand: Uint8Array,
): Uint8Array {
	const MPrime = constructMPrimeHash(prehash, algo, ctx);
	try {
		return slhSignInternalTs(x, params, sk, MPrime, optRand);
	} finally {
		wipe(MPrime);
	}
}
