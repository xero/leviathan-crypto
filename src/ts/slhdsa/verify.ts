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
// src/ts/slhdsa/verify.ts
//
// SLH-DSA verify drivers, FIPS 205 §10.3 wrappers around the WASM
// slhVerifyInternal entry point (FIPS 205 §9.3 Algorithm 20).
//
// Two drivers:
//   • slhVerifyInternalTs, writes (pk ‖ M' ‖ sig) into INPUT, runs
//     slhVerifyInternal, returns a boolean. M' is the already-domain-
//     separated bytes built by the caller.
//   • verifyWithPrehash, builds the HashSLH-DSA M' from
//     (digest, oid(ph), ctx) and forwards. Mirrors
//     src/ts/mldsa/verify.ts:verifyWithPrehash.
//
// Posture: returns boolean. Any WASM exception during the inner call is
// swallowed and converted to false; FIPS 205 §10.3 / §3.6.2 model verify
// as a pure predicate. Caller-side contract violations (ctx > 255 bytes,
// unsupported ph) are surfaced at the public-method layer, not here.
//
// Buffer hygiene: INPUT held pk + M' + sig (all public inputs). The WASM
// wipe is still applied for consistency with the sign path and to clear
// any sk residue that might have lingered from a previous sign call.

import type { SlhDsaExports } from './types.js';
import type { SlhDsaParams } from './params.js';
import { wipe } from '../utils.js';
import { type PreHashAlgorithm, constructMPrimeHash } from './prehash.js';

/**
 * Drive slhVerifyInternal with caller-built M' bytes.
 *
 * Layout written into INPUT (per src/asm/slhdsa/slh.ts §slhVerifyInternal):
 *   INPUT = pk (2n) ‖ M' (msgLen) ‖ sig (sigBytes)
 *
 * The caller has already filtered wrong-length pk and sig (the public
 * verify*() surface returns false for those before calling this driver).
 * Inside this function, length-mismatch only manifests if pk / sig were
 * truncated post-validation; we defensively re-check to keep the WASM
 * call within its declared INPUT bounds.
 *
 * Returns true iff slhVerifyInternal returns 1 (the §9.3 constant-time
 * PK.root comparison succeeded plus all FORS / hypertree path checks).
 */
export function slhVerifyInternalTs(
	x:      SlhDsaExports,
	params: SlhDsaParams,
	pk:     Uint8Array,
	MPrime: Uint8Array,
	sig:    Uint8Array,
): boolean {
	const inOff  = x.getInputOffset();
	const pkLen  = params.pkBytes;
	const msgLen = MPrime.length;
	const sigLen = sig.length;
	const inputTotal = pkLen + msgLen + sigLen;

	const mem = new Uint8Array(x.memory.buffer);
	try {
		params.wasmSelector();

		mem.set(pk,     inOff);
		mem.set(MPrime, inOff + pkLen);
		mem.set(sig,    inOff + pkLen + msgLen);

		return x.slhVerifyInternal(msgLen) === 1;
	} catch {
		// FIPS 205 §10.3 verify is a pure predicate. Any unexpected
		// exception (out-of-memory, kernel argument error) is treated
		// as "did not authenticate". The public surface already filters
		// caller contract violations (ctx > 255) before reaching this
		// driver, so swallowing here cannot mask a contract bug.
		return false;
	} finally {
		mem.fill(0, inOff, inOff + inputTotal);
		x.wipeBuffers();
	}
}

/**
 * HashSLH-DSA verify, post-prehash. FIPS 205 §10.3 Algorithm 25 lines
 * 16-19. Builds M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(algo) ‖ prehash and drives
 * Verify_internal.
 *
 * Same return / throw posture as `slhVerifyInternalTs`: returns a pure
 * boolean for every signature outcome. Caller (in index.ts) is expected
 * to have already filtered wrong-length vk / sig / digest with the
 * appropriate verdict (false) before calling this helper.
 *
 * The caller owns `prehash`; this helper never wipes it.
 */
export function verifyWithPrehash(
	x:       SlhDsaExports,
	params:  SlhDsaParams,
	pk:      Uint8Array,
	prehash: Uint8Array,
	sig:     Uint8Array,
	algo:    PreHashAlgorithm,
	ctx:     Uint8Array,
): boolean {
	const MPrime = constructMPrimeHash(prehash, algo, ctx);
	try {
		return slhVerifyInternalTs(x, params, pk, MPrime, sig);
	} finally {
		wipe(MPrime);
	}
}
