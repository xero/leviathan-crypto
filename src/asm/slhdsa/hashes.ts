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
// src/asm/slhdsa/hashes.ts
//
// FIPS 205 §11.2 SHAKE-family hash function instantiation.
// Phase 2 ships SHAKE only; the SHA-2 family from §11.2 Table 5 is out of
// scope (sig-phase2.md §3, AGENTS.md §4).
//
// Tweakable hash (§11.2 Table 4):
//   F(PK.seed, ADRS, M1)        = SHAKE256(PK.seed || ADRS || M1, 8n)
//   H(PK.seed, ADRS, M2)        = SHAKE256(PK.seed || ADRS || M2, 8n)
//   T_ℓ(PK.seed, ADRS, M)       = SHAKE256(PK.seed || ADRS || M,  8n)
//   PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
//
// F / H / T_ℓ / PRF collapse into one internal `tweakableHash` routine: the
// input pattern is PK.seed (n bytes) || ADRS (32 bytes) || variable-length
// tail. slhdsa-c's `slh_h` uses the same factoring. PRF is the same shape
// with SK.seed (n bytes) as the tail. Callers pick the wrapper that matches
// the spec name they're citing.
//
// Message-digest functions (§11.2 Table 4):
//   PRFmsg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n)
//   Hmsg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m)
//
// Output lengths come from the active parameter set's PARAMS slot (n from
// PARAMS_N_OFF, m from PARAMS_M_OFF; populated by slhSetParams{128f,192f,
// 256f}). Per FIPS 205 §11.1 Table 2: n=16/24/32 for 128f/192f/256f;
// m=30/39/49 same param-set order.

import {
	getParamN, getParamM,
} from './buffers';
import {
	shake256Init, keccakAbsorbAt, keccakSqueezeTo,
} from './keccak';
import { ADRS_BYTES } from './address';

// ── tweakableHash ──────────────────────────────────────────────────────────
// Internal core for F / H / T_ℓ / PRF. Caller picks the wrapper that matches
// the spec name they're calling from; the bytes hashed are identical.
//
// FIPS 205 §11.2 Table 4. Output size: n bytes (read from PARAMS_N_OFF).

function tweakableHash(
	outPtr:    i32,
	pkSeedPtr: i32,
	adrsPtr:   i32,
	tailPtr:   i32,
	tailLen:   i32,
): void {
	const n = getParamN();
	shake256Init();
	keccakAbsorbAt(pkSeedPtr, n);
	keccakAbsorbAt(adrsPtr,   ADRS_BYTES);
	keccakAbsorbAt(tailPtr,   tailLen);
	keccakSqueezeTo(outPtr, n);
}

/** FIPS 205 §11.2 Table 4. F : (PK.seed, ADRS, M1) → n bytes.
 *  M1 is n bytes in §5 Algorithm 1 (the WOTS+ chain input). */
export function slhHashF(outPtr: i32, pkSeedPtr: i32, adrsPtr: i32, m1Ptr: i32): void {
	tweakableHash(outPtr, pkSeedPtr, adrsPtr, m1Ptr, getParamN());
}

/** FIPS 205 §11.2 Table 4. H : (PK.seed, ADRS, M2) → n bytes.
 *  M2 is 2·n bytes in §6 Algorithm 7 (XMSS internal-node compression). */
export function slhHashH(outPtr: i32, pkSeedPtr: i32, adrsPtr: i32, m2Ptr: i32): void {
	tweakableHash(outPtr, pkSeedPtr, adrsPtr, m2Ptr, getParamN() << 1);
}

/** FIPS 205 §11.2 Table 4. T_ℓ : (PK.seed, ADRS, M) → n bytes.
 *  Variable-length tail (ℓ·n bytes); caller passes the length explicitly. */
export function slhHashTl(
	outPtr: i32, pkSeedPtr: i32, adrsPtr: i32, mPtr: i32, mLen: i32,
): void {
	tweakableHash(outPtr, pkSeedPtr, adrsPtr, mPtr, mLen);
}

/** FIPS 205 §11.2 Table 4. PRF : (PK.seed, SK.seed, ADRS) → n bytes.
 *  Note the §11.2 byte order: PK.seed || ADRS || SK.seed, not the argument
 *  order in the function header. The wrapper preserves that hash order. */
export function slhPRF(outPtr: i32, pkSeedPtr: i32, skSeedPtr: i32, adrsPtr: i32): void {
	tweakableHash(outPtr, pkSeedPtr, adrsPtr, skSeedPtr, getParamN());
}

/** FIPS 205 §11.2 Table 4. PRFmsg : (SK.prf, opt_rand, M) → n bytes.
 *  Used by slh_sign (§10.1 Algorithm 18 line 5) to derive the randomizer R. */
export function slhPRFmsg(
	outPtr: i32, prfPtr: i32, optRandPtr: i32, mPtr: i32, mLen: i32,
): void {
	const n = getParamN();
	shake256Init();
	keccakAbsorbAt(prfPtr,     n);
	keccakAbsorbAt(optRandPtr, n);
	keccakAbsorbAt(mPtr,       mLen);
	keccakSqueezeTo(outPtr, n);
}

/** FIPS 205 §11.2 Table 4. Hmsg : (R, PK.seed, PK.root, M) → m bytes.
 *  Output length is `m` per FIPS 205 §11.1 Table 2 (30/39/49 for 128f/192f/
 *  256f), NOT `n`. Used by slh_sign / slh_verify to compute the digest that
 *  drives FORS+hypertree (§10.1 Algorithm 18 line 6 / Algorithm 20 line 9). */
export function slhHmsg(
	outPtr: i32, rPtr: i32, pkSeedPtr: i32, pkRootPtr: i32, mPtr: i32, mLen: i32,
): void {
	const n = getParamN();
	const m = getParamM();
	shake256Init();
	keccakAbsorbAt(rPtr,      n);
	keccakAbsorbAt(pkSeedPtr, n);
	keccakAbsorbAt(pkRootPtr, n);
	keccakAbsorbAt(mPtr,      mLen);
	keccakSqueezeTo(outPtr, m);
}

// ── Direct SHAKE access for substrate gate tests ───────────────────────────
// `slhShake256` is a thin pointer-arg wrapper around SHAKE256 (no PK.seed
// or ADRS), kept around for the substrate gate test in
// test/unit/slhdsa/slhdsa-hashes.test.ts. Production callers should use the
// §11.2 hash family wrappers above.

export function slhShake256(outPtr: i32, outLen: i32, inPtr: i32, inLen: i32): void {
	shake256Init();
	keccakAbsorbAt(inPtr, inLen);
	keccakSqueezeTo(outPtr, outLen);
}
