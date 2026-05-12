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
// src/ts/mldsa/verify.ts
//
// FIPS 204 §6.3 Algorithm 8, ML-DSA.Verify_internal.
//
// Verify is a pure boolean predicate: returns true iff the signature
// passes the FIPS 204 norm check (‖z‖∞ < γ₁ − β) AND the constant-time
// comparison of the recomputed c̃' against the σ-supplied c̃. There is
// no analog to the FO transform's implicit-rejection branch (Kyber's
// `return pseudorandom shared secret on failure`); ML-DSA verification
// is binary.
//
// SUF-CMA-critical preconditions enforced here:
//   1. Length check on pk and σ, caller (verify() in index.ts) returns
//      false on mismatch BEFORE invoking this internal function, per
//      FIPS 204 §3.6.2.
//   2. HintBitUnpack-malformed → false (FIPS 204 §D.3 / Algorithm 21
//      lines 4, 9, 17). The kernel returns -1; we propagate as false.
//   3. Constant-time c̃ ↔ c̃' comparison via leviathan-crypto's
//      `constantTimeEqual` (SIMD WASM XOR-accumulate, no early-exit).
//
// Slot allocation:
//   POLYVEC_SLOT_0   t₁ → t₁·2^d (regular) → t̂₁·2^d (regular) → tomont
//   POLYVEC_SLOT_1   z (time-domain) → ẑ (regular) → ẑ tomont
//   POLYVEC_SLOT_2   h (hint polyvec; alive through use_hint)
//   POLYVEC_SLOT_3   Â · ẑ → w'_approx → w'₁ (in place via use_hint aliasing)
//   POLYVEC_SLOT_4   ĉ · t̂₁·2^d intermediate
//   POLY_SLOT_0      signs (8 bytes, sample_in_ball signsOff)
//   POLY_SLOT_1      c → ĉ
//   POLY_SLOT_7      reserved scratch for polyvec_pointwise_acc_montgomery

import type { MlDsaExports, Sha3Exports } from './types.js';
import type { MlDsaParams } from './params.js';
import { constantTimeEqual, wipe } from '../utils.js';
import { sha3Absorb, shake256Hash, shake256HashConcat } from './sha3-helpers.js';
import { expandA } from './expand.js';
import { type PreHashAlgorithm, getOid } from './hashvariant.js';
import { constructMPrimeHash } from './format.js';

const POLY_BYTES    = 1024;
const D             = 13;
const Q             = 8380417;
const SHAKE256_RATE = 136;

function bitlen(n: number): number {
	let b = 0; let x = n;
	while (x > 0) {
		b++; x >>>= 1;
	}
	return b;
}

/**
 * ML-DSA.Verify_internal, FIPS 204 Algorithm 8.
 *
 * Inputs (all caller-validated for length by the public verify() method):
 *   vk    , encoded verification key (pkBytes)
 *   MPrime, domain-separated message bytes
 *   sig   , encoded signature (sigBytes)
 *
 * Returns: boolean.
 *   true , signature authenticates the message under vk.
 *   false, wrong sig, malformed hint encoding, or norm check failure.
 */
export function mldsaVerifyInternal(
	mx: MlDsaExports,
	sx: Sha3Exports,
	params: MlDsaParams,
	vk: Uint8Array,
	MPrime: Uint8Array,
	sig: Uint8Array,
): boolean {
	const { k, l, tau, lambda, gamma1, gamma2, beta, omega } = params;
	const lambdaOver4  = lambda >>> 2;                      // 32 / 48 / 64
	const c            = 1 + bitlen(gamma1 - 1);            // 18 or 20
	const zPolyBytes   = 32 * c;
	const t1Bitlen     = bitlen(Q - 1) - D;                 // 23 − 13 = 10
	const t1PolyBytes  = (256 * t1Bitlen) >> 3;             // 320
	const w1Bitlen     = bitlen(((Q - 1) / (2 * gamma2)) - 1);
	const w1PolyBytes  = (256 * w1Bitlen) >> 3;
	const w1TotalBytes = k * w1PolyBytes;
	const t1ScalarShift = D;                                // multiply t₁ by 2^d in time domain

	// ── WASM offsets ─────────────────────────────────────────────────────
	const matOff   = mx.getMatrixSlot();
	const slot0    = mx.getPolyvecSlot0();   // t₁ then t̂₁·2^d (tomont)
	const slot1    = mx.getPolyvecSlot1();   // z then ẑ (tomont)
	const slot2    = mx.getPolyvecSlot2();   // h
	const slot3    = mx.getPolyvecSlot3();   // Â·ẑ → w'_approx → w'₁
	const slot4    = mx.getPolyvecSlot4();   // ĉ·t̂₁·2^d
	const polySlotBase = mx.getPolySlotBase();
	const polySlot0 = mx.getPolySlot0();     // signs
	const polySlot1 = mx.getPolySlot1();     // c → ĉ
	const xofOff   = mx.getXofPrfOffset();

	const mlMem    = new Uint8Array(mx.memory.buffer);
	const sha3Mem  = new Uint8Array(sx.memory.buffer);
	const sha3OutOff = sx.getOutOffset();

	// TS-side sensitive buffers, wipe in finally even though MPrime, c̃,
	// μ are public-derivable (vk, sig, M are public). Keep the surface
	// uniform with sign so future audits don't have to special-case verify.
	let mu:        Uint8Array | undefined;
	let tr:        Uint8Array | undefined;
	let cTilde:    Uint8Array | undefined;
	let cTildeNew: Uint8Array | undefined;
	let w1Bytes:   Uint8Array | undefined;

	try {
		// ── Step 1: pkDecode (FIPS 204 §7.2 Algorithm 23) ────────────────
		const rho = vk.subarray(0, 32);
		for (let r = 0; r < k; r++) {
			const srcOff = 32 + r * t1PolyBytes;
			mlMem.set(vk.subarray(srcOff, srcOff + t1PolyBytes), xofOff);
			mx.simple_bit_unpack(slot0 + r * POLY_BYTES, xofOff, t1Bitlen);
		}

		// ── Step 2: sigDecode (FIPS 204 §7.2 Algorithm 27) ────────────────
		// σ = c̃ ‖ z_packed ‖ h_packed
		cTilde = sig.slice(0, lambdaOver4);
		let off = lambdaOver4;
		for (let r = 0; r < l; r++) {
			mlMem.set(sig.subarray(off, off + zPolyBytes), xofOff);
			mx.bit_unpack(slot1 + r * POLY_BYTES, xofOff, gamma1 - 1, gamma1);
			off += zPolyBytes;
		}
		// HintBitUnpack, FIPS 204 Algorithm 21. Returns -1 on any of the
		// three malformed-input checks (lines 4, 9, 17). Propagate as
		// false: this is the SUF-CMA fix from FIPS 204 §D.3.
		mlMem.set(sig.subarray(off, off + omega + k), xofOff);
		if (mx.hint_bit_unpack(slot2, xofOff, k, omega) < 0) return false;

		// ── Step (Alg 8 line 4) Â ← ExpandA(ρ) ─────────────────────────
		expandA(mx, sx, params, rho, matOff);

		// ── Step (Alg 8 line 5) tr ← H(BytesToBits(pk), 64) ──────────────
		tr = shake256Hash(sx, vk, 64);

		// ── Step (Alg 8 line 6) μ ← H(BytesToBits(tr) ‖ M', 64) ──────────
		mu = shake256HashConcat(sx, [tr, MPrime], 64);

		// ── Step (Alg 8 line 7) c ← SampleInBall(c̃) ───────────────────
		mlMem.fill(0, polySlot1, polySlot1 + POLY_BYTES);
		sx.shake256Init();
		sha3Absorb(sx, cTilde);
		sx.shakePad();
		sx.shakeSqueezeBlock();
		mlMem.set(sha3Mem.subarray(sha3OutOff,     sha3OutOff +   8), polySlot0);
		mlMem.set(sha3Mem.subarray(sha3OutOff + 8, sha3OutOff + SHAKE256_RATE), xofOff);
		let sampleI = mx.sample_in_ball(polySlot1, polySlot0, xofOff, SHAKE256_RATE - 8, tau, 256 - tau);
		while (sampleI < 256) {
			sx.shakeSqueezeBlock();
			mlMem.set(sha3Mem.subarray(sha3OutOff, sha3OutOff + SHAKE256_RATE), xofOff);
			sampleI = mx.sample_in_ball(polySlot1, polySlot0, xofOff, SHAKE256_RATE, tau, sampleI);
		}

		// ── Step (Alg 8 line 8) w'_approx ← NTT⁻¹(Â ∘ NTT(z) − NTT(c) ∘ NTT(t₁·2^d))
		// (a) NTT z, then tomont so the matrix kernel's R⁻¹ leaves regular result.
		mx.polyvec_ntt(slot1, l);
		mx.polyvec_tomont(slot1, l);
		// (b) Compute t₁·2^d in time domain. t₁[i] ∈ [0, 1023]; t₁[i]·2^13
		//     ≤ 1023 · 8192 = 8,380,416 < q = 8,380,417, so no mod needed
		//     and no overflow. Use Int32Array view over the slot region.
		const t1View = new Int32Array(mlMem.buffer, slot0, k * 256);
		for (let i = 0; i < k * 256; i++) t1View[i] <<= t1ScalarShift;
		mx.polyvec_ntt(slot0, k);
		mx.polyvec_tomont(slot0, k);
		// (c) ĉ ← NTT(c), single polynomial in place.
		mx.ntt(polySlot1);
		// (d) Â · ẑ → slot3 (regular form in NTT domain)
		mx.polyvec_matrix_pointwise_montgomery(slot3, matOff, slot1, k, l);
		// (e) ĉ · t̂₁·2^d → slot4, TS-side per-poly loop; ĉ regular, t̂₁·2^d
		//     tomont so the kernel's R⁻¹ leaves the result regular.
		for (let r = 0; r < k; r++) {
			mx.poly_pointwise_montgomery(
				slot4 + r * POLY_BYTES,
				polySlot1,
				slot0 + r * POLY_BYTES,
			);
		}
		// (f) w'_approx (NTT domain) ← Â·ẑ − ĉ·t̂₁·2^d
		mx.polyvec_sub(slot3, slot3, slot4, k);
		mx.polyvec_invntt(slot3, k);
		mx.polyvec_caddq(slot3, k);                              // canonical for use_hint

		// ── Step (Alg 8 line 9) w'₁ ← UseHint(h, w'_approx) ─────────────
		// use_hint is alias-safe between r and a (read both before write
		// per coefficient), so overwrite w'_approx with w'₁ in slot3.
		mx.polyvec_use_hint(slot3, slot2, slot3, k, gamma2);

		// ── Step (Alg 8 line 10) c̃' ← H(μ ‖ w₁Encode(w'₁), λ/4) ─────────
		for (let r = 0; r < k; r++) {
			mx.simple_bit_pack(xofOff + r * w1PolyBytes, slot3 + r * POLY_BYTES, w1Bitlen);
		}
		w1Bytes = mlMem.slice(xofOff, xofOff + w1TotalBytes);
		cTildeNew = shake256HashConcat(sx, [mu, w1Bytes], lambdaOver4);

		// ── Step (Alg 8 line 11) return ‖z‖∞ < γ₁ − β AND c̃ = c̃' ───────
		// The sigDecode bit_unpack output is in centered residues
		// [-(γ₁-1), γ₁], chknorm consumes that form directly without
		// polyvec_reduce. We must check norm AFTER the NTT path because
		// our slot1 holds NTT-domain ẑ now. Re-decode z into a fresh slot
		// for the norm check.
		//
		// Re-decode is cheap (bit_unpack is a single-pass kernel). Use
		// slot4 (already overwritten above) as the destination.
		off = lambdaOver4;
		for (let r = 0; r < l; r++) {
			mlMem.set(sig.subarray(off, off + zPolyBytes), xofOff);
			mx.bit_unpack(slot4 + r * POLY_BYTES, xofOff, gamma1 - 1, gamma1);
			off += zPolyBytes;
		}
		const normFail = mx.polyvec_chknorm(slot4, gamma1 - beta, l);

		// Constant-time comparison via the SIMD ct WASM module. We
		// evaluate normFail and the c̃ comparison both before returning,
		// so that an attacker who can observe timing cannot distinguish
		// "norm failed" from "c̃ mismatch", both run to completion before
		// the boolean reduction. (The c̃ != c̃' branch is taken regardless
		// of normFail; both signals are public-input-derived so this is
		// not a CT requirement, but it preserves the symmetry.)
		const cTildeEq = constantTimeEqual(cTilde, cTildeNew);
		return normFail === 0 && cTildeEq;
	} catch {
		// FIPS 204 verify is a pure predicate. Any unexpected exception
		// (out-of-memory, kernel argument errors) is treated as "did not
		// authenticate", never propagate. The SUF-CMA risk of swallowing
		// is bounded by validate*.ts callers: the ones that throw on
		// caller contract violations (oversize ctx) run BEFORE this
		// function executes.
		return false;
	} finally {
		// Wipe TS-side scratch.
		if (mu)        wipe(mu);
		if (tr)        wipe(tr);
		if (cTilde)    wipe(cTilde);
		if (cTildeNew) wipe(cTildeNew);
		if (w1Bytes)   wipe(w1Bytes);

		// Wipe WASM scratch, verify operates on public inputs (vk, sig,
		// M, ctx all public; t₁, ẑ, w'_approx, h all public-derivable),
		// but the discipline mirrors sign for review consistency. Cheap.
		mlMem.fill(0, mx.getPolyvecSlotBase(), mx.getPolyvecSlotBase() + 5 * mx.getPolyvecSlotSize());
		mlMem.fill(0, polySlotBase, polySlotBase + 8 * POLY_BYTES);
		mlMem.fill(0, xofOff, xofOff + 8192);

		// SHA3 module: wipe state across op boundary, same convention as
		// keygen / sign. Holds vk (public), tr (public), μ (public-derivable).
		sx.wipeBuffers();
	}
}

/**
 * HashML-DSA verify, post-prehash. FIPS 204 §5.4 Algorithm 5 lines 17-19.
 * Builds M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(algo) ‖ prehash and drives
 * Verify_internal.
 *
 * Same return / throw posture as `mldsaVerifyInternal`: returns a pure
 * boolean for every signature outcome. Caller (in index.ts) is expected
 * to have already filtered wrong-length vk / sig / digest with the
 * appropriate verdict (false) before calling this helper.
 *
 * The caller owns `prehash`; this helper never wipes it.
 */
export function verifyWithPrehash(
	mx:      MlDsaExports,
	sx:      Sha3Exports,
	params:  MlDsaParams,
	vk:      Uint8Array,
	prehash: Uint8Array,
	sig:     Uint8Array,
	algo:    PreHashAlgorithm,
	ctx:     Uint8Array,
): boolean {
	const oid    = getOid(algo);
	const MPrime = constructMPrimeHash(ctx, oid, prehash);
	try {
		return mldsaVerifyInternal(mx, sx, params, vk, MPrime, sig);
	} finally {
		wipe(MPrime);
	}
}
