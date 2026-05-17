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
// src/asm/mldsa/poly.ts
//
// ML-DSA, scalar polynomial arithmetic in R_q and T_q.
// FIPS 204 §7.6 (AddNTT, MultiplyNTT) and the supporting reduce / freeze / norm
// primitives needed by KeyGen_internal, Sign_internal, Verify_internal.
//
// SIMD versions of the byte-parallel primitives (add, sub, reduce, caddq,
// pointwise) live in poly_simd.ts. The scalar versions here remain available
// as cross-checks and for the path widths SIMD does not cover (poly_freeze,
// poly_chknorm).
//
// CT posture for poly_chknorm: the early-exit branch reveals "some coefficient
// exceeded the bound", which the attacker already learns from the signing
// retry pattern (each restart of Algorithm 7 changes the SHAKE output, so the
// number of iterations is observable through other side channels). The leak is
// statistical and not key-revealing. Documented per FIPS 204 §2.3 (norm
// definition) and §3.6.3 (intermediate-value sensitivity).

import { Q, N } from './params';
import { barrett_reduce, montgomery_reduce } from './reduce';

// ── poly_add, FIPS 204 Algorithm 44 (AddNTT, coefficient-wise) ─────────────
// No reduction. r[i] = a[i] + b[i] in i32.
export function poly_add(rOff: i32, aOff: i32, bOff: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		store<i32>(rOff + i * 4,
			load<i32>(aOff + i * 4) + load<i32>(bOff + i * 4));
	}
}

// ── poly_sub, coefficient-wise subtraction ─────────────────────────────────
// No reduction. r[i] = a[i] - b[i] in i32.
export function poly_sub(rOff: i32, aOff: i32, bOff: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		store<i32>(rOff + i * 4,
			load<i32>(aOff + i * 4) - load<i32>(bOff + i * 4));
	}
}

// ── poly_reduce, apply Barrett (centered) to each coefficient ──────────────
// Each coefficient → mod± q in [-(q-1)/2, (q-1)/2] (FIPS 204 §2.3).
export function poly_reduce(polyOff: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		store<i32>(polyOff + i * 4, barrett_reduce(load<i32>(polyOff + i * 4)));
	}
}

// ── poly_caddq, conditional add q ──────────────────────────────────────────
// Maps any coefficient in [-q+1, q-1] back to [0, q-1] by adding q to negatives.
// Branch-free via sign-bit mask. Used pre-encoding (pkEncode, sigEncode etc.).
export function poly_caddq(polyOff: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		const a: i32 = load<i32>(polyOff + i * 4);
		// (a >> 31) is -1 when a < 0, else 0; AND with q yields q or 0.
		store<i32>(polyOff + i * 4, a + ((a >> 31) & Q));
	}
}

// ── poly_freeze, full canonical-residue reduction ──────────────────────────
// reduce → caddq. After this every coefficient lies in [0, q-1].
export function poly_freeze(polyOff: i32): void {
	poly_reduce(polyOff);
	poly_caddq(polyOff);
}

// ── poly_pointwise_montgomery, FIPS 204 Algorithm 45 (MultiplyNTT) ─────────
// Coefficient-wise c[i] = MontgomeryReduce(a[i] · b[i]) ≡ a[i]·b[i]·2^-32 (mod q).
// The 2^-32 factor matches the Montgomery convention used by the NTT path:
// when one input is in Montgomery form (×2^32), the closing reduce produces
// the regular-form product. The orchestration layer is responsible for tracking
// which factor is in Montgomery form. Output magnitude < 2q (FIPS 204 App. A).
export function poly_pointwise_montgomery(rOff: i32, aOff: i32, bOff: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		const a: i32 = load<i32>(aOff + i * 4);
		const b: i32 = load<i32>(bOff + i * 4);
		store<i32>(rOff + i * 4, montgomery_reduce(<i64>a * <i64>b));
	}
}

// ── poly_tomont, convert each coefficient to Montgomery form ───────────────
// p[i] ← p[i] · R mod q, where R = 2³². Implemented as
//   p[i] ← MontgomeryReduce(p[i] · MONT_R_SQ),  MONT_R_SQ = R² mod q.
//
// MONT_R_SQ derivation: R = 2³² ≡ 4193792 (mod q). R² mod q = 2365951
// (FIPS 204 §2.3 / Appendix A, same constant the Dilithium reference
// names MONTSQ). Verified once via BigInt at the keygen-gate level
// (test/unit/mldsa/mldsa.test.ts) when ACVP keygen vectors round-trip.
//
// Used by keygen: after NTT(s₁), one factor of the matrix-vector
// product needs to be in Montgomery form so that the subsequent
// pointwise_montgomery (which applies an R⁻¹) leaves the regular-form
// result Â·ŝ₁. The tomont scaling collapses with the post-NTT regular-form
// stream into the Montgomery convention expected by the pointwise kernel.
const MONT_R_SQ: i32 = 2365951;

export function poly_tomont(polyOff: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		const a: i32 = load<i32>(polyOff + i * 4);
		store<i32>(polyOff + i * 4, montgomery_reduce(<i64>a * <i64>MONT_R_SQ));
	}
}

// ── poly_chknorm, return 1 iff some |w_i| ≥ bound, else 0 ──────────────────
// Implements the ||w||∞ < bound test of FIPS 204 §2.3 over i32 coefficients
// already reduced to centered residues (mod± q). The early-exit on the first
// over-bound coefficient is data-dependent on input, but the leak is the same
// already-observable rejection-restart pattern, see file header.
//
// Used by the rejection branches at Alg 7 lines 21-25: ||z||∞ < γ1−β,
// ||r0||∞ < γ2−β, ||ct0||∞ < γ2.
export function poly_chknorm(polyOff: i32, bound: i32): i32 {
	for (let i: i32 = 0; i < N; i++) {
		const a: i32 = load<i32>(polyOff + i * 4);
		// |a| via two's-complement: m = a >> 31 sprays sign bit; (a + m) ^ m.
		const m: i32 = a >> 31;
		const abs: i32 = (a + m) ^ m;
		if (abs >= bound) return 1;
	}
	return 0;
}
