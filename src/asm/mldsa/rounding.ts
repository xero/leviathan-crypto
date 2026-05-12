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
// src/asm/mldsa/rounding.ts
//
// ML-DSA, high-/low-order rounding kernels.
// FIPS 204 §7.4 Algorithms 35-40 (Power2Round, Decompose, HighBits, LowBits,
// MakeHint, UseHint).
//
// All kernels expect input in canonical [0, q-1] form. Phase-4 wrappers must
// call poly_caddq before invoking any function from this file.
//
// CT posture: Decompose's special-case branch (line 3 of Alg 36) is data-
// dependent on the input coefficient. Inputs to Decompose come from secret-
// derived intermediate values (w, ct0). The leak here is the same statistical
// signal already produced by the signing rejection-restart loop, the next
// iteration of Alg 7 depends on these values, and the iteration count is
// observable through SHAKE differences. Documented per FIPS 204 §3.6.3.
// MakeHint composes two HighBits calls per coefficient; same posture applies.
// Power2Round is fully branch-free.

import { Q, D, N } from './params';

// ── Constants derived from D (= 13 across all parameter sets) ───────────────

/** 2^D, divisor for low-bit drop. */
const TWO_D: i32 = 1 << D;          // 8192
/** 2^(D-1), half-divisor for centered split. */
const HALF_TWO_D: i32 = 1 << (D - 1); // 4096
/** Mask for the low D bits. */
const LOW_D_MASK: i32 = TWO_D - 1;  // 0x1FFF

// ── power2round, FIPS 204 Algorithm 35 ─────────────────────────────────────
// Splits each coefficient r ∈ [0, q-1] into (r1, r0) such that
// r ≡ r1 · 2^d + r0 (mod q), with r0 ∈ (-2^(d-1), 2^(d-1)] and
// r1 ∈ [0, ⌈(q-1)/2^d⌉ - 1] = [0, 1023].
//
// Branch-free centered split:
//   r0_unsigned = r & (2^d − 1)         in [0, 2^d − 1]
//   if r0_unsigned > 2^(d-1) → subtract 2^d to land in (−2^(d-1), 0)
//   r1 = (r − r0) / 2^d                 (exact division by 2^d)
export function power2round(r1Off: i32, r0Off: i32, aOff: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		const r:  i32 = load<i32>(aOff + i * 4);
		const u:  i32 = r & LOW_D_MASK;                 // [0, 2^d − 1]
		// mask = -1 iff u > 2^(d-1), else 0.
		const mask: i32 = (HALF_TWO_D - u) >> 31;
		const r0: i32 = u - (TWO_D & mask);             // (−2^(d-1), 2^(d-1)]
		const r1: i32 = (r - r0) >> D;                  // exact division by 2^d
		store<i32>(r1Off + i * 4, r1);
		store<i32>(r0Off + i * 4, r0);
	}
}

// ── _decompose_step, single-coefficient Decompose, returns (r1, r0) packed ─
// Returns an i64 with r1 in the low 32 bits (signed) and r0 in the high 32
// bits (signed). Inlined so the caller doesn't pay for a function call; the
// pack/unpack compiles to register moves on the WASM SIMD pipeline.
//
// FIPS 204 Algorithm 36 (one coefficient). Input a ∈ [0, q-1].
@inline
function _decompose_step(a: i32, gamma2: i32): i64 {
	const twoG2: i32 = gamma2 << 1;
	// u = a mod 2γ₂  ∈ [0, 2γ₂ − 1]   (a is in [0, q-1] per caller contract).
	const u: i32 = a - (a / twoG2) * twoG2;
	// Centered: if u > γ₂ → subtract 2γ₂ → (-γ₂, 0]; else u stays in [0, γ₂].
	const mask: i32 = (gamma2 - u) >> 31;
	let r0: i32 = u - (twoG2 & mask);                   // (-γ₂, γ₂]
	let r1: i32 = (a - r0) / twoG2;                     // [0, M]
	// Special case (Alg 36 line 3): if a − r0 = q − 1 then (r1, r0) ← (0, r0 − 1).
	if (a - r0 == Q - 1) {
		r1 = 0;
		r0 -= 1;
	}
	// Pack: r1 in low 32 bits (zero-extended via u32 cast to avoid sign
	// pollution into the upper half), r0 in high 32 bits (sign-preserved).
	return ((<i64>r0) << 32) | (<i64><u32>r1);
}

// ── decompose, FIPS 204 Algorithm 36 (poly-wide) ───────────────────────────
export function decompose(r1Off: i32, r0Off: i32, aOff: i32, gamma2: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		const p: i64 = _decompose_step(load<i32>(aOff + i * 4), gamma2);
		store<i32>(r1Off + i * 4, <i32>p);            // low 32 = r1
		store<i32>(r0Off + i * 4, <i32>(p >> 32));    // high 32 = r0 (arithmetic shift preserves sign)
	}
}

// ── highbits, FIPS 204 Algorithm 37 (poly-wide) ────────────────────────────
export function highbits(rOff: i32, aOff: i32, gamma2: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		store<i32>(rOff + i * 4, <i32>_decompose_step(load<i32>(aOff + i * 4), gamma2));
	}
}

// ── lowbits, FIPS 204 Algorithm 38 (poly-wide) ─────────────────────────────
export function lowbits(rOff: i32, aOff: i32, gamma2: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		store<i32>(rOff + i * 4, <i32>(_decompose_step(load<i32>(aOff + i * 4), gamma2) >> 32));
	}
}

// ── make_hint, FIPS 204 Algorithm 39 (poly-wide) ───────────────────────────
// h[i] = [[ HighBits(r[i]) ≠ HighBits(r[i] + z[i]) ]] where addition is in Z_q.
//
// Both r and z must be in [0, q-1] before this call, Sign_internal ensures
// this by applying poly_caddq to the relevant polyvecs first. The kernel
// performs the modular reduction of (r + z) internally so the second
// HighBits call sees a value in Z_q.
export function make_hint(hOff: i32, zOff: i32, rOff: i32, gamma2: i32): void {
	for (let i: i32 = 0; i < N; i++) {
		const r: i32 = load<i32>(rOff + i * 4);
		const z: i32 = load<i32>(zOff + i * 4);
		// Modular sum in Z_q: r, z ∈ [0, q-1] ⇒ r+z ∈ [0, 2q-2]; one conditional
		// subtract canonicalises the result to [0, q-1].
		let sum: i32 = r + z;
		if (sum >= Q) sum -= Q;
		const r1:  i32 = <i32>_decompose_step(r,   gamma2);   // low 32 of each pack
		const r1z: i32 = <i32>_decompose_step(sum, gamma2);
		store<i32>(hOff + i * 4, r1 == r1z ? 0 : 1);
	}
}

// ── use_hint, FIPS 204 Algorithm 40 (poly-wide) ────────────────────────────
// m = (q − 1) / (2γ₂); for each coefficient:
//   (r1, r0) ← Decompose(r)
//   if h = 1 and r0 > 0 : return (r1 + 1) mod m
//   if h = 1 and r0 ≤ 0 : return (r1 − 1) mod m
//   else                : return r1
//
// Wrap-around: (r1 − 1) mod m = m − 1 when r1 = 0; (r1 + 1) mod m = 0 when
// r1 = m − 1.
export function use_hint(rOff: i32, hOff: i32, aOff: i32, gamma2: i32): void {
	const m: i32 = (Q - 1) / (gamma2 << 1);
	for (let i: i32 = 0; i < N; i++) {
		const a: i32 = load<i32>(aOff + i * 4);
		const h: i32 = load<i32>(hOff + i * 4);
		const p:  i64 = _decompose_step(a, gamma2);
		const r1: i32 = <i32>p;
		const r0: i32 = <i32>(p >> 32);
		let out: i32 = r1;
		if (h == 1) {
			if (r0 > 0) {
				out = r1 + 1;
				if (out == m) out = 0;
			} else {
				out = r1 - 1;
				if (out < 0) out = m - 1;
			}
		}
		store<i32>(rOff + i * 4, out);
	}
}
