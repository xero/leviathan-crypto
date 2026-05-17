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
// src/asm/p256/scalar_mult.ts
//
// Variable-base and fixed-base scalar multiplication.
// Constant-time, double-and-add-always over the RCB complete-addition
// substrate.
//
// pointMul(scalar, P, out): [scalar]P for arbitrary P.
// pointMulBase(scalar, out): [scalar]G for the SP 800-186 §3.2.1.3
//   basepoint. Currently implemented as pointMul(scalar, G, out); a
//   future revision can replace this with a fixed-base comb table for
//   performance, but the gate test (n*G == identity) is independent
//   of the algorithm choice and will catch any change.
//
// Algorithm: scan the scalar BE byte stream MSB-first, 1 bit at a
// time. For each bit:
//   1. R ← 2 * R              (constant-time pointDouble)
//   2. T ← R + P              (constant-time pointAdd; T is always
//                              computed, regardless of bit value)
//   3. R ← bit ? T : R        (mask-driven select over all 96 bytes
//                              of the projective point coordinates)
//
// No branch on secret bits. The 256-bit loop runs 256 pointDouble
// and 256 pointAdd calls; both formulas are RCB complete additions
// (handle identity, P = Q, P = -Q internally), so the substrate
// never falls into a special-case path.
//
// Posture: AGENTS.md §"Constant-time operations" prohibits the leaky
// `if bit: R = R + P` shape; this implementation uses the mask-select
// form throughout.

import {
	POINT_TMP, POINT_TMP_STRIDE,
} from './buffers'

import {
	pointZero, pointBasepoint, pointAdd, pointDouble,
} from './point'

// ── Constant-time point select ─────────────────────────────────────────────
//
// out = cond ? a : b. cond must be 0 or 1. Operates over the full
// 96-byte projective-coordinate representation. mask-driven byte-wise
// OR-and-NAND (u32 lane).

@inline
function pointCondSelect(out: i32, a: i32, b: i32, cond: u32): void {
	const mask: u32 = ((-(cond as i32)) as u32)
	for (let k: i32 = 0; k < 96; k += 4) {
		const va: u32 = load<u32>(a + k)
		const vb: u32 = load<u32>(b + k)
		store<u32>(out + k, (va & mask) | (vb & ~mask))
	}
}

// ── pointMul: variable-base scalar multiplication ──────────────────────────

/**
 * out = [scalar]P. scalar is 32 bytes BIG-endian per FIPS 186-5 §6;
 * out is the resulting projective point (X : Y : Z) at offset out
 * (96 bytes).
 *
 * Slot allocation in POINT_TMP:
 *   slot 0: accumulator R
 *   slot 1: candidate T = R + P
 *   slot 2..5: free for caller use
 *   slot 6: reserved by point.ts pointSub
 *   slot 7: reserved by point.ts internal staging (X_OUT/Y_OUT/Z_OUT)
 *
 * Caller's `p` must NOT alias POINT_TMP slot 0, 1, or 7.
 */
export function pointMul(scalarBE: i32, p: i32, out: i32): void {
	const R: i32 = POINT_TMP + 0 * POINT_TMP_STRIDE
	const T: i32 = POINT_TMP + 1 * POINT_TMP_STRIDE

	pointZero(R)

	for (let byteIdx: i32 = 0; byteIdx < 32; byteIdx++) {
		const byte: u32 = load<u8>(scalarBE + byteIdx) as u32
		for (let bitIdx: i32 = 7; bitIdx >= 0; bitIdx--) {
			pointDouble(R, R)
			pointAdd(T, R, p)
			const bit: u32 = (byte >> (bitIdx as u32)) & 1
			pointCondSelect(R, T, R, bit)
		}
	}

	memory.copy(out, R, 96)
}

// ── pointMulBase: fixed-base scalar multiplication ─────────────────────────
//
// Currently a thin wrapper over pointMul with G materialised at call
// time. Future optimization: precomputed comb table on G (4-bit
// windows over multiples of G, 2^16 G, 2^32 G, ...) for sign
// performance. The gate test exercises [n]G = identity (the curve-
// order check) which is independent of the algorithm shape and will
// catch any change.

/**
 * out = [scalar]G where G is the SP 800-186 §3.2.1.3 P-256 basepoint.
 */
export function pointMulBase(scalarBE: i32, out: i32): void {
	// Materialise G at slot 2 of POINT_TMP (slots 0 and 1 are used by
	// pointMul as accumulator R and candidate T).
	const Gslot: i32 = POINT_TMP + 2 * POINT_TMP_STRIDE
	pointBasepoint(Gslot)
	pointMul(scalarBE, Gslot, out)
}
