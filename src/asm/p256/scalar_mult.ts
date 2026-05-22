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
//   basepoint. Implemented as pointMul(scalar, G, out): the same
//   variable-base double-and-add-always ladder used for arbitrary
//   points. A fixed-base comb table is not used. Comb tables
//   precompute an array indexed by secret scalar bits, which is a
//   lookup table even under constant-time masked-select discipline.
//   The project's architectural commitment (SECURITY.md
//   §Side-channel resistance, docs/architecture.md) is register-only
//   logic with no data-dependent memory access across every
//   primitive. P-256 holds the same line as Serpent, AES, ChaCha20,
//   and the hash family.
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

// ── pointMulDoubleVerify: Strauss-Shamir [u1]G + [u2]Q ─────────────────────
//
// Verify-only double scalar multiplication. Interleaves the two ladders
// of [u1]G and [u2]Q into a single 256-iteration loop: one shared
// doubling per bit position plus a conditional add of one of four
// precomputed combinations {O, Q, G, G+Q} based on the bit pair
// (u1_bit, u2_bit). Replaces the two-ladder + final-add pattern used by
// ecdsaVerify with roughly half the scalar-multiplication work.
//
// NOT constant-time across the (u1_bit, u2_bit) selector. ECDSA verify
// inputs are public on the wire (pk, msgHash, sig) and the call site at
// ecdsa.ts ecdsaVerify is already non-CT across reject branches per
// docs/asm_p256.md#verify-timing. The four-entry precomputed table is
// indexed by PUBLIC bits, not by any secret-derived value, so it is
// outside the architectural prohibition on "lookup tables indexed by
// secret bits" (SECURITY.md §Side-channel resistance).
//
// Reference: Strauss 1964 "Addition chains for vectors"; the simultaneous
// multi-scalar pattern is standard in ECDSA implementations.
//
// Slot allocation in POINT_TMP:
//   slot 0: accumulator R
//   slot 2: basepoint G (materialized inside this function)
//   slot 3: G + Q (precomputed once before the loop)
//   slot 7: reserved by point.ts pointAdd / pointDouble internal staging
//
// Caller's Q must NOT alias POINT_TMP slot 0, 2, 3, or 7. The `out`
// pointer may alias slot 3 (the call site in ecdsa.ts does this; the
// final R-to-out copy lands after G+Q is no longer read).

/**
 * out = [u1]G + [u2]Q. Strauss-Shamir simultaneous double scalar mult.
 *
 * @param u1BE 32-byte BE scalar (verify-side u1 = e * w mod n)
 * @param u2BE 32-byte BE scalar (verify-side u2 = r * w mod n)
 * @param Q    projective point (the verifier's pk after on-curve gate)
 * @param out  96-byte output point
 *
 * Inputs are all public-derived; this function is not constant-time
 * across the bit-pair selector. Do not call from any code path that
 * carries secret-derived scalars.
 */
export function pointMulDoubleVerify(u1BE: i32, u2BE: i32, Q: i32, out: i32): void {
	const R:  i32 = POINT_TMP + 0 * POINT_TMP_STRIDE
	const G:  i32 = POINT_TMP + 2 * POINT_TMP_STRIDE
	const GQ: i32 = POINT_TMP + 3 * POINT_TMP_STRIDE

	pointBasepoint(G)
	pointAdd(GQ, G, Q)
	pointZero(R)

	for (let byteIdx: i32 = 0; byteIdx < 32; byteIdx++) {
		const b1: u32 = load<u8>(u1BE + byteIdx) as u32
		const b2: u32 = load<u8>(u2BE + byteIdx) as u32
		for (let bitIdx: i32 = 7; bitIdx >= 0; bitIdx--) {
			pointDouble(R, R)
			const bit1: u32 = (b1 >> (bitIdx as u32)) & 1
			const bit2: u32 = (b2 >> (bitIdx as u32)) & 1
			const idx: u32 = (bit1 << 1) | bit2
			// idx 0: R += O, skip; RCB complete add would handle O correctly
			// but the add is wasted work and a public-branch saves the cost.
			if (idx == 1) {
				pointAdd(R, R, Q)
			} else if (idx == 2) {
				pointAdd(R, R, G)
			} else if (idx == 3) {
				pointAdd(R, R, GQ)
			}
		}
	}

	memory.copy(out, R, 96)
}
