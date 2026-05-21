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
// src/asm/curve25519/edwards.ts
//
// edwards25519 point operations on extended (X:Y:Z:T) coordinates.
// RFC 8032 §5.1.4 addition formula (citing Hisil-Wong-Carter-Dawson 2008
// "Twisted Edwards Curves Revisited" §3.1 for a = -1 curves) and the
// matching §3.2 doubling formula.
//
// Each Edwards point occupies 160 bytes: X (offset 0), Y (offset 40),
// Z (offset 80), T (offset 120). Each coordinate is a 5×51-bit limb
// field element (see field.ts).
//
// Scalar multiplication uses straight-line double-and-add with
// constant-time conditional select. NO precomputed tables. NO comb. NO
// sliding window. Variable-base (edPointMul) and fixed-base
// (edPointMulBase) share the same loop body; the only difference is
// where the input point comes from.

import {
	feAdd, feSub, feNeg, feMul, feSqr,
	feIsEqual, feCondSwap,
	loadD, loadTwoD,
} from './field'

import { FIELD_TMP_OFFSET, FIELD_TMP_STRIDE, POINT_TMP_OFFSET, POINT_TMP_STRIDE } from './buffers'

// Edwards point coordinate offsets within a 160-byte point.
const X_OFF: i32 = 0
const Y_OFF: i32 = 40
const Z_OFF: i32 = 80
const T_OFF: i32 = 120

// ── Identity, basepoint loaders ─────────────────────────────────────────────

/** Set p to the identity element (0:1:1:0). RFC 8032 §5.1.4. */
export function edPointZero(out: i32): void {
	// X = 0
	store<i64>(out + X_OFF +  0, 0); store<i64>(out + X_OFF +  8, 0); store<i64>(out + X_OFF + 16, 0); store<i64>(out + X_OFF + 24, 0); store<i64>(out + X_OFF + 32, 0)
	// Y = 1
	store<i64>(out + Y_OFF +  0, 1); store<i64>(out + Y_OFF +  8, 0); store<i64>(out + Y_OFF + 16, 0); store<i64>(out + Y_OFF + 24, 0); store<i64>(out + Y_OFF + 32, 0)
	// Z = 1
	store<i64>(out + Z_OFF +  0, 1); store<i64>(out + Z_OFF +  8, 0); store<i64>(out + Z_OFF + 16, 0); store<i64>(out + Z_OFF + 24, 0); store<i64>(out + Z_OFF + 32, 0)
	// T = 0
	store<i64>(out + T_OFF +  0, 0); store<i64>(out + T_OFF +  8, 0); store<i64>(out + T_OFF + 16, 0); store<i64>(out + T_OFF + 24, 0); store<i64>(out + T_OFF + 32, 0)
}

/**
 * Write the edwards25519 basepoint B (RFC 8032 §5.1, Table 1) to `out` in
 * extended coords. X = Bx, Y = By, Z = 1, T = Bx*By (mod p).
 *
 * The decimal Bx, By in the spec lift to canonical 5×51-bit limb forms via
 * straight bit re-windowing of their canonical 32-byte LE encodings. The
 * T = X*Y limb form is the offline-computed product; both are pinned to
 * the spec values and reproducible from them.
 */
export function edPointBasepoint(out: i32): void {
	// X = Bx
	store<i64>(out + X_OFF +  0, 0x00062D608F25D51A)
	store<i64>(out + X_OFF +  8, 0x000412A4B4F6592A)
	store<i64>(out + X_OFF + 16, 0x00075B7171A4B31D)
	store<i64>(out + X_OFF + 24, 0x0001FF60527118FE)
	store<i64>(out + X_OFF + 32, 0x000216936D3CD6E5)
	// Y = By
	store<i64>(out + Y_OFF +  0, 0x0006666666666658)
	store<i64>(out + Y_OFF +  8, 0x0004CCCCCCCCCCCC)
	store<i64>(out + Y_OFF + 16, 0x0001999999999999)
	store<i64>(out + Y_OFF + 24, 0x0003333333333333)
	store<i64>(out + Y_OFF + 32, 0x0006666666666666)
	// Z = 1
	store<i64>(out + Z_OFF +  0, 1); store<i64>(out + Z_OFF +  8, 0); store<i64>(out + Z_OFF + 16, 0); store<i64>(out + Z_OFF + 24, 0); store<i64>(out + Z_OFF + 32, 0)
	// T = Bx*By (mod p)
	store<i64>(out + T_OFF +  0, 0x00068AB3A5B7DDA3)
	store<i64>(out + T_OFF +  8, 0x00000EEA2A5EADBB)
	store<i64>(out + T_OFF + 16, 0x0002AF8DF483C27E)
	store<i64>(out + T_OFF + 24, 0x000332B375274732)
	store<i64>(out + T_OFF + 32, 0x00067875F0FD78B7)
}

// ── edPointDouble ───────────────────────────────────────────────────────────
//
// RFC 8032 §5.1.4 doubling formula (twisted Edwards a = -1):
//   A  = X1^2
//   B  = Y1^2
//   C  = 2*Z1^2
//   H  = A+B
//   E  = H-(X1+Y1)^2          ( = -2*X1*Y1 )
//   G  = A-B
//   F  = C+G
//   X3 = E*F
//   Y3 = G*H
//   T3 = E*H
//   Z3 = F*G
//
// FIELD_TMP slots used: 0..6 (7 slots). Out may alias `a` because all
// reads from `a` precede any write to `out`.

export function edPointDouble(out: i32, a: i32): void {
	const A: i32 = FIELD_TMP_OFFSET + 0 * FIELD_TMP_STRIDE
	const B: i32 = FIELD_TMP_OFFSET + 1 * FIELD_TMP_STRIDE
	const C: i32 = FIELD_TMP_OFFSET + 2 * FIELD_TMP_STRIDE
	const E: i32 = FIELD_TMP_OFFSET + 3 * FIELD_TMP_STRIDE
	const G: i32 = FIELD_TMP_OFFSET + 4 * FIELD_TMP_STRIDE
	const F: i32 = FIELD_TMP_OFFSET + 5 * FIELD_TMP_STRIDE
	const H: i32 = FIELD_TMP_OFFSET + 6 * FIELD_TMP_STRIDE

	// A = X1^2, B = Y1^2, C = 2*Z1^2
	feSqr(A, a + X_OFF)
	feSqr(B, a + Y_OFF)
	feSqr(C, a + Z_OFF)
	feAdd(C, C, C)

	// H = A + B, G = A - B
	feAdd(H, A, B)
	feSub(G, A, B)

	// E = H - (X1+Y1)^2  (per RFC 8032 §5.1.4; algebraically -2*X1*Y1).
	// Computed via a single feSub from precomputed H rather than as
	// `(X+Y)^2 - A - B` followed by feNeg, because chained feSubs grow
	// limbs beyond what feNeg's 2*p offset can safely cancel.
	feAdd(E, a + X_OFF, a + Y_OFF)
	feSqr(E, E)
	feSub(E, H, E)

	// F = C + G
	feAdd(F, C, G)

	// X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
	feMul(out + X_OFF, E, F)
	feMul(out + Y_OFF, G, H)
	feMul(out + T_OFF, E, H)
	feMul(out + Z_OFF, F, G)
}

// ── edPointAdd ──────────────────────────────────────────────────────────────
//
// RFC 8032 §5.1.4 addition formula (twisted Edwards a = -1):
//   A  = (Y1-X1)*(Y2-X2)
//   B  = (Y1+X1)*(Y2+X2)
//   C  = T1*2*d*T2
//   D  = Z1*2*Z2
//   E  = B-A
//   F  = D-C
//   G  = D+C
//   H  = B+A
//   X3 = E*F
//   Y3 = G*H
//   T3 = E*H
//   Z3 = F*G
//
// FIELD_TMP slots used: 0..12 (13 slots). Out may alias `a` or `b`
// because all reads from a, b precede any write to out.

export function edPointAdd(out: i32, a: i32, b: i32): void {
	const SUB1: i32 = FIELD_TMP_OFFSET +  0 * FIELD_TMP_STRIDE
	const ADD1: i32 = FIELD_TMP_OFFSET +  1 * FIELD_TMP_STRIDE
	const SUB2: i32 = FIELD_TMP_OFFSET +  2 * FIELD_TMP_STRIDE
	const ADD2: i32 = FIELD_TMP_OFFSET +  3 * FIELD_TMP_STRIDE
	const TWOD: i32 = FIELD_TMP_OFFSET +  4 * FIELD_TMP_STRIDE
	const A:    i32 = FIELD_TMP_OFFSET +  5 * FIELD_TMP_STRIDE
	const B:    i32 = FIELD_TMP_OFFSET +  6 * FIELD_TMP_STRIDE
	const C:    i32 = FIELD_TMP_OFFSET +  7 * FIELD_TMP_STRIDE
	const D:    i32 = FIELD_TMP_OFFSET +  8 * FIELD_TMP_STRIDE
	const E:    i32 = FIELD_TMP_OFFSET +  9 * FIELD_TMP_STRIDE
	const F:    i32 = FIELD_TMP_OFFSET + 10 * FIELD_TMP_STRIDE
	const G:    i32 = FIELD_TMP_OFFSET + 11 * FIELD_TMP_STRIDE
	const H:    i32 = FIELD_TMP_OFFSET + 12 * FIELD_TMP_STRIDE

	feSub(SUB1, a + Y_OFF, a + X_OFF)
	feAdd(ADD1, a + Y_OFF, a + X_OFF)
	feSub(SUB2, b + Y_OFF, b + X_OFF)
	feAdd(ADD2, b + Y_OFF, b + X_OFF)

	feMul(A, SUB1, SUB2)
	feMul(B, ADD1, ADD2)

	// C = T1 * 2d * T2
	loadTwoD(TWOD)
	feMul(C, a + T_OFF, TWOD)
	feMul(C, C, b + T_OFF)

	// D = 2 * Z1 * Z2
	feMul(D, a + Z_OFF, b + Z_OFF)
	feAdd(D, D, D)

	feSub(E, B, A)
	feSub(F, D, C)
	feAdd(G, D, C)
	feAdd(H, B, A)

	feMul(out + X_OFF, E, F)
	feMul(out + Y_OFF, G, H)
	feMul(out + T_OFF, E, H)
	feMul(out + Z_OFF, F, G)
}

// ── edPointSub ──────────────────────────────────────────────────────────────
//
// (X:Y:Z:T) - (X':Y':Z':T') = (X:Y:Z:T) + (-X':Y':Z':-T'), exploiting the
// fact that the additive inverse on edwards25519 negates X and T.

export function edPointSub(out: i32, a: i32, b: i32): void {
	// Build -b in POINT_TMP slot 3 (reserved for this purpose; edPointMul
	// only uses slots 0..2). 160 bytes copied + two feNeg in place.
	const negB: i32 = POINT_TMP_OFFSET + 3 * POINT_TMP_STRIDE
	feNeg(negB + X_OFF, b + X_OFF)
	memory.copy(negB + Y_OFF, b + Y_OFF, 40)
	memory.copy(negB + Z_OFF, b + Z_OFF, 40)
	feNeg(negB + T_OFF, b + T_OFF)
	edPointAdd(out, a, negB)
}

// ── edPointEqual ────────────────────────────────────────────────────────────
//
// Constant-time projective-coordinate equality: P1 = (X1:Y1:Z1:T1) equals
// P2 = (X2:Y2:Z2:T2) iff X1*Z2 == X2*Z1 AND Y1*Z2 == Y2*Z1. The T
// coordinate is redundant (T = X*Y/Z) and cross-mult on T duplicates the
// X,Y checks; testing on X and Y alone is sufficient.
//
// Both feIsEqual calls execute regardless of the first's result, and the
// final AND is bitwise so timing does not depend on the first comparison.

export function edPointEqual(a: i32, b: i32): i32 {
	const t0: i32 = FIELD_TMP_OFFSET + 0 * FIELD_TMP_STRIDE
	const t1: i32 = FIELD_TMP_OFFSET + 1 * FIELD_TMP_STRIDE
	const t2: i32 = FIELD_TMP_OFFSET + 2 * FIELD_TMP_STRIDE
	const t3: i32 = FIELD_TMP_OFFSET + 3 * FIELD_TMP_STRIDE

	feMul(t0, a + X_OFF, b + Z_OFF)   // X1 * Z2
	feMul(t1, b + X_OFF, a + Z_OFF)   // X2 * Z1
	feMul(t2, a + Y_OFF, b + Z_OFF)   // Y1 * Z2
	feMul(t3, b + Y_OFF, a + Z_OFF)   // Y2 * Z1

	const xEq: i32 = feIsEqual(t0, t1)
	const yEq: i32 = feIsEqual(t2, t3)
	return xEq & yEq
}

// ── edPointOnCurve ──────────────────────────────────────────────────────────
//
// Projective curve membership: -X^2 + Y^2 = Z^2 + d*T^2 (mod p), plus the
// extended-coord invariant X*Y = Z*T. Together these prove the point lies
// on the twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2 (after dividing
// by Z^2) with x*y = T/Z (after dividing by Z).

export function edPointOnCurve(p: i32): i32 {
	const X2: i32 = FIELD_TMP_OFFSET +  0 * FIELD_TMP_STRIDE
	const Y2: i32 = FIELD_TMP_OFFSET +  1 * FIELD_TMP_STRIDE
	const Z2: i32 = FIELD_TMP_OFFSET +  2 * FIELD_TMP_STRIDE
	const T2: i32 = FIELD_TMP_OFFSET +  3 * FIELD_TMP_STRIDE
	const D:  i32 = FIELD_TMP_OFFSET +  4 * FIELD_TMP_STRIDE
	const L:  i32 = FIELD_TMP_OFFSET +  5 * FIELD_TMP_STRIDE
	const R:  i32 = FIELD_TMP_OFFSET +  6 * FIELD_TMP_STRIDE
	const XY: i32 = FIELD_TMP_OFFSET +  7 * FIELD_TMP_STRIDE
	const ZT: i32 = FIELD_TMP_OFFSET +  8 * FIELD_TMP_STRIDE

	feSqr(X2, p + X_OFF)
	feSqr(Y2, p + Y_OFF)
	feSqr(Z2, p + Z_OFF)
	feSqr(T2, p + T_OFF)

	loadD(D)
	feMul(R, D, T2)
	feAdd(R, R, Z2)               // R = Z^2 + d*T^2

	feSub(L, Y2, X2)              // L = -X^2 + Y^2

	feMul(XY, p + X_OFF, p + Y_OFF)
	feMul(ZT, p + Z_OFF, p + T_OFF)

	const eq1: i32 = feIsEqual(L, R)
	const eq2: i32 = feIsEqual(XY, ZT)
	return eq1 & eq2
}

// ── Constant-time point select ──────────────────────────────────────────────
//
// Conditional swap on each of the 4 coordinates. When swap = 1, R and Q
// are exchanged in place; when swap = 0, both are left untouched. The
// "select R := bit ? Q : R" semantics needed by the double-and-add inner
// loop is realised by this swap: after the call, R holds whichever of
// {R, Q} the bit selects, and Q holds the other (which is discarded /
// overwritten in the next iteration).

@inline
function edPointCondSwap(R: i32, Q: i32, swap: i32): void {
	feCondSwap(R + X_OFF, Q + X_OFF, swap)
	feCondSwap(R + Y_OFF, Q + Y_OFF, swap)
	feCondSwap(R + Z_OFF, Q + Z_OFF, swap)
	feCondSwap(R + T_OFF, Q + T_OFF, swap)
}

// ── edPointMul ──────────────────────────────────────────────────────────────
//
// Variable-base scalar multiplication: out = [scalar] * P. Straight-line
// double-and-add with constant-time conditional select. The loop runs
// exactly 255 iterations (covering scalar bits 254..0, the canonical range
// after RFC 8032 clamping); the time and addition / doubling count is
// fixed regardless of scalar value.
//
// NO precomputed tables. NO comb. NO sliding window.
//
// POINT_TMP slot usage:
//   slot 0: R    (accumulator, updated each iteration)
//   slot 1: Q    (R + P candidate)
//   slot 2: D    (R doubled, copied back to R each iteration)
//   slot 3: edPointSub scratch (reserved)
//
// FIELD_TMP slots 0..12 are reclaimed by edPointDouble / edPointAdd
// between iterations.

export function edPointMul(out: i32, scalar: i32, p: i32): void {
	const R: i32 = POINT_TMP_OFFSET + 0 * POINT_TMP_STRIDE
	const Q: i32 = POINT_TMP_OFFSET + 1 * POINT_TMP_STRIDE
	const D: i32 = POINT_TMP_OFFSET + 2 * POINT_TMP_STRIDE

	edPointZero(R)

	for (let i: i32 = 254; i >= 0; i--) {
		edPointDouble(D, R)
		memory.copy(R, D, 160)

		edPointAdd(Q, R, p)

		const byteIdx: i32 = i >> 3
		const bitIdx:  i32 = i & 7
		const bit:     i32 = (load<u8>(scalar + byteIdx) as i32 >> bitIdx) & 1

		edPointCondSwap(R, Q, bit)
	}

	memory.copy(out, R, 160)
}

// ── edPointMulBase ──────────────────────────────────────────────────────────
// Fixed-base: out = [scalar] * B. Same loop as edPointMul with B in
// POINT_TMP slot 3. No precomputed comb (see edPointMul rule).

export function edPointMulBase(out: i32, scalar: i32): void {
	// Materialise B into the spare POINT_TMP slot reserved for this, then
	// dispatch to the variable-base loop.
	const B: i32 = POINT_TMP_OFFSET + 3 * POINT_TMP_STRIDE
	edPointBasepoint(B)
	edPointMul(out, scalar, B)
}
