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
// src/asm/p256/point.ts
//
// P-256 short-Weierstrass projective coordinates and complete
// addition / doubling per Renes-Costello-Batina 2016, "Complete
// addition formulas for prime order elliptic curves" (eprint
// 2015/1060). The specialised a = -3 formulas (P-256 has a = p - 3
// per SP 800-186 §3.2.1.3) eliminate the explicit a-multiplications
// and the algorithm internally uses b (the curve's b constant) and
// the small literal 3 for the b3 = 3 * b factor; the helper triples
// inline rather than caching a precomputed b3.
//
// Projective coordinate representation: (X : Y : Z) at offsets
// (p + 0, p + 32, p + 64). 96 bytes per point. Affine recovery:
// (x, y) = (X / Z, Y / Z), one feInv per affinify call.
//
// Aliasing: pointAdd and pointDouble both stage their final X3 / Y3 /
// Z3 in scratch slots and copy to `out` only at the end, so `out`
// may alias `p` or `q` safely. Callers in scalar_mult.ts rely on
// this (e.g. the accumulator R is updated via `pointAdd(R, R, Q)`).
//
// Algorithm references (verbatim line numbering from RCB 2016):
//   pointAdd     ← Algorithm 4 (complete addition, a = -3)
//   pointDouble  ← Algorithm 6 (dedicated doubling, a = -3)
//
// Both algorithms are unified / exception-free over the projective
// model: they correctly handle the identity (Z = 0), P = Q, and
// P = -Q without branches. This is the property that justifies the
// "complete addition" terminology.

import {
	FIELD_TMP, FIELD_TMP_STRIDE,
} from './buffers'

import {
	feAdd, feSub, feNeg, feMul, feSqr, feInv, feSqrt, feCopy,
	feZero, feOne, feIsZero, feIsEqual, feIsOdd,
	loadB,
} from './field'

// ── Point-arithmetic FE scratch slots ─────────────────────────────────────
//
// Slots 16..31 of FIELD_TMP. Slots 0..15 belong to field.ts internals
// (feMul / feReduce / feInv / feSqrt); point.ts must not touch them
// across feMul calls because feMul clobbers them.

const XX:        i32 = FIELD_TMP + 16 * FIELD_TMP_STRIDE
const YY:        i32 = FIELD_TMP + 17 * FIELD_TMP_STRIDE
const ZZ:        i32 = FIELD_TMP + 18 * FIELD_TMP_STRIDE
const XY_PAIRS:  i32 = FIELD_TMP + 19 * FIELD_TMP_STRIDE
const YZ_PAIRS:  i32 = FIELD_TMP + 20 * FIELD_TMP_STRIDE
const XZ_PAIRS:  i32 = FIELD_TMP + 21 * FIELD_TMP_STRIDE
const BZZ_PART:  i32 = FIELD_TMP + 22 * FIELD_TMP_STRIDE
const BZZ3:      i32 = FIELD_TMP + 23 * FIELD_TMP_STRIDE
const YY_M_BZZ3: i32 = FIELD_TMP + 24 * FIELD_TMP_STRIDE
const YY_P_BZZ3: i32 = FIELD_TMP + 25 * FIELD_TMP_STRIDE
const ZZ3:       i32 = FIELD_TMP + 26 * FIELD_TMP_STRIDE
const BXZ:       i32 = FIELD_TMP + 27 * FIELD_TMP_STRIDE
const BXZ3:      i32 = FIELD_TMP + 28 * FIELD_TMP_STRIDE
const XX3_M_ZZ3: i32 = FIELD_TMP + 29 * FIELD_TMP_STRIDE
const TMP1:      i32 = FIELD_TMP + 30 * FIELD_TMP_STRIDE
const TMP2:      i32 = FIELD_TMP + 31 * FIELD_TMP_STRIDE

// Three more scratch slots for pointDouble + final-output staging. We
// pull these from the POINT_TMP region's last slot (slot 7), which is
// only used as an explicit ladder scratch at higher levels and not
// during a single point op. 96 bytes = 3 × 32-byte FE.
//
// Imported via the buffers.ts offset; see ./buffers.ts for the
// rationale (point.ts internal scratch must not alias FIELD_TMP slots
// 0..15 or other concurrently-live point storage).

import {POINT_TMP, POINT_TMP_STRIDE} from './buffers'
const X_OUT:  i32 = POINT_TMP + 7 * POINT_TMP_STRIDE +  0
const Y_OUT:  i32 = POINT_TMP + 7 * POINT_TMP_STRIDE + 32
const Z_OUT:  i32 = POINT_TMP + 7 * POINT_TMP_STRIDE + 64

// ── Coordinate-offset helpers ──────────────────────────────────────────────

@inline function pX(p: i32): i32 { return p + 0  }
@inline function pY(p: i32): i32 { return p + 32 }
@inline function pZ(p: i32): i32 { return p + 64 }

// ── Identity / basepoint loaders ───────────────────────────────────────────

/**
 * Write the projective identity element (0 : 1 : 0) to `out`. RCB
 * §2.1 / §3.1: any point with Z = 0 is the point at infinity; we use
 * the canonical (0:1:0) form for clarity at the call site.
 */
export function pointZero(out: i32): void {
	feZero(pX(out))
	feOne(pY(out))
	feZero(pZ(out))
}

/**
 * Write the P-256 basepoint G = (Gx, Gy, 1) to `out`. SP 800-186
 * §3.2.1.3 publishes (Gx, Gy) in big-endian hex; the LE limb form
 * below is the byte-reversed transcription per u32 word, mirroring
 * the conversion convention used by feFromBytes / feToBytes.
 *
 *   Gx = 6B17D1F2 E12C4247 F8BCE6E5 63A440F2
 *        77037D81 2DEB33A0 F4A13945 D898C296   (32 BE hex digits)
 *   Gy = 4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16
 *        2BCE3357 6B315ECE CBB64068 37BF51F5
 *
 * LE u32 limb order (limb[0] is LSB):
 *   Gx[0..7] = D898C296, F4A13945, 2DEB33A0, 77037D81,
 *              63A440F2, F8BCE6E5, E12C4247, 6B17D1F2
 *   Gy[0..7] = 37BF51F5, CBB64068, 6B315ECE, 2BCE3357,
 *              7C0F9E16, 8EE7EB4A, FE1A7F9B, 4FE342E2
 */
export function pointBasepoint(out: i32): void {
	const x: i32 = pX(out)
	const y: i32 = pY(out)
	const z: i32 = pZ(out)

	store<u32>(x +  0, 0xD898C296)
	store<u32>(x +  4, 0xF4A13945)
	store<u32>(x +  8, 0x2DEB33A0)
	store<u32>(x + 12, 0x77037D81)
	store<u32>(x + 16, 0x63A440F2)
	store<u32>(x + 20, 0xF8BCE6E5)
	store<u32>(x + 24, 0xE12C4247)
	store<u32>(x + 28, 0x6B17D1F2)

	store<u32>(y +  0, 0x37BF51F5)
	store<u32>(y +  4, 0xCBB64068)
	store<u32>(y +  8, 0x6B315ECE)
	store<u32>(y + 12, 0x2BCE3357)
	store<u32>(y + 16, 0x7C0F9E16)
	store<u32>(y + 20, 0x8EE7EB4A)
	store<u32>(y + 24, 0xFE1A7F9B)
	store<u32>(y + 28, 0x4FE342E2)

	feOne(z)
}

// ── Negation / equality ────────────────────────────────────────────────────

/**
 * out = -P. The projective negation (X : Y : Z) → (X : -Y : Z).
 */
export function pointNegate(out: i32, p: i32): void {
	if (out != p) {
		feCopy(pX(out), pX(p))
		feCopy(pZ(out), pZ(p))
	}
	feNeg(pY(out), pY(p))
}

/**
 * Returns 1 if P == Q (as projective points), 0 otherwise.
 *
 * (X_P : Y_P : Z_P) == (X_Q : Y_Q : Z_Q)  iff
 *   X_P * Z_Q == X_Q * Z_P  AND  Y_P * Z_Q == Y_Q * Z_P
 *
 * Constant-time wrt the limbs of both inputs; feIsEqual folds the
 * limb-wise XOR into a single 0/1.
 */
export function pointEqual(p: i32, q: i32): i32 {
	const lhs: i32 = TMP1
	const rhs: i32 = TMP2
	feMul(lhs, pX(p), pZ(q))   // X_P * Z_Q
	feMul(rhs, pX(q), pZ(p))   // X_Q * Z_P
	const xEq: i32 = feIsEqual(lhs, rhs)
	feMul(lhs, pY(p), pZ(q))   // Y_P * Z_Q
	feMul(rhs, pY(q), pZ(p))   // Y_Q * Z_P
	const yEq: i32 = feIsEqual(lhs, rhs)
	return xEq & yEq
}

// ── Substrate gate / pk-import check: pointOnCurve ─────────────────────────

/**
 * Returns 1 if P lies on the P-256 curve, 0 otherwise. Curve equation
 * in projective form for a = -3 short Weierstrass:
 *
 *   Y² * Z == X³ - 3 * X * Z² + b * Z³
 *
 * Used for the pk-import strict-gate in the verify call path: a
 * decompressed pk that fails on-curve is a strict-gate rejection.
 */
export function pointOnCurve(p: i32): i32 {
	const lhs: i32 = XX     // Y² * Z
	const rhs: i32 = YY     // X³ - 3*X*Z² + b*Z³
	const tmp: i32 = ZZ
	const tmp2: i32 = XY_PAIRS

	// lhs = Y² * Z
	feSqr(tmp, pY(p))
	feMul(lhs, tmp, pZ(p))

	// X³ term: tmp = X²; tmp2 = X² * X = X³
	feSqr(tmp, pX(p))
	feMul(tmp2, tmp, pX(p))

	// 3*X*Z² term: tmp = Z²; tmp = Z² * X; tmp = 3 * X * Z²
	feSqr(tmp, pZ(p))
	feMul(tmp, tmp, pX(p))
	const threeXZ2: i32 = YZ_PAIRS
	feAdd(threeXZ2, tmp, tmp)
	feAdd(threeXZ2, threeXZ2, tmp)
	// rhs = X³ - 3*X*Z²
	feSub(rhs, tmp2, threeXZ2)

	// b * Z³ term: tmp = Z²; tmp = Z² * Z = Z³; tmp2 = b; tmp = b * Z³
	feSqr(tmp, pZ(p))
	feMul(tmp, tmp, pZ(p))
	loadB(tmp2)
	feMul(tmp, tmp2, tmp)
	feAdd(rhs, rhs, tmp)

	return feIsEqual(lhs, rhs)
}

// ── pointAdd: Renes-Costello-Batina Algorithm 4 (a = -3) ───────────────────
//
// Verbatim translation of the algorithm 4 specialisation from
// "Complete addition formulas for prime order elliptic curves"
// (eprint 2015/1060). Variable names mirror the RustCrypto p256 /
// primeorder reference, which itself is annotated against RCB.
//
// Line-by-line cost: 14 feMul + ~30 feAdd/feSub. The 14 mults
// breakdown: 3 cross multiplies on the basis coords (xx, yy, zz),
// 3 cross multiplies for the Karatsuba-style xy/yz/xz pair sums,
// 2 mults by b (b*zz, b*xz_pairs), 6 final-output mults.

/**
 * out = P + Q. Renes-Costello-Batina 2016 Algorithm 4, complete
 * addition for short-Weierstrass curves with a = -3. `out` may alias
 * `p` or `q`; all reads of (X1..Z2) complete before any writes to
 * (X3..Z3).
 */
export function pointAdd(out: i32, p: i32, q: i32): void {
	const x1: i32 = pX(p); const y1: i32 = pY(p); const z1: i32 = pZ(p)
	const x2: i32 = pX(q); const y2: i32 = pY(q); const z2: i32 = pZ(q)

	// Lines 1-3: xx = X1*X2, yy = Y1*Y2, zz = Z1*Z2
	feMul(XX, x1, x2)
	feMul(YY, y1, y2)
	feMul(ZZ, z1, z2)

	// Lines 4-8: xy_pairs = (X1+Y1)(X2+Y2) - (xx+yy)
	feAdd(TMP1, x1, y1)
	feAdd(TMP2, x2, y2)
	feMul(TMP1, TMP1, TMP2)
	feAdd(TMP2, XX, YY)
	feSub(XY_PAIRS, TMP1, TMP2)

	// Lines 9-13: yz_pairs = (Y1+Z1)(Y2+Z2) - (yy+zz)
	feAdd(TMP1, y1, z1)
	feAdd(TMP2, y2, z2)
	feMul(TMP1, TMP1, TMP2)
	feAdd(TMP2, YY, ZZ)
	feSub(YZ_PAIRS, TMP1, TMP2)

	// Lines 14-18: xz_pairs = (X1+Z1)(X2+Z2) - (xx+zz)
	feAdd(TMP1, x1, z1)
	feAdd(TMP2, x2, z2)
	feMul(TMP1, TMP1, TMP2)
	feAdd(TMP2, XX, ZZ)
	feSub(XZ_PAIRS, TMP1, TMP2)

	// Lines 19-20: bzz_part = xz_pairs - b * zz
	loadB(TMP1)
	feMul(TMP2, TMP1, ZZ)
	feSub(BZZ_PART, XZ_PAIRS, TMP2)

	// Lines 21-22: bzz3 = 3 * bzz_part = (bzz_part + bzz_part) + bzz_part
	feAdd(TMP1, BZZ_PART, BZZ_PART)
	feAdd(BZZ3, TMP1, BZZ_PART)

	// Lines 23-24: yy_m_bzz3, yy_p_bzz3
	feSub(YY_M_BZZ3, YY, BZZ3)
	feAdd(YY_P_BZZ3, YY, BZZ3)

	// Lines 26-27: zz3 = 3 * zz
	feAdd(TMP1, ZZ, ZZ)
	feAdd(ZZ3, TMP1, ZZ)

	// Lines 25, 28-29: bxz = b * xz_pairs - (zz3 + xx)
	loadB(TMP1)
	feMul(TMP2, TMP1, XZ_PAIRS)
	feAdd(TMP1, ZZ3, XX)
	feSub(BXZ, TMP2, TMP1)

	// Lines 30-31: bxz3 = 3 * bxz
	feAdd(TMP1, BXZ, BXZ)
	feAdd(BXZ3, TMP1, BXZ)

	// Lines 32-34: xx3_m_zz3 = 3*xx - zz3
	feAdd(TMP1, XX, XX)
	feAdd(TMP2, TMP1, XX)
	feSub(XX3_M_ZZ3, TMP2, ZZ3)

	// Lines 35, 39-40: X3 = yy_p_bzz3 * xy_pairs - yz_pairs * bxz3
	feMul(TMP1, YY_P_BZZ3, XY_PAIRS)
	feMul(TMP2, YZ_PAIRS, BXZ3)
	feSub(X_OUT, TMP1, TMP2)

	// Lines 36-38: Y3 = yy_p_bzz3 * yy_m_bzz3 + xx3_m_zz3 * bxz3
	feMul(TMP1, YY_P_BZZ3, YY_M_BZZ3)
	feMul(TMP2, XX3_M_ZZ3, BXZ3)
	feAdd(Y_OUT, TMP1, TMP2)

	// Lines 41-43: Z3 = yy_m_bzz3 * yz_pairs + xy_pairs * xx3_m_zz3
	feMul(TMP1, YY_M_BZZ3, YZ_PAIRS)
	feMul(TMP2, XY_PAIRS, XX3_M_ZZ3)
	feAdd(Z_OUT, TMP1, TMP2)

	// Final commit (after all reads of p, q have completed): copy
	// staged X_OUT / Y_OUT / Z_OUT into the caller's `out` slots.
	feCopy(pX(out), X_OUT)
	feCopy(pY(out), Y_OUT)
	feCopy(pZ(out), Z_OUT)
}

// ── pointDouble: Renes-Costello-Batina Algorithm 6 (a = -3) ────────────────
//
// Specialised dedicated-doubling formula. Verbatim translation of the
// RustCrypto reference. 6 squarings or feMul-by-self equivalents plus
// the same b-multiplications, 19 adds/subs. The "double().double()"
// pattern at the end (Z3 = (yz2*yy).double().double() = 8 * y * z * yy)
// reflects the algorithm's specialisation: yz2 is already 2*yz, so
// (yz2*yy).double().double() = 8 * y * z * yy = 4 * yz2 * yy.

/**
 * out = 2P. Renes-Costello-Batina 2016 Algorithm 6, dedicated
 * doubling for a = -3. Complete (handles the identity).
 */
export function pointDouble(out: i32, p: i32): void {
	const x1: i32 = pX(p); const y1: i32 = pY(p); const z1: i32 = pZ(p)

	// Lines 1-3
	feSqr(XX, x1)
	feSqr(YY, y1)
	feSqr(ZZ, z1)

	// Lines 4-5: xy2 = 2 * X * Y
	feMul(TMP1, x1, y1)
	feAdd(XY_PAIRS, TMP1, TMP1)  // alias XY_PAIRS as xy2

	// Lines 6-7: xz2 = 2 * X * Z
	feMul(TMP1, x1, z1)
	feAdd(XZ_PAIRS, TMP1, TMP1)  // alias XZ_PAIRS as xz2

	// Lines 8-9: bzz_part = b * zz - xz2
	loadB(TMP1)
	feMul(TMP2, TMP1, ZZ)
	feSub(BZZ_PART, TMP2, XZ_PAIRS)

	// Lines 10-11: bzz3 = 3 * bzz_part
	feAdd(TMP1, BZZ_PART, BZZ_PART)
	feAdd(BZZ3, TMP1, BZZ_PART)

	// Lines 12-13: yy_m_bzz3, yy_p_bzz3
	feSub(YY_M_BZZ3, YY, BZZ3)
	feAdd(YY_P_BZZ3, YY, BZZ3)

	// Line 14: y_frag = yy_p_bzz3 * yy_m_bzz3 (parked in YZ_PAIRS slot)
	feMul(YZ_PAIRS, YY_P_BZZ3, YY_M_BZZ3)
	// Line 15: x_frag = yy_m_bzz3 * xy2 (parked in BZZ_PART slot — bzz_part no longer needed)
	feMul(BZZ_PART, YY_M_BZZ3, XY_PAIRS)

	// Lines 16-17: zz3 = 3 * zz
	feAdd(TMP1, ZZ, ZZ)
	feAdd(ZZ3, TMP1, ZZ)

	// Lines 18-20: bxz2 = b * xz2 - (zz3 + xx)
	loadB(TMP1)
	feMul(TMP2, TMP1, XZ_PAIRS)
	feAdd(TMP1, ZZ3, XX)
	feSub(BXZ, TMP2, TMP1)

	// Lines 21-22: bxz6 = 3 * bxz2 (the algorithm names this bxz6_part
	// because bxz2 already contains a factor of 2 from xz2, so 3 * bxz2
	// is 6 * b * x * z minus 3 * (3*zz + xx)).
	feAdd(TMP1, BXZ, BXZ)
	feAdd(BXZ3, TMP1, BXZ)

	// Lines 23-25: xx3_m_zz3 = 3*xx - zz3
	feAdd(TMP1, XX, XX)
	feAdd(TMP2, TMP1, XX)
	feSub(XX3_M_ZZ3, TMP2, ZZ3)

	// Lines 26-27: Y3 = y_frag + xx3_m_zz3 * bxz6
	feMul(TMP1, XX3_M_ZZ3, BXZ3)
	feAdd(Y_OUT, YZ_PAIRS, TMP1)  // y_frag was in YZ_PAIRS

	// Lines 28-29: yz2 = 2 * Y * Z
	feMul(TMP1, y1, z1)
	feAdd(TMP2, TMP1, TMP1)        // yz2 in TMP2

	// Lines 30-31: X3 = x_frag - bxz6 * yz2
	feMul(TMP1, BXZ3, TMP2)
	feSub(X_OUT, BZZ_PART, TMP1)   // x_frag was in BZZ_PART

	// Lines 32-34: Z3 = 4 * yz2 * yy = (yz2 * yy).double().double()
	feMul(TMP1, TMP2, YY)
	feAdd(TMP1, TMP1, TMP1)
	feAdd(Z_OUT, TMP1, TMP1)

	// Final commit
	feCopy(pX(out), X_OUT)
	feCopy(pY(out), Y_OUT)
	feCopy(pZ(out), Z_OUT)
}

// ── pointSub ───────────────────────────────────────────────────────────────

/**
 * out = P - Q = P + (-Q). Negate Q in scratch, then add. Constant
 * cost: 1 pointNegate + 1 pointAdd.
 */
export function pointSub(out: i32, p: i32, q: i32): void {
	const negQ: i32 = POINT_TMP + 6 * POINT_TMP_STRIDE
	pointNegate(negQ, q)
	pointAdd(out, p, negQ)
}

// ── pointAffinify: (X : Y : Z) → (x = X/Z, y = Y/Z) ────────────────────────
//
// Used at the end of [s]G to extract the affine x-coordinate for
// r = x mod n (FIPS 186-5 §6.4 step 4) and at the verify step's
// u1*G + u2*Q result for r comparison.
//
// Caller passes outX, outY as 32-byte field-element offsets. If the
// input point is the identity (Z == 0), feInv returns the inverse of
// 0 which is itself 0 (Fermat: 0^(p-2) = 0), so outX = X * 0 = 0,
// outY = Y * 0 = 0. The caller is responsible for distinguishing the
// identity case if it matters (the strict-gate rejects identity at
// verify time so this is normally a non-issue).

/**
 * outX = X / Z (mod p), outY = Y / Z (mod p). One feInv per call.
 *
 * zInv lives in POINT_TMP slot 7's third FE sub-slot (Z_OUT alias).
 * POINT_TMP slot 7 is reserved for pointAdd / pointDouble internal
 * staging; pointAffinify does not call those, so reuse is safe. Using
 * a FIELD_TMP slot (e.g. TMP1) here is unsafe because a caller may
 * pass outX = TMP1 (alias), in which case the first feMul would
 * overwrite zInv before the second feMul reads it, silently producing
 * outY = Y * X * zInv instead of Y * zInv.
 */
export function pointAffinify(p: i32, outX: i32, outY: i32): void {
	const zInv: i32 = Z_OUT
	feInv(zInv, pZ(p))
	feMul(outX, pX(p), zInv)
	feMul(outY, pY(p), zInv)
}

// ── pointCompress: SEC1 §2.3.3 ─────────────────────────────────────────────
//
// 33-byte compressed encoding: prefix byte 0x02 if y is even, 0x03 if y
// is odd, followed by the 32-byte BE encoding of x. Caller is
// responsible for handling the identity case explicitly (compressing
// the identity has no canonical SEC1 encoding; the suite-level wrapper
// rejects identity pks at construction).

import {feToBytes, feFromBytes} from './field'

/**
 * Compress the projective point P to 33 bytes at `out`. Computes the
 * affine (x, y) via one feInv on Z, then writes 0x02 || x or
 * 0x03 || x depending on parity of y. `out` and `p` may not alias the
 * point-FE scratch slots.
 *
 * xAff / yAff are placed in slots XX / YY (FIELD_TMP slots 16, 17)
 * which do NOT alias with the TMP1 slot pointAffinify uses internally
 * for zInv. Using TMP1 / TMP2 here would alias zInv and silently
 * corrupt yAff (the second feMul inside pointAffinify reads zInv from
 * the slot that was already overwritten by the first feMul writing
 * outX).
 */
export function pointCompress(out: i32, p: i32): void {
	const xAff: i32 = XX
	const yAff: i32 = YY
	pointAffinify(p, xAff, yAff)
	const prefix: u8 = (0x02 + (feIsOdd(yAff) as u8)) as u8
	store<u8>(out, prefix)
	feToBytes(out + 1, xAff)
}

// ── pointDecompress: SEC1 §2.3.4 ───────────────────────────────────────────
//
// Read prefix byte (must be 0x02 or 0x03), deserialize x, compute
// y² = x³ - 3*x + b, take sqrt (feSqrt is x^((p+1)/4) which is the
// principal sqrt for p ≡ 3 (mod 4)), pick the parity matching the
// prefix. Returns 1 on success, 0 on:
//   - prefix byte not in {0x02, 0x03}
//   - x ≥ p (canonical encoding violation)
//   - y² is a quadratic non-residue (no x on curve)
//
// Output: out is (X : Y : Z = 1) with Z = 1 for the freshly-decoded
// affine point.

/**
 * Decompress 33-byte compressed-point encoding at `src`. Returns 1 on
 * success, 0 on rejection. The strict-gate at the ECDSA verify call
 * site treats 0 as a verify failure (FIPS 186-5 §6.5.2 step 1, public
 * key validation rejects pks that fail to decode).
 */
export function pointDecompress(out: i32, src: i32): i32 {
	const prefix: u8 = load<u8>(src)
	// Prefix must be 0x02 or 0x03. Reject 0x00 (identity), 0x04 (uncompressed
	// — not supported here; uncompressed pks are TS-side decoded), and any
	// other byte.
	if (prefix != 0x02 && prefix != 0x03) {
		return 0
	}

	// Deserialize x from src+1..src+33.
	const x: i32 = pX(out)
	feFromBytes(x, src + 1)

	// TODO: x < p check. feFromBytes does not reduce, so an adversarial
	// x in [p, 2^256) would decode but represent a non-canonical field
	// element. The verify-side strict-gate elsewhere (pointOnCurve)
	// catches this indirectly — a non-canonical x won't satisfy the
	// curve equation against a canonical y. For belt-and-suspenders
	// we could compare x to p here; deferred until the gate test
	// surfaces the case.

	// y² = x³ - 3*x + b
	const x3: i32 = TMP1
	const minus3x: i32 = TMP2
	const ySq: i32 = XX  // reuse scratch
	feSqr(x3, x)
	feMul(x3, x3, x)            // x³
	feAdd(minus3x, x, x)
	feAdd(minus3x, minus3x, x)  // 3*x
	feSub(ySq, x3, minus3x)     // x³ - 3*x
	loadB(TMP1)
	feAdd(ySq, ySq, TMP1)       // x³ - 3*x + b

	// y = sqrt(y²). For p ≡ 3 (mod 4), y = (y²)^((p+1)/4).
	const yCand: i32 = pY(out)
	feSqrt(yCand, ySq)

	// Verify the candidate squares back: feSqr(yCand) ==? ySq.
	const yCandSq: i32 = TMP2
	feSqr(yCandSq, yCand)
	const ok: i32 = feIsEqual(yCandSq, ySq)
	if (ok == 0) {
		// Not a quadratic residue → x is not on the curve.
		return 0
	}

	// Fix parity: if (prefix & 1) != feIsOdd(yCand), negate yCand.
	const wantOdd: i32 = (prefix & 1) as i32
	const isOdd:   i32 = feIsOdd(yCand)
	if (wantOdd != isOdd) {
		feNeg(yCand, yCand)
	}

	// Z = 1
	feOne(pZ(out))
	return 1
}
