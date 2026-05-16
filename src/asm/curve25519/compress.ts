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
// src/asm/curve25519/compress.ts
//
// edwards25519 point encoding / decoding per RFC 8032 §5.1.2 and §5.1.3.
//
// Encoding (§5.1.2): convert (X:Y:Z:T) to affine (x, y) via Z^-1, encode
// y as 32-byte LE, then OR the LSB of x into the top bit of byte 31.
//
// Decoding (§5.1.3): parse sign bit and y; check y < p; recover x from
// the curve equation x^2 = (y^2 - 1)/(d*y^2 + 1) via the p ≡ 5 mod 8
// square-root trick (no modular inversion); apply sign and validate.

import {
	feAdd, feSub, feMul, feSqr, feInv,
	feFromBytes, feToBytes, feIsZero, feIsNegative, feCondSwap, feCondNeg,
	fePow_p58, loadD, loadSqrtM1,
} from './field'

import { FIELD_TMP_OFFSET, FIELD_TMP_STRIDE } from './buffers'

const X_OFF: i32 = 0
const Y_OFF: i32 = 40
const Z_OFF: i32 = 80
const T_OFF: i32 = 120

// ── edPointCompress ─────────────────────────────────────────────────────────
//
// out: 32-byte encoded point. p: 160-byte input point in extended coords.
// Algorithm:
//   Zinv = Z^-1
//   x = X * Zinv  (mod p)
//   y = Y * Zinv  (mod p)
//   write y as 32-byte LE canonical
//   set top bit of out[31] to LSB of canonical x
//
// FIELD_TMP slots used: 0..11 (feInv internal), 12 (x), 13 (y).

export function edPointCompress(out: i32, p: i32): void {
	const Zinv: i32 = FIELD_TMP_OFFSET + 11 * FIELD_TMP_STRIDE
	const x:    i32 = FIELD_TMP_OFFSET + 12 * FIELD_TMP_STRIDE
	const y:    i32 = FIELD_TMP_OFFSET + 13 * FIELD_TMP_STRIDE

	feInv(Zinv, p + Z_OFF)
	feMul(x, p + X_OFF, Zinv)
	feMul(y, p + Y_OFF, Zinv)

	feToBytes(out, y)                  // top bit of out[31] is 0 (canonical)
	const xSign: u8 = feIsNegative(x) as u8
	store<u8>(out + 31, load<u8>(out + 31) | (xSign << 7))
}

// ── edPointDecompress ───────────────────────────────────────────────────────
//
// out: 160-byte output point (extended coords). src: 32-byte encoded point.
// Returns 1 on success, 0 on failure (non-canonical y, non-residue x^2,
// or x = 0 with x_0 = 1).
//
// FIELD_TMP slot allocation:
//   11:     y       (persistent, written to out + Y_OFF at the end)
//   12:     u       (persistent across pow, needed for ± test)
//   13:     v       (persistent across pow, needed for v*x^2 test)
//   14:     u*v^3   (persistent across pow, multiplied with pow result)
//   15:     u*v^7 → pow result → candidate x → final x
//
// Slots 0..10 hold:
//   - pre-pow scratch (one, y^2, d, v^2, v^3, v^4, v^7) before fePow_p58
//   - fePow_p58 internal scratch during the call (all clobbered)
//   - post-pow scratch: x^2, v*x^2, vx2 ± u diff buffers, sqrt(-1), xAlt
//
// feIsEqual uses slot 15 internally, which would clobber the candidate x.
// We avoid it by computing differences explicitly via feSub and feAdd
// into slots in the 0..10 range and calling feIsZero (which uses slot 0).

export function edPointDecompress(out: i32, src: i32): i32 {
	const y:    i32 = FIELD_TMP_OFFSET + 11 * FIELD_TMP_STRIDE
	const u:    i32 = FIELD_TMP_OFFSET + 12 * FIELD_TMP_STRIDE
	const v:    i32 = FIELD_TMP_OFFSET + 13 * FIELD_TMP_STRIDE
	const u_v3: i32 = FIELD_TMP_OFFSET + 14 * FIELD_TMP_STRIDE
	const x:    i32 = FIELD_TMP_OFFSET + 15 * FIELD_TMP_STRIDE

	// ── Step 1: parse sign bit, mask top bit, decode y, check y < p ──
	const signByte: u8 = load<u8>(src + 31)
	const xSign:    i32 = (signByte >> 7) as i32

	// Decode y; feFromBytes masks bit 255 automatically.
	feFromBytes(y, src)

	// Canonicality: re-encode and compare to (src with top bit cleared).
	// If equal, the input was a canonical representation of y in [0, p);
	// if not, y >= p was encoded and decoding fails.
	const yRe: i32 = FIELD_TMP_OFFSET + 0 * FIELD_TMP_STRIDE  // 32 bytes scratch
	feToBytes(yRe, y)
	let canonDiff: u32 = 0
	for (let i: i32 = 0; i < 31; i++) {
		canonDiff |= (load<u8>(yRe + i) ^ load<u8>(src + i)) as u32
	}
	// Compare byte 31 with top bit of src masked off.
	canonDiff |= (load<u8>(yRe + 31) ^ (load<u8>(src + 31) & 0x7F)) as u32
	// canonical = 1 iff canonDiff == 0.
	const canonical: i32 = (((0 - canonDiff) >> 31) ^ 1) as i32 & 1

	// ── Step 2: compute u = y^2 - 1, v = d*y^2 + 1 ────────────────────
	const ONE: i32 = FIELD_TMP_OFFSET + 1 * FIELD_TMP_STRIDE
	store<i64>(ONE +  0, 1); store<i64>(ONE +  8, 0); store<i64>(ONE + 16, 0); store<i64>(ONE + 24, 0); store<i64>(ONE + 32, 0)

	const y2: i32 = FIELD_TMP_OFFSET + 2 * FIELD_TMP_STRIDE
	feSqr(y2, y)
	feSub(u, y2, ONE)

	const D: i32 = FIELD_TMP_OFFSET + 3 * FIELD_TMP_STRIDE
	loadD(D)
	feMul(v, D, y2)
	feAdd(v, v, ONE)

	// ── Step 3: build u*v^3 and u*v^7 ─────────────────────────────────
	const v2: i32 = FIELD_TMP_OFFSET + 4 * FIELD_TMP_STRIDE
	const v3: i32 = FIELD_TMP_OFFSET + 5 * FIELD_TMP_STRIDE
	const v4: i32 = FIELD_TMP_OFFSET + 6 * FIELD_TMP_STRIDE
	const v7: i32 = FIELD_TMP_OFFSET + 7 * FIELD_TMP_STRIDE

	feSqr(v2, v)
	feMul(v3, v2, v)
	feMul(u_v3, u, v3)
	feSqr(v4, v2)
	feMul(v7, v4, v3)
	feMul(x, u, v7)                     // x slot holds u*v^7 (input to pow)

	// ── Step 4: candidate root = u*v^3 * (u*v^7)^((p-5)/8) ───────────
	fePow_p58(x, x)
	feMul(x, x, u_v3)                   // candidate x

	// ── Step 5: verify v*x^2 ∈ {u, -u}, possibly apply sqrt(-1) ──────
	// Scratch in slots 0..6 (post-pow, freely usable; feIsZero internally
	// uses slot 0 which we clobber after each call).
	const x2:    i32 = FIELD_TMP_OFFSET + 1 * FIELD_TMP_STRIDE  // reused 'ONE' slot, fine to overwrite
	const vx2:   i32 = FIELD_TMP_OFFSET + 2 * FIELD_TMP_STRIDE
	const diff:  i32 = FIELD_TMP_OFFSET + 3 * FIELD_TMP_STRIDE
	const sum:   i32 = FIELD_TMP_OFFSET + 4 * FIELD_TMP_STRIDE
	const sM1:   i32 = FIELD_TMP_OFFSET + 5 * FIELD_TMP_STRIDE
	const xAlt:  i32 = FIELD_TMP_OFFSET + 6 * FIELD_TMP_STRIDE

	feSqr(x2, x)
	feMul(vx2, v, x2)

	// Inline equality / negated-equality: avoid feIsEqual's slot-15 scratch
	// because slot 15 is our live candidate x.
	feSub(diff, vx2, u)
	const eqU:  i32 = feIsZero(diff)
	feAdd(sum, vx2, u)
	const eqNU: i32 = feIsZero(sum)

	loadSqrtM1(sM1)
	feMul(xAlt, x, sM1)
	// Conditional move via feCondSwap: when eqNU, x receives xAlt (the
	// sqrt(-1)-multiplied candidate). This is a conditional move pattern,
	// not a true swap: the xAlt slot (slot 6) is dead after this line.
	// Step 6 reads only x, step 7 only the boolean flags, step 8 only x
	// and y, so the side effect of writing xAlt's slot is inert. Using
	// feCondSwap here saves a dedicated cmov helper.
	feCondSwap(x, xAlt, eqNU)

	// ── Step 6: apply sign bit per RFC 8032 §5.1.3 step 4 ────────────
	const xLsb: i32 = feIsNegative(x)
	const flip: i32 = xLsb ^ xSign
	feCondNeg(x, x, flip)

	// Spec edge case: if x = 0 and xSign = 1, decoding fails.
	const xIsZero: i32 = feIsZero(x)
	const zeroFail: i32 = xIsZero & xSign

	// ── Step 7: aggregate success flag ───────────────────────────────
	const sqRootOk: i32 = eqU | eqNU
	const success: i32 = canonical & sqRootOk & (1 ^ zeroFail)

	// ── Step 8: build extended-coord point (X = x, Y = y, Z = 1, T = x*y) ─
	memory.copy(out + X_OFF, x, 40)
	memory.copy(out + Y_OFF, y, 40)
	store<i64>(out + Z_OFF +  0, 1)
	store<i64>(out + Z_OFF +  8, 0)
	store<i64>(out + Z_OFF + 16, 0)
	store<i64>(out + Z_OFF + 24, 0)
	store<i64>(out + Z_OFF + 32, 0)
	feMul(out + T_OFF, x, y)

	return success
}
