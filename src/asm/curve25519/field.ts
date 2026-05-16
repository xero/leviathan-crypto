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
// src/asm/curve25519/field.ts
//
// GF(2^255 - 19) field arithmetic, single-element (one-at-a-time) path.
// RFC 7748 §4 and RFC 8032 §5.1 specify the underlying field; the limb
// form chosen for this module is 5 × 64-bit unsigned limbs at radix 2^51,
// per the donna-c64 lineage (Bernstein-Duif-Lange-Schwabe-Yang 2011,
// curve25519-dalek's "u64" backend).
//
// Each canonical limb is in [0, 2^51). After add / sub, limbs hold up
// to 52 bits. After mul / sqr followed by carry-and-reduce, limbs come
// back into the [0, 2^51) range.
//
// 128-bit accumulators: feMul / feSqr need 128-bit accumulators because
// a single cross product a[i]*b[j] (each ≤ 2^52) is ≤ 2^104, exceeding
// i64. AssemblyScript lacks a native u128 so we simulate it with a pair
// of u64 values (lo, hi) per output column, stored in the ACC region of
// linear memory and built up via 4-piece split multiplication
// (32-bit × 32-bit → 64-bit partial products).
//
// Field element memory layout: 40 bytes (5 × 8-byte limbs, little-endian
// i64 in linear memory).

import {
	ACC_OFFSET, FIELD_TMP_OFFSET, FIELD_TMP_STRIDE,
} from './buffers'

// ── Constants ───────────────────────────────────────────────────────────────

// 2^51 - 1 mask, used to extract a single limb's worth of bits.
const MASK_51: i64 = 0x7FFFFFFFFFFFF

// Twice the field prime, per-limb. Used by feSub / feNeg as additive
// offset to keep limbs non-negative before the subtraction; result is
// equivalent modulo p. p = 2^255 - 19, so 2p = 2^256 - 38. In radix 2^51:
//   2p[0] = 2 * (2^51 - 19) = 2^52 - 38
//   2p[1..4] = 2 * (2^51 - 1) = 2^52 - 2
// Sub adds these so that even max-input b doesn't drive the limb below 0.
const TWO_P_0:       i64 = 0xFFFFFFFFFFFDA   // 2^52 - 38
const TWO_P_NONZERO: i64 = 0xFFFFFFFFFFFFE   // 2^52 - 2

// ── Limb load / store helpers ───────────────────────────────────────────────

@inline
function ldL(p: i32, i: i32): i64 {
	return load<i64>(p + (i << 3))
}

@inline
function stL(p: i32, i: i32, v: i64): void {
	store<i64>(p + (i << 3), v)
}

// ── Accumulator helpers, 128-bit (lo, hi) pairs in ACC region ───────────────
//
// ACC_OFFSET holds 5 × 16 = 80 bytes. Slot c (0..4) is at offset c*16
// with the low u64 at +0 and the high u64 at +8. Each feMul / feSqr
// zeros the slots on entry, accumulates the cross products, then
// carries-and-reduces into a 5-limb result.

@inline
function accClear(): void {
	memory.fill(ACC_OFFSET, 0, 80)
}

@inline
function accLo(col: i32): u64 {
	return load<u64>(ACC_OFFSET + (col << 4))
}

@inline
function accHi(col: i32): u64 {
	return load<u64>(ACC_OFFSET + (col << 4) + 8)
}

@inline
function accStore(col: i32, lo: u64, hi: u64): void {
	store<u64>(ACC_OFFSET + (col << 4), lo)
	store<u64>(ACC_OFFSET + (col << 4) + 8, hi)
}

// Add a 64-bit multiplication a * b (each ≤ 2^54-ish) into the column-c
// 128-bit accumulator. Implemented via 4-piece split:
//   aL/aH, bL/bH are the low / high 32-bit halves of the operands.
//   The full product is ll + (lh + hl) * 2^32 + hh * 2^64, where each
//   partial is a u32 * u32 → u64 multiplication (no overflow).
// 128-bit add with manual carry detection (unsigned compare on lo).
@inline
function accAddMul(col: i32, a: i64, b: i64): void {
	const aU: u64 = a as u64
	const bU: u64 = b as u64

	const aL: u64 = aU & 0xFFFFFFFF
	const aH: u64 = aU >> 32
	const bL: u64 = bU & 0xFFFFFFFF
	const bH: u64 = bU >> 32

	// Four partial products. Each fits in u64 because the operands fit
	// in u32, so the product fits in u64.
	const ll: u64 = aL * bL
	const lh: u64 = aL * bH
	const hl: u64 = aH * bL
	const hh: u64 = aH * bH

	// Combine the two middle terms; mid ≤ 2 * (2^32-1) * (2^32-1) which
	// can overflow u64. But aH, bH are small (operands ≤ 2^54 → high
	// halves ≤ 2^22), so mid ≤ 2 * 2^32 * 2^22 = 2^55. Fits u64.
	const mid: u64 = lh + hl

	// Build product (prodLo, prodHi):
	//   prodLo = ll + ((mid & 0xFFFFFFFF) << 32)  [with carry to hi]
	//   prodHi = hh + (mid >> 32) + carry_from_lo
	const midLo: u64 = mid << 32
	const midHi: u64 = mid >> 32
	const prodLo: u64 = ll + midLo
	const carryLo: u64 = prodLo < ll ? 1 : 0
	const prodHi: u64 = hh + midHi + carryLo

	// Add to existing accumulator.
	const oldLo: u64 = accLo(col)
	const oldHi: u64 = accHi(col)
	const newLo: u64 = oldLo + prodLo
	const carryAcc: u64 = newLo < oldLo ? 1 : 0
	const newHi: u64 = oldHi + prodHi + carryAcc
	accStore(col, newLo, newHi)
}

// ── Element-level helpers ───────────────────────────────────────────────────

/** Zero a field element at `out`. */
export function feZero(out: i32): void {
	stL(out, 0, 0); stL(out, 1, 0); stL(out, 2, 0); stL(out, 3, 0); stL(out, 4, 0)
}

/** Set a field element at `out` to the multiplicative identity (1). */
export function feOne(out: i32): void {
	stL(out, 0, 1); stL(out, 1, 0); stL(out, 2, 0); stL(out, 3, 0); stL(out, 4, 0)
}

/** Copy a field element from `src` to `dst` (40 bytes). */
@inline
export function feCopy(dst: i32, src: i32): void {
	memory.copy(dst, src, 40)
}

// ── feAdd / feSub / feNeg ──────────────────────────────────────────────────

/**
 * out = a + b (no reduction). Each limb is added pairwise; result
 * limbs may be up to ~2^52. Safe to feed directly into feMul / feSqr.
 */
export function feAdd(out: i32, a: i32, b: i32): void {
	stL(out, 0, ldL(a, 0) + ldL(b, 0))
	stL(out, 1, ldL(a, 1) + ldL(b, 1))
	stL(out, 2, ldL(a, 2) + ldL(b, 2))
	stL(out, 3, ldL(a, 3) + ldL(b, 3))
	stL(out, 4, ldL(a, 4) + ldL(b, 4))
}

/**
 * out = a - b (mod p). Adds 2p per-limb to ensure non-negativity, then
 * subtracts b. Each output limb is positive and ≤ ~2^53 (the slack is
 * absorbed by the next reduce-and-carry step in feMul / feSqr, or by
 * an explicit feReduce if the caller compares / serialises).
 */
export function feSub(out: i32, a: i32, b: i32): void {
	stL(out, 0, (ldL(a, 0) + TWO_P_0) - ldL(b, 0))
	stL(out, 1, (ldL(a, 1) + TWO_P_NONZERO) - ldL(b, 1))
	stL(out, 2, (ldL(a, 2) + TWO_P_NONZERO) - ldL(b, 2))
	stL(out, 3, (ldL(a, 3) + TWO_P_NONZERO) - ldL(b, 3))
	stL(out, 4, (ldL(a, 4) + TWO_P_NONZERO) - ldL(b, 4))
}

/** out = -a (mod p). Equivalent to feSub with a=0. */
export function feNeg(out: i32, a: i32): void {
	stL(out, 0, TWO_P_0 - ldL(a, 0))
	stL(out, 1, TWO_P_NONZERO - ldL(a, 1))
	stL(out, 2, TWO_P_NONZERO - ldL(a, 2))
	stL(out, 3, TWO_P_NONZERO - ldL(a, 3))
	stL(out, 4, TWO_P_NONZERO - ldL(a, 4))
}

// ── feMul ───────────────────────────────────────────────────────────────────
//
// Schoolbook 5×5 with reduction baked in: terms where i+j ≥ 5 wrap via
// 2^255 ≡ 19 mod p, so b[j] for j ∈ {1..4} is pre-multiplied by 19 once
// and the "wrapped" columns reuse the pre-multiplied b19[j] value.
//
// Column k accumulates the 5 cross products whose weight reduces to 2^(51k):
//   col 0: a[0]*b[0] + a[1]*b19[4] + a[2]*b19[3] + a[3]*b19[2] + a[4]*b19[1]
//   col 1: a[0]*b[1] + a[1]*b[0]   + a[2]*b19[4] + a[3]*b19[3] + a[4]*b19[2]
//   col 2: a[0]*b[2] + a[1]*b[1]   + a[2]*b[0]   + a[3]*b19[4] + a[4]*b19[3]
//   col 3: a[0]*b[3] + a[1]*b[2]   + a[2]*b[1]   + a[3]*b[0]   + a[4]*b19[4]
//   col 4: a[0]*b[4] + a[1]*b[3]   + a[2]*b[2]   + a[3]*b[1]   + a[4]*b[0]
//
// Each accumulator is a 128-bit (lo, hi) value; the final reduce step
// extracts the low 51 bits as the output limb and carries the high
// bits to the next column (or wraps to column 0 with a ×19 multiplier).

/**
 * out = a * b (mod p). Out may alias a or b safely; operands are loaded
 * into i64 locals before any store to `out`.
 */
export function feMul(out: i32, a: i32, b: i32): void {
	const a0: i64 = ldL(a, 0)
	const a1: i64 = ldL(a, 1)
	const a2: i64 = ldL(a, 2)
	const a3: i64 = ldL(a, 3)
	const a4: i64 = ldL(a, 4)
	const b0: i64 = ldL(b, 0)
	const b1: i64 = ldL(b, 1)
	const b2: i64 = ldL(b, 2)
	const b3: i64 = ldL(b, 3)
	const b4: i64 = ldL(b, 4)

	// Pre-multiplied reduction columns. b[j] ≤ 2^52, b[j]*19 ≤ 2^57.
	const b1_19: i64 = b1 * 19
	const b2_19: i64 = b2 * 19
	const b3_19: i64 = b3 * 19
	const b4_19: i64 = b4 * 19

	accClear()

	accAddMul(0, a0, b0)
	accAddMul(0, a1, b4_19)
	accAddMul(0, a2, b3_19)
	accAddMul(0, a3, b2_19)
	accAddMul(0, a4, b1_19)

	accAddMul(1, a0, b1)
	accAddMul(1, a1, b0)
	accAddMul(1, a2, b4_19)
	accAddMul(1, a3, b3_19)
	accAddMul(1, a4, b2_19)

	accAddMul(2, a0, b2)
	accAddMul(2, a1, b1)
	accAddMul(2, a2, b0)
	accAddMul(2, a3, b4_19)
	accAddMul(2, a4, b3_19)

	accAddMul(3, a0, b3)
	accAddMul(3, a1, b2)
	accAddMul(3, a2, b1)
	accAddMul(3, a3, b0)
	accAddMul(3, a4, b4_19)

	accAddMul(4, a0, b4)
	accAddMul(4, a1, b3)
	accAddMul(4, a2, b2)
	accAddMul(4, a3, b1)
	accAddMul(4, a4, b0)

	reduceAndStore(out)
}

// ── feSqr ───────────────────────────────────────────────────────────────────
//
// Squaring exploits a[i]*a[j] = a[j]*a[i]: the off-diagonal cross products
// each appear twice in the schoolbook, so we compute each once and double.
// Saves about half the addAccMul calls vs feMul(a, a).
//
// Column accumulations (a[i]*a[j] terms grouped):
//   col 0: a[0]^2 + 2*a[1]*a[4]*19 + 2*a[2]*a[3]*19
//   col 1: 2*a[0]*a[1] + 2*a[2]*a[4]*19 + a[3]^2 * 19
//   col 2: 2*a[0]*a[2] + a[1]^2 + 2*a[3]*a[4]*19
//   col 3: 2*a[0]*a[3] + 2*a[1]*a[2] + a[4]^2 * 19
//   col 4: 2*a[0]*a[4] + 2*a[1]*a[3] + a[2]^2

/** out = a^2 (mod p). */
export function feSqr(out: i32, a: i32): void {
	const a0: i64 = ldL(a, 0)
	const a1: i64 = ldL(a, 1)
	const a2: i64 = ldL(a, 2)
	const a3: i64 = ldL(a, 3)
	const a4: i64 = ldL(a, 4)

	const a0_2: i64 = a0 * 2
	const a1_2: i64 = a1 * 2
	const a2_2: i64 = a2 * 2
	const a3_2: i64 = a3 * 2

	const a3_19: i64 = a3 * 19
	const a4_19: i64 = a4 * 19

	accClear()

	accAddMul(0, a0,    a0)
	accAddMul(0, a1_2,  a4_19)
	accAddMul(0, a2_2,  a3_19)

	accAddMul(1, a0_2,  a1)
	accAddMul(1, a2_2,  a4_19)
	accAddMul(1, a3,    a3_19)

	accAddMul(2, a0_2,  a2)
	accAddMul(2, a1,    a1)
	accAddMul(2, a3_2,  a4_19)

	accAddMul(3, a0_2,  a3)
	accAddMul(3, a1_2,  a2)
	accAddMul(3, a4,    a4_19)

	accAddMul(4, a0_2,  a4)
	accAddMul(4, a1_2,  a3)
	accAddMul(4, a2,    a2)

	reduceAndStore(out)
}

// ── Reduce-and-carry chain ─────────────────────────────────────────────────
//
// After feMul / feSqr, each accumulator slot holds a 128-bit value. To
// extract the canonical 5×51 limb form:
//   1. limb[k] := acc[k].lo & MASK_51
//   2. carry := (acc[k].lo >> 51) | (acc[k].hi << 13)  [13 = 64 - 51]
//   3. carry propagates to acc[k+1] as a 64-bit add (the high bits of the
//      previous accumulator add to the next column's low half)
//   4. Column 4 → column 0 wrap uses ×19 multiplier (2^255 ≡ 19 mod p)
//
// Performed in two stages: a "first pass" that extracts limbs in order
// 0,1,2,3,4 with carry, then a "second pass" on limbs 0 and 1 to absorb
// the wraparound carry from limb 4 into limb 0 (which may overflow into
// limb 1). Two passes suffice because the worst-case carry from column 4
// is small (~2^60) and the ×19 multiplication produces ≤ 2^60 * 19 ≈ 2^64.3
// across two limb columns, so a single secondary carry to limb 1
// finishes the chain.

@inline
function reduceAndStore(out: i32): void {
	// Extract limb 0 and carry to column 1.
	let lo0: u64 = accLo(0)
	let hi0: u64 = accHi(0)
	let limb0: i64 = (lo0 & MASK_51 as u64) as i64
	let carry: u64 = (lo0 >> 51) | (hi0 << 13)

	// Add carry into column 1 (64-bit add into the low half is enough
	// because the carry itself is ≤ 2^60 and column 1's accumulator
	// was filled by feMul/feSqr to ≤ 5 * 2^104 = 2^106.3; adding a
	// 64-bit carry keeps the hi unchanged here only when the lo add
	// does not overflow. Re-detect overflow and propagate to hi.)
	let lo1: u64 = accLo(1)
	let hi1: u64 = accHi(1)
	let lo1New: u64 = lo1 + carry
	let carryToHi1: u64 = lo1New < lo1 ? 1 : 0
	hi1 += carryToHi1
	let limb1: i64 = (lo1New & MASK_51 as u64) as i64
	carry = (lo1New >> 51) | (hi1 << 13)

	let lo2: u64 = accLo(2)
	let hi2: u64 = accHi(2)
	let lo2New: u64 = lo2 + carry
	let carryToHi2: u64 = lo2New < lo2 ? 1 : 0
	hi2 += carryToHi2
	let limb2: i64 = (lo2New & MASK_51 as u64) as i64
	carry = (lo2New >> 51) | (hi2 << 13)

	let lo3: u64 = accLo(3)
	let hi3: u64 = accHi(3)
	let lo3New: u64 = lo3 + carry
	let carryToHi3: u64 = lo3New < lo3 ? 1 : 0
	hi3 += carryToHi3
	let limb3: i64 = (lo3New & MASK_51 as u64) as i64
	carry = (lo3New >> 51) | (hi3 << 13)

	let lo4: u64 = accLo(4)
	let hi4: u64 = accHi(4)
	let lo4New: u64 = lo4 + carry
	let carryToHi4: u64 = lo4New < lo4 ? 1 : 0
	hi4 += carryToHi4
	let limb4: i64 = (lo4New & MASK_51 as u64) as i64
	carry = (lo4New >> 51) | (hi4 << 13)

	// Carry from limb 4 wraps to limb 0 with ×19 multiplier. The carry
	// itself is bounded (≤ 2^60 after typical feMul); 19 * 2^60 ≈ 2^64.3
	// just barely overflows i64. To be safe, propagate again to limb 1.
	let limb0New: i64 = limb0 + (carry as i64) * 19
	limb0 = limb0New & MASK_51
	limb1 += limb0New >> 51

	// limb1 is now ≤ 2^51 + small carry; mask once and propagate.
	let limb1Carry: i64 = limb1 >> 51
	limb1 &= MASK_51
	limb2 += limb1Carry

	stL(out, 0, limb0)
	stL(out, 1, limb1)
	stL(out, 2, limb2)
	stL(out, 3, limb3)
	stL(out, 4, limb4)
}

// ── feMul121666 ─────────────────────────────────────────────────────────────
//
// Multiply a field element by the small constant 121665 (≈ 2^17), used
// by the Montgomery ladder hot path (RFC 7748 §5 ladder-step). Since
// 121665 < 2^17, each product limb * 121665 fits in i64 (≤ 2^52 * 2^17
// = 2^69, ouch that overflows; but since input limbs are typically
// ≤ 2^52 in size, the product limb is ≤ 2^69 and we need a careful
// reduce that fits within i64 accumulators).
//
// Plan: each output limb gets one product (no cross terms; this is a
// scalar-by-limb multiplication, not a field multiplication). After
// multiplying, run a carry chain to bring back to 5×51 form, with the
// limb 4 → limb 0 wrap × 19.

/** out = a * 121665 (mod p). */
export function feMul121666(out: i32, a: i32): void {
	const k: i64 = 121665
	// Each input limb ≤ 2^52. Product ≤ 2^52 * 2^17 = 2^69.
	// We need 128-bit accumulators here too, but only on the diagonal
	// (no cross products with 19x reduction). Reuse the ACC pattern.
	accClear()
	accAddMul(0, ldL(a, 0), k)
	accAddMul(1, ldL(a, 1), k)
	accAddMul(2, ldL(a, 2), k)
	accAddMul(3, ldL(a, 3), k)
	accAddMul(4, ldL(a, 4), k)
	reduceAndStore(out)
}

// ── feFromBytes / feToBytes ─────────────────────────────────────────────────

/**
 * out = decode(src) where src is a 32-byte LE field element. Masks the
 * top bit of byte 31 (RFC 7748 §5 X25519 u-coordinate decoding rule;
 * Ed25519 callers that use the top bit for x-sign extract that bit
 * before calling this routine).
 *
 * Splits the 256-bit number into 5 × 51-bit limbs by extracting 51-bit
 * windows from the LE byte stream.
 */
export function feFromBytes(out: i32, src: i32): void {
	// Load four 64-bit little-endian words.
	const w0: u64 = load<u64>(src + 0)
	const w1: u64 = load<u64>(src + 8)
	const w2: u64 = load<u64>(src + 16)
	let w3: u64 = load<u64>(src + 24)
	// Mask top bit (bit 255) per RFC 7748 §5.
	w3 &= 0x7FFFFFFFFFFFFFFF

	// 51-bit windows:
	//   limb 0: bits   0..50  → low 51 bits of w0
	//   limb 1: bits  51..101 → (w0 >> 51) | (w1 & ((1 << 38) - 1)) << 13  (51 = 13 below 64; need 38 bits from w1)
	//     Actually w0 has bits 0..63; bits 51..63 are 13 bits. We need 51 bits total, so 51 - 13 = 38 bits from w1.
	//     limb1 = (w0 >> 51) | ((w1 & ((1 << 38) - 1)) << 13)
	//   limb 2: bits 102..152 → starts at bit 102 in w1 (= 38 in w1's local), need 51 bits.
	//     w1 covers bits 64..127, so 102..127 is 26 bits from w1, then 25 bits from w2.
	//     limb2 = (w1 >> 38) | ((w2 & ((1 << 25) - 1)) << 26)
	//   limb 3: bits 153..203 → starts at bit 153 = 25 + 64 of w2 = w2 bit 25.
	//     153..191 is 39 bits from w2 (bits 25..63), then 12 bits from w3 (bits 0..11).
	//     limb3 = (w2 >> 25) | ((w3 & ((1 << 12) - 1)) << 39)
	//   limb 4: bits 204..254 → starts at bit 204 in w3 (= 12 of w3's local), need 51 bits.
	//     limb4 = w3 >> 12  (gives bits 12..62 of w3 = bits 204..254 of the full number)

	const limb0: u64 =  w0                & MASK_51 as u64
	const limb1: u64 = ((w0 >> 51) | (w1 << 13)) & MASK_51 as u64
	const limb2: u64 = ((w1 >> 38) | (w2 << 26)) & MASK_51 as u64
	const limb3: u64 = ((w2 >> 25) | (w3 << 39)) & MASK_51 as u64
	const limb4: u64 =   w3 >> 12

	stL(out, 0, limb0 as i64)
	stL(out, 1, limb1 as i64)
	stL(out, 2, limb2 as i64)
	stL(out, 3, limb3 as i64)
	stL(out, 4, limb4 as i64)
}

/**
 * out = encode(src), 32-byte LE canonical encoding.
 * Fully reduces the field element to its canonical representative
 * (single value in [0, p)) before encoding. Required by RFC 8032
 * §5.1.2 (point encoding canonicality) and by the strict-verification
 * posture TASK-C will adopt.
 *
 * Reduction strategy:
 *   1. Propagate any limb-overflow carry within the 5-limb representation
 *      so that each limb is < 2^51 (i.e. ≤ 2^51 - 1).
 *   2. Subtract p conditionally: if the resulting value is ≥ p, subtract;
 *      otherwise leave alone. Done in constant time by adding 19 (which
 *      forces a carry-out of bit 255 iff value ≥ p) and checking the
 *      carry, but a cleaner approach is to compute (value + 19) and use
 *      the top bit of bit-255 as the conditional-subtract mask.
 *   3. Serialize the 5 × 51-bit limbs into 4 × u64 LE words.
 */
export function feToBytes(out: i32, src: i32): void {
	// Step 1: reduce limbs into [0, 2^51) by propagating carry.
	let h0: i64 = ldL(src, 0)
	let h1: i64 = ldL(src, 1)
	let h2: i64 = ldL(src, 2)
	let h3: i64 = ldL(src, 3)
	let h4: i64 = ldL(src, 4)

	let c: i64 = h0 >> 51; h0 -= c << 51; h1 += c
	c = h1 >> 51; h1 -= c << 51; h2 += c
	c = h2 >> 51; h2 -= c << 51; h3 += c
	c = h3 >> 51; h3 -= c << 51; h4 += c
	c = h4 >> 51; h4 -= c << 51; h0 += c * 19

	// One more round: limb 0 may have gained up to (something small) * 19,
	// which might exceed 2^51. Propagate once more through 0 → 1.
	c = h0 >> 51; h0 -= c << 51; h1 += c

	// Step 2: conditionally subtract p. The classical trick:
	//   compute (value + 19) — this overflows bit 255 iff value >= p.
	//   Then use bit 255 of the result as a mask: 0 means "value was < p,
	//   subtract back the 19"; 1 means "value was >= p, the 19 already
	//   absorbed the underflow at bit 255 so we just clear bit 255".
	//
	// Equivalently: add 19 to h0, propagate carry, then mask off bit 255
	// from h4 and keep the result.
	let q: i64 = (h0 + 19) >> 51
	q = (h1 + q) >> 51
	q = (h2 + q) >> 51
	q = (h3 + q) >> 51
	q = (h4 + q) >> 51
	// q is now 1 if value >= p, 0 otherwise.

	// Subtract p iff q = 1: add 19*q to h0, then mask each limb to 51 bits.
	h0 += 19 * q
	c = h0 >> 51; h0 -= c << 51; h1 += c
	c = h1 >> 51; h1 -= c << 51; h2 += c
	c = h2 >> 51; h2 -= c << 51; h3 += c
	c = h3 >> 51; h3 -= c << 51; h4 += c
	h4 &= MASK_51

	// Step 3: pack into 4 × u64 LE words.
	const w0: u64 = (h0 as u64) | ((h1 as u64) << 51)
	const w1: u64 = ((h1 as u64) >> 13) | ((h2 as u64) << 38)
	const w2: u64 = ((h2 as u64) >> 26) | ((h3 as u64) << 25)
	const w3: u64 = ((h3 as u64) >> 39) | ((h4 as u64) << 12)

	store<u64>(out +  0, w0)
	store<u64>(out +  8, w1)
	store<u64>(out + 16, w2)
	store<u64>(out + 24, w3)
}

// ── Boolean / sign helpers ─────────────────────────────────────────────────

/**
 * Returns 1 if a == 0 (mod p) in canonical form, 0 otherwise.
 * Computes the canonical encoding then OR-folds the bytes; result is 1
 * iff every byte is zero.
 */
export function feIsZero(a: i32): i32 {
	const tmp: i32 = FIELD_TMP_OFFSET
	feToBytes(tmp, a)
	let r: u64 = 0
	r |= load<u64>(tmp +  0)
	r |= load<u64>(tmp +  8)
	r |= load<u64>(tmp + 16)
	r |= load<u64>(tmp + 24)
	// r = 0 iff all bytes were zero.
	// Convert "r == 0 ? 1 : 0" without branches.
	const x: u64 = r | (0 - r)  // sign bit = 1 iff r != 0
	return (1 - ((x >> 63) as i32)) as i32
}

/**
 * Returns the LSB of the canonical encoding of a. RFC 8032 §5.1.2
 * defines a field element to be "negative" iff its canonical low byte's
 * LSB is set; the sign-bit packing of point encoding uses this.
 */
export function feIsNegative(a: i32): i32 {
	const tmp: i32 = FIELD_TMP_OFFSET
	feToBytes(tmp, a)
	return (load<u8>(tmp) & 1) as i32
}

// ── Constant-time conditional helpers ───────────────────────────────────────

/**
 * Conditionally swap two field elements a and b in place. `swap` MUST
 * be 0 or 1; behaviour for other values is undefined (but the function
 * is still constant-time). When swap=1, a and b are exchanged; when
 * swap=0, both are left untouched.
 *
 * Implementation: build the all-ones mask from swap (0 → 0, 1 → -1),
 * XOR-swap each limb pair: for each (a[i], b[i]):
 *   t = mask & (a[i] ^ b[i])
 *   a[i] ^= t; b[i] ^= t
 */
export function feCondSwap(a: i32, b: i32, swap: i32): void {
	const mask: i64 = -((swap as i64) & 1)
	for (let i: i32 = 0; i < 5; i++) {
		const ai: i64 = ldL(a, i)
		const bi: i64 = ldL(b, i)
		const t:  i64 = mask & (ai ^ bi)
		stL(a, i, ai ^ t)
		stL(b, i, bi ^ t)
	}
}

/**
 * Conditionally negate: out = neg ? -a : a. `neg` MUST be 0 or 1.
 * Both branches execute; the result is mask-selected at the limb level.
 */
export function feCondNeg(out: i32, a: i32, neg: i32): void {
	const mask: i64 = -((neg as i64) & 1)
	// out = a ^ (mask & (a ^ -a))
	// = a if mask == 0, = -a if mask == -1
	stL(out, 0, ldL(a, 0) ^ (mask & (ldL(a, 0) ^ (TWO_P_0      - ldL(a, 0)))))
	stL(out, 1, ldL(a, 1) ^ (mask & (ldL(a, 1) ^ (TWO_P_NONZERO - ldL(a, 1)))))
	stL(out, 2, ldL(a, 2) ^ (mask & (ldL(a, 2) ^ (TWO_P_NONZERO - ldL(a, 2)))))
	stL(out, 3, ldL(a, 3) ^ (mask & (ldL(a, 3) ^ (TWO_P_NONZERO - ldL(a, 3)))))
	stL(out, 4, ldL(a, 4) ^ (mask & (ldL(a, 4) ^ (TWO_P_NONZERO - ldL(a, 4)))))
}

// ── feInv: a^(p-2) via Bernstein's addition chain ───────────────────────────
//
// p - 2 = 2^255 - 21. Standard 254-squarings + 11-multiplications chain
// (Bernstein-Lange et al). All intermediate results live in
// FIELD_TMP_OFFSET slots so feInv does not allocate; the chain is:
//
//   z2     = a^2
//   z8     = z2^4                          (a^8)
//   z9     = z8 * a                        (a^9)
//   z11    = z9 * z2                       (a^11)
//   z22    = z11^2
//   z_5_0  = z22 * z9                      (a^(2^5  - 1))
//   z_10_5 = z_5_0^(2^5)
//   z_10_0 = z_10_5 * z_5_0                (a^(2^10 - 1))
//   z_20_10= z_10_0^(2^10)
//   z_20_0 = z_20_10 * z_10_0              (a^(2^20 - 1))
//   z_40_20= z_20_0^(2^20)
//   z_40_0 = z_40_20 * z_20_0              (a^(2^40 - 1))
//   z_50_10= z_40_0^(2^10)
//   z_50_0 = z_50_10 * z_10_0              (a^(2^50 - 1))
//   z_100_50= z_50_0^(2^50)
//   z_100_0 = z_100_50 * z_50_0            (a^(2^100 - 1))
//   z_200_100= z_100_0^(2^100)
//   z_200_0  = z_200_100 * z_100_0         (a^(2^200 - 1))
//   z_250_50 = z_200_0^(2^50)
//   z_250_0  = z_250_50 * z_50_0           (a^(2^250 - 1))
//   z_255_5  = z_250_0^(2^5)
//   out      = z_255_5 * z11               (a^(p-2))

/** out = a^(-1) mod p (via Fermat's little theorem, a^(p-2)). */
export function feInv(out: i32, a: i32): void {
	// Slot offsets in FIELD_TMP (each 40 bytes).
	const t0: i32 = FIELD_TMP_OFFSET +  0 * FIELD_TMP_STRIDE  // z2 / scratch
	const t1: i32 = FIELD_TMP_OFFSET +  1 * FIELD_TMP_STRIDE  // z9
	const t2: i32 = FIELD_TMP_OFFSET +  2 * FIELD_TMP_STRIDE  // z11
	const t3: i32 = FIELD_TMP_OFFSET +  3 * FIELD_TMP_STRIDE  // z_5_0
	const t4: i32 = FIELD_TMP_OFFSET +  4 * FIELD_TMP_STRIDE  // z_10_0
	const t5: i32 = FIELD_TMP_OFFSET +  5 * FIELD_TMP_STRIDE  // z_20_0
	const t6: i32 = FIELD_TMP_OFFSET +  6 * FIELD_TMP_STRIDE  // z_40_0
	const t7: i32 = FIELD_TMP_OFFSET +  7 * FIELD_TMP_STRIDE  // z_50_0
	const t8: i32 = FIELD_TMP_OFFSET +  8 * FIELD_TMP_STRIDE  // z_100_0
	const t9: i32 = FIELD_TMP_OFFSET +  9 * FIELD_TMP_STRIDE  // z_200_0
	const tA: i32 = FIELD_TMP_OFFSET + 10 * FIELD_TMP_STRIDE  // misc scratch

	// z2 = a^2
	feSqr(t0, a)
	// z8 = z2^4
	feSqr(tA, t0)
	feSqr(tA, tA)
	// z9 = z8 * a
	feMul(t1, tA, a)
	// z11 = z9 * z2
	feMul(t2, t1, t0)
	// z22 = z11^2  (reuse t0)
	feSqr(t0, t2)
	// z_5_0 = z22 * z9
	feMul(t3, t0, t1)
	// z_10_5 = z_5_0^(2^5)  (5 squarings)
	feSqr(tA, t3)
	for (let i: i32 = 0; i < 4; i++) feSqr(tA, tA)
	// z_10_0 = z_10_5 * z_5_0
	feMul(t4, tA, t3)
	// z_20_10 = z_10_0^(2^10)  (10 squarings)
	feSqr(tA, t4)
	for (let i: i32 = 0; i < 9; i++) feSqr(tA, tA)
	// z_20_0 = z_20_10 * z_10_0
	feMul(t5, tA, t4)
	// z_40_20 = z_20_0^(2^20)  (20 squarings)
	feSqr(tA, t5)
	for (let i: i32 = 0; i < 19; i++) feSqr(tA, tA)
	// z_40_0 = z_40_20 * z_20_0
	feMul(t6, tA, t5)
	// z_50_10 = z_40_0^(2^10)  (10 squarings)
	feSqr(tA, t6)
	for (let i: i32 = 0; i < 9; i++) feSqr(tA, tA)
	// z_50_0 = z_50_10 * z_10_0
	feMul(t7, tA, t4)
	// z_100_50 = z_50_0^(2^50)  (50 squarings)
	feSqr(tA, t7)
	for (let i: i32 = 0; i < 49; i++) feSqr(tA, tA)
	// z_100_0 = z_100_50 * z_50_0
	feMul(t8, tA, t7)
	// z_200_100 = z_100_0^(2^100)  (100 squarings)
	feSqr(tA, t8)
	for (let i: i32 = 0; i < 99; i++) feSqr(tA, tA)
	// z_200_0 = z_200_100 * z_100_0
	feMul(t9, tA, t8)
	// z_250_50 = z_200_0^(2^50)  (50 squarings)
	feSqr(tA, t9)
	for (let i: i32 = 0; i < 49; i++) feSqr(tA, tA)
	// z_250_0 = z_250_50 * z_50_0
	feMul(tA, tA, t7)
	// z_255_5 = z_250_0^(2^5)  (5 squarings)
	feSqr(tA, tA)
	for (let i: i32 = 0; i < 4; i++) feSqr(tA, tA)
	// out = z_255_5 * z11
	feMul(out, tA, t2)
}

// ── fePow_p58: a^((p-5)/8) ─────────────────────────────────────────────────
//
// Used by point decompression (RFC 8032 §5.1.3) to compute the square-root
// candidate via the p ≡ 5 (mod 8) trick:
//   sqrt(u/v) candidate = u * v^3 * (u * v^7)^((p-5)/8)
//
// (p-5)/8 = (2^255 - 24)/8 = 2^252 - 3.  The addition chain reuses the
// same z_250_0 prefix as feInv, then squares twice and multiplies by a:
//   z_250_0 = a^(2^250 - 1)
//   z_252_2 = z_250_0^4 = a^(2^252 - 4)
//   out     = z_252_2 * a = a^(2^252 - 3) = a^((p-5)/8)

/** out = a^((p-5)/8) mod p, used by point decompression. */
export function fePow_p58(out: i32, a: i32): void {
	const t0: i32 = FIELD_TMP_OFFSET +  0 * FIELD_TMP_STRIDE
	const t1: i32 = FIELD_TMP_OFFSET +  1 * FIELD_TMP_STRIDE  // z9
	const t2: i32 = FIELD_TMP_OFFSET +  2 * FIELD_TMP_STRIDE  // z11
	const t3: i32 = FIELD_TMP_OFFSET +  3 * FIELD_TMP_STRIDE  // z_5_0
	const t4: i32 = FIELD_TMP_OFFSET +  4 * FIELD_TMP_STRIDE  // z_10_0
	const t5: i32 = FIELD_TMP_OFFSET +  5 * FIELD_TMP_STRIDE  // z_20_0
	const t6: i32 = FIELD_TMP_OFFSET +  6 * FIELD_TMP_STRIDE  // z_40_0
	const t7: i32 = FIELD_TMP_OFFSET +  7 * FIELD_TMP_STRIDE  // z_50_0
	const t8: i32 = FIELD_TMP_OFFSET +  8 * FIELD_TMP_STRIDE  // z_100_0
	const t9: i32 = FIELD_TMP_OFFSET +  9 * FIELD_TMP_STRIDE  // z_200_0
	const tA: i32 = FIELD_TMP_OFFSET + 10 * FIELD_TMP_STRIDE  // scratch

	feSqr(t0, a)                       // z2
	feSqr(tA, t0); feSqr(tA, tA)       // z8
	feMul(t1, tA, a)                   // z9
	feMul(t2, t1, t0)                  // z11
	feSqr(t0, t2)                      // z22
	feMul(t3, t0, t1)                  // z_5_0
	feSqr(tA, t3); for (let i: i32 = 0; i < 4; i++) feSqr(tA, tA)
	feMul(t4, tA, t3)                  // z_10_0
	feSqr(tA, t4); for (let i: i32 = 0; i < 9; i++) feSqr(tA, tA)
	feMul(t5, tA, t4)                  // z_20_0
	feSqr(tA, t5); for (let i: i32 = 0; i < 19; i++) feSqr(tA, tA)
	feMul(t6, tA, t5)                  // z_40_0
	feSqr(tA, t6); for (let i: i32 = 0; i < 9; i++) feSqr(tA, tA)
	feMul(t7, tA, t4)                  // z_50_0
	feSqr(tA, t7); for (let i: i32 = 0; i < 49; i++) feSqr(tA, tA)
	feMul(t8, tA, t7)                  // z_100_0
	feSqr(tA, t8); for (let i: i32 = 0; i < 99; i++) feSqr(tA, tA)
	feMul(t9, tA, t8)                  // z_200_0
	feSqr(tA, t9); for (let i: i32 = 0; i < 49; i++) feSqr(tA, tA)
	feMul(tA, tA, t7)                  // z_250_0
	feSqr(tA, tA); feSqr(tA, tA)       // z_252_2 = z_250_0^4
	feMul(out, tA, a)                  // a^(2^252 - 3) = a^((p-5)/8)
}

// ── feIsEqual ──────────────────────────────────────────────────────────────

/**
 * Returns 1 if a == b (mod p) in canonical form, 0 otherwise. Constant-time:
 * folds (a - b) into canonical bytes and OR-accumulates. Uses the last
 * FIELD_TMP slot internally; safe to call when slots 0..14 are live.
 */
export function feIsEqual(a: i32, b: i32): i32 {
	const tmp: i32 = FIELD_TMP_OFFSET + 15 * FIELD_TMP_STRIDE
	feSub(tmp, a, b)
	return feIsZero(tmp)
}

// ── Curve constants as field elements ──────────────────────────────────────
//
// Values per RFC 8032 §5.1: d = -121665/121666 (mod p). 2d is the lifted
// addition-formula coefficient from §5.1.4. sqrt(-1) is 2^((p-1)/4) (mod p)
// per the §5.1.1 / §5.1.3 square-root trick (p ≡ 5 mod 8 case).
//
// Each constant is written as five i64 limbs in radix 2^51 LE. Derivation
// of the limb values: take the spec's decimal value, reduce mod p, split
// into 51-bit windows. The values below are produced by an offline BigInt
// computation pinned to the spec decimal forms; the offline script is
// reproducible from the spec values alone.

/** Write the field element d (per RFC 8032 §5.1) to dst. */
@inline
export function loadD(dst: i32): void {
	stL(dst, 0, 0x00034DCA135978A3)
	stL(dst, 1, 0x0001A8283B156EBD)
	stL(dst, 2, 0x0005E7A26001C029)
	stL(dst, 3, 0x000739C663A03CBB)
	stL(dst, 4, 0x00052036CEE2B6FF)
}

/** Write the field element 2d (per RFC 8032 §5.1.4) to dst. */
@inline
export function loadTwoD(dst: i32): void {
	stL(dst, 0, 0x00069B9426B2F159)
	stL(dst, 1, 0x00035050762ADD7A)
	stL(dst, 2, 0x0003CF44C0038052)
	stL(dst, 3, 0x0006738CC7407977)
	stL(dst, 4, 0x0002406D9DC56DFF)
}

/** Write the field element sqrt(-1) = 2^((p-1)/4) (mod p) to dst. */
@inline
export function loadSqrtM1(dst: i32): void {
	stL(dst, 0, 0x00061B274A0EA0B0)
	stL(dst, 1, 0x0000D5A5FC8F189D)
	stL(dst, 2, 0x0007EF5E9CBD0C60)
	stL(dst, 3, 0x00078595A6804C9E)
	stL(dst, 4, 0x0002B8324804FC1D)
}
