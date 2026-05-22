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
// src/asm/p256/field.ts
//
// GF(p256) field arithmetic, where p256 is the prime from
// NIST SP 800-186 §3.2.1.3:
//
//   p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//     = ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
//       (32 hex digits per row, MSB on the left, matching the SP 800-186 table)
//
// Limb form: 8 × u32 at radix 2^32, saturated. limb[0] is the LSB
// (little-endian limb order in linear memory). 32 bytes per element.
//
// Byte order: feFromBytes / feToBytes convert between the 32-byte BIG-
// endian wire form (FIPS 186-5 §6, SEC1 §2.3.3 / §2.3.6) and the
// internal LE limb form. P-256 spec encoding is big-endian; the WASM
// internal form is little-endian-limb for arithmetic convenience.
//
// Constant-time discipline: fixed-length loops + mask-driven selects.
// No branches on secret limbs, no early returns.
//
// Non-Montgomery domain (locked). Natural field domain;
// feFromBytes / feToBytes are radix conversions. Rationale and
// RustCrypto comparison: docs/asm_p256.md#representation-choice.
//
// Reduction reference: HMV §2.4.1 Algorithm 2.27 ("Fast reduction
// modulo p256"). 16 × u32 product → 9 candidate 8 × u32 terms s1..s9,
// summed / subtracted per the prime's Solinas structure. Per-term
// aliasing cited inline at the feReduce site.

import {
	FIELD_TMP, FIELD_TMP_STRIDE,
	MUL_INT_LO,
} from './buffers'

// ── Constants: p256, R = 2^256 mod p, helper masks ──────────────────────────
//
// Inline u32 limb values per SP 800-186 §3.2.1.3:
//
//   p256 (LE limbs, limb[0] is the LSB):
//     P0 = 0xFFFFFFFF, P1 = 0xFFFFFFFF, P2 = 0xFFFFFFFF, P3 = 0x00000000,
//     P4 = 0x00000000, P5 = 0x00000000, P6 = 0x00000001, P7 = 0xFFFFFFFF
//
// Derivation reproducible from the SP 800-186 hex form:
//   p256 = ffffffff00000001000000000000000000000000ffffffffffffffffffffffff
//   Split into 8 BE words (MSB to LSB):
//     ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
//   Reverse to LE limb order:
//     limb[0]=ffffffff, limb[1]=ffffffff, limb[2]=ffffffff, limb[3]=00000000,
//     limb[4]=00000000, limb[5]=00000000, limb[6]=00000001, limb[7]=ffffffff

const P0: u32 = 0xFFFFFFFF
const P1: u32 = 0xFFFFFFFF
const P2: u32 = 0xFFFFFFFF
const P3: u32 = 0x00000000
const P4: u32 = 0x00000000
const P5: u32 = 0x00000000
const P6: u32 = 0x00000001
const P7: u32 = 0xFFFFFFFF

// ── Limb load / store helpers ───────────────────────────────────────────────

@inline
function ld(p: i32, i: i32): u32 {
	return load<u32>(p + (i << 2))
}

@inline
function st(p: i32, i: i32, v: u32): void {
	store<u32>(p + (i << 2), v)
}

// ── Element-level helpers ───────────────────────────────────────────────────

/** Zero a field element at `out` (32 bytes). */
export function feZero(out: i32): void {
	memory.fill(out, 0, 32)
}

/** Set a field element at `out` to the multiplicative identity (1). */
export function feOne(out: i32): void {
	st(out, 0, 1)
	st(out, 1, 0); st(out, 2, 0); st(out, 3, 0)
	st(out, 4, 0); st(out, 5, 0); st(out, 6, 0); st(out, 7, 0)
}

/** Copy a field element from `src` to `dst` (32 bytes). */
@inline
export function feCopy(dst: i32, src: i32): void {
	memory.copy(dst, src, 32)
}

// ── feFromBytes / feToBytes (32-byte big-endian wire form) ──────────────────

/**
 * out = decode(src), where src is 32 bytes BIG-endian per FIPS 186-5 /
 * SEC1. Reverses byte order while packing into 8 LE u32 limbs.
 *
 * NOTE: does not reduce mod p. Callers that feed an unreduced value
 * (e.g. a raw scalar that may exceed p) must follow with feReduce.
 * The signature-time call site reads the secret scalar d and assumes
 * d ∈ [1, n-1], which is < p (n < p for P-256), so the raw bytes
 * already represent a canonical field element.
 */
export function feFromBytes(out: i32, src: i32): void {
	// limb[i] = bytes at offsets [28-4i .. 31-4i] interpreted big-endian.
	for (let i: i32 = 0; i < 8; i++) {
		const byteBase: i32 = src + 28 - (i << 2)
		const v: u32 =
			((load<u8>(byteBase    ) as u32) << 24) |
			((load<u8>(byteBase + 1) as u32) << 16) |
			((load<u8>(byteBase + 2) as u32) <<  8) |
			 (load<u8>(byteBase + 3) as u32)
		st(out, i, v)
	}
}

/**
 * out = encode(src), 32-byte BIG-endian canonical encoding. Caller
 * must ensure src is fully reduced (limbs < p256). The arithmetic
 * routines (feAdd / feSub / feMul / feSqr) all return canonical
 * limb form (< p) so this contract is normally automatic; the only
 * non-canonical inputs come from feFromBytes on adversarial wire data,
 * which is rare and the verify-path strict-gate handles separately.
 */
export function feToBytes(out: i32, src: i32): void {
	for (let i: i32 = 0; i < 8; i++) {
		const v: u32 = ld(src, i)
		const byteBase: i32 = out + 28 - (i << 2)
		store<u8>(byteBase,     ((v >> 24) & 0xff) as u8)
		store<u8>(byteBase + 1, ((v >> 16) & 0xff) as u8)
		store<u8>(byteBase + 2, ((v >>  8) & 0xff) as u8)
		store<u8>(byteBase + 3,  (v        & 0xff) as u8)
	}
}

// ── Internal: 9-limb sum / subtract helpers ────────────────────────────────
// Solinas per-term arithmetic can spill one bit above 8 limbs (2 * p256
// < 2^257); 9-limb form is 8 u32 limbs + 1 u32 carry, 36 bytes total in
// FIELD_TMP / the 9-limb scratch region below.

@inline
function add8(out: i32, a: i32, b: i32): u32 {
	// out = a + b, returns final carry-out (0 or 1).
	let carry: u32 = 0
	for (let i: i32 = 0; i < 8; i++) {
		const ai: u64 = ld(a, i) as u64
		const bi: u64 = ld(b, i) as u64
		const s:  u64 = ai + bi + (carry as u64)
		st(out, i, s as u32)
		carry = (s >> 32) as u32
	}
	return carry
}

@inline
function sub8(out: i32, a: i32, b: i32): u32 {
	// out = a - b, returns final borrow (0 or 1).
	let borrow: u32 = 0
	for (let i: i32 = 0; i < 8; i++) {
		const ai: i64 = ld(a, i) as i64
		const bi: i64 = ld(b, i) as i64
		const d:  i64 = ai - bi - (borrow as i64)
		st(out, i, (d as u32))
		borrow = ((d >> 63) & 1) as u32
	}
	return borrow
}

// Build P in `dst` (8 limbs). Inline so the constants stay symbolic at
// the call site rather than living in linear memory.
@inline
function loadP(dst: i32): void {
	st(dst, 0, P0); st(dst, 1, P1); st(dst, 2, P2); st(dst, 3, P3)
	st(dst, 4, P4); st(dst, 5, P5); st(dst, 6, P6); st(dst, 7, P7)
}

// ── feAdd / feSub / feNeg / feHalve ────────────────────────────────────────

/**
 * out = a + b (mod p). The sum may overflow the 8-limb representation
 * by one bit; conditionally subtract p once. The condition is
 * (carry == 1) OR (a + b >= p), evaluated constant-time.
 */
export function feAdd(out: i32, a: i32, b: i32): void {
	const sumBuf: i32 = FIELD_TMP + 0 * FIELD_TMP_STRIDE
	const carry: u32 = add8(sumBuf, a, b)

	// Check if sumBuf >= p: compute (sumBuf - p), if no borrow then sumBuf >= p.
	const pBuf: i32 = FIELD_TMP + 1 * FIELD_TMP_STRIDE
	loadP(pBuf)
	const minusP: i32 = FIELD_TMP + 2 * FIELD_TMP_STRIDE
	const borrow: u32 = sub8(minusP, sumBuf, pBuf)
	// Need to subtract if carry == 1 (sum overflowed 8 limbs, so sum >= 2^256 > p)
	// OR if borrow == 0 (sumBuf >= p).
	// cond = carry | (1 - borrow)
	const cond: u32 = carry | ((1 - borrow) as u32 & 1)
	const mask: u32 = ((-(cond as i32)) as u32)
	for (let i: i32 = 0; i < 8; i++) {
		const va: u32 = ld(minusP,  i)
		const vb: u32 = ld(sumBuf,  i)
		st(out, i, (va & mask) | (vb & ~mask))
	}
}

/**
 * out = a - b (mod p). If a < b, add p to make the result non-negative.
 * Constant-time: always compute both (a - b) and (a - b + p), select
 * the correct one via the borrow mask.
 */
export function feSub(out: i32, a: i32, b: i32): void {
	const diffBuf: i32 = FIELD_TMP + 3 * FIELD_TMP_STRIDE
	const borrow: u32 = sub8(diffBuf, a, b)

	const pBuf: i32 = FIELD_TMP + 4 * FIELD_TMP_STRIDE
	loadP(pBuf)
	const corrBuf: i32 = FIELD_TMP + 5 * FIELD_TMP_STRIDE
	add8(corrBuf, diffBuf, pBuf)  // diffBuf + p, ignore final carry (cancels with borrow)

	// If borrow == 1, use corrBuf; else use diffBuf.
	const mask: u32 = ((-(borrow as i32)) as u32)
	for (let i: i32 = 0; i < 8; i++) {
		const va: u32 = ld(corrBuf, i)
		const vb: u32 = ld(diffBuf, i)
		st(out, i, (va & mask) | (vb & ~mask))
	}
}

/** out = -a (mod p). Equivalent to feSub with a = 0. */
export function feNeg(out: i32, a: i32): void {
	const zeroBuf: i32 = FIELD_TMP + 6 * FIELD_TMP_STRIDE
	memory.fill(zeroBuf, 0, 32)
	feSub(out, zeroBuf, a)
}

// ── feMul ───────────────────────────────────────────────────────────────────
//
// Step 1: 8×8 schoolbook into MUL_INT_LO (low 8) || MUL_INT_HI (high 8).
// Step 2: Solinas reduction, HMV §2.4.1 Algorithm 2.27.
//
//   s1 = (c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0 )
//   s2 = ( 0,  c11, c10, c9,  c8,  0,   0,   0  )
//   s3 = ( 0,  c12, c11, c10, c9,  0,   0,   0  )
//   s4 = (c8,  c11, c10, c9,  c14, c13, c12, c15)
//   s5 = (c10, c8,  c15, c14, c13, c12, c11, c9 )
//   s6 = (c11, c9,  0,   0,   c15, c14, c13, c12)
//   s7 = (c12, 0,   c10, c9,  c8,  c15, c14, c13)
//   s8 = (c13, 0,   c11, c10, c9,  0,   c15, c14)
//   s9 = (c13, 0,   c10, c9,  c8,  0,   c14, c15)
//
//   r = s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9 (mod p)
//
// k = 4 mod-p corrections (worst-case +s coefficient); applied
// via condSub9IfGe.

/**
 * out = a * b (mod p). Out may alias a or b safely; operands are read
 * into the multiplication intermediate before any store to `out`.
 */
export function feMul(out: i32, a: i32, b: i32): void {
	// Step 1: 8x8 schoolbook into MUL_INT_LO || MUL_INT_HI (16 × u32).
	memory.fill(MUL_INT_LO, 0, 64)
	for (let i: i32 = 0; i < 8; i++) {
		const ai: u64 = ld(a, i) as u64
		let carry: u64 = 0
		for (let j: i32 = 0; j < 8; j++) {
			const bj: u64 = ld(b, j) as u64
			const pij: u64 = load<u32>(MUL_INT_LO + ((i + j) << 2)) as u64
			const t: u64 = pij + ai * bj + carry
			store<u32>(MUL_INT_LO + ((i + j) << 2), t as u32)
			carry = t >> 32
		}
		// carry into limb [i+8]. Always at offset MUL_INT_LO + (i+8)*4.
		// Since the schoolbook only writes limbs 0..15, slot 16 is unused.
		store<u32>(MUL_INT_LO + ((i + 8) << 2), carry as u32)
	}

	// Step 2: HMV Algorithm 2.27 Solinas reduction. The 16 × u32 product
	// is read from MUL_INT_LO (c[0..15]). We materialise each of s1..s9
	// (each 8 × u32) into FIELD_TMP slots, then sum / subtract them.
	feReduce(out)
}

// Internal: read c[i] (i in 0..15) from MUL_INT_LO.
@inline
function c(i: i32): u32 {
	return load<u32>(MUL_INT_LO + (i << 2))
}

/**
 * Apply HMV Algorithm 2.27 to MUL_INT_LO (16 × u32) and write the
 * reduced 8 × u32 field element to `out`. Each si lives in a dedicated
 * FIELD_TMP slot; the final accumulator and mod-p correction loop
 * operate on 9-limb (8 limbs + 1 carry word) buffers to absorb the
 * recipe's coefficient of 2 on s2 / s3.
 *
 * Term aliasing per HMV §2.4.1 Algorithm 2.27 (P-256):
 *
 *   s1 = (c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0 )
 *   s2 = (c15, c14, c13, c12, c11, 0,   0,   0  )
 *   s3 = (0,   c15, c14, c13, c12, 0,   0,   0  )
 *   s4 = (c15, c14, 0,   0,   0,   c10, c9,  c8 )
 *   s5 = (c8,  c13, c15, c14, c13, c11, c10, c9 )
 *   s6 = (c10, c8,  0,   0,   0,   c13, c12, c11)
 *   s7 = (c11, c9,  0,   0,   c15, c14, c13, c12)
 *   s8 = (c12, 0,   c10, c9,  c8,  c15, c14, c13)
 *   s9 = (c13, 0,   c11, c10, c9,  0,   c15, c14)
 *
 *   r = s1 + 2 s2 + 2 s3 + s4 + s5 - s6 - s7 - s8 - s9 (mod p)
 */
@inline
function feReduce(out: i32): void {
	const s1: i32 = FIELD_TMP +  7 * FIELD_TMP_STRIDE
	const s2: i32 = FIELD_TMP +  8 * FIELD_TMP_STRIDE
	const s3: i32 = FIELD_TMP +  9 * FIELD_TMP_STRIDE
	const s4: i32 = FIELD_TMP + 10 * FIELD_TMP_STRIDE
	const s5: i32 = FIELD_TMP + 11 * FIELD_TMP_STRIDE
	const s6: i32 = FIELD_TMP + 12 * FIELD_TMP_STRIDE
	const s7: i32 = FIELD_TMP + 13 * FIELD_TMP_STRIDE
	// reuse 14, 15 for s8, s9
	const s8: i32 = FIELD_TMP + 14 * FIELD_TMP_STRIDE
	const s9: i32 = FIELD_TMP + 15 * FIELD_TMP_STRIDE

	// s1 = c[0..7]
	for (let i: i32 = 0; i < 8; i++) st(s1, i, c(i))

	// s2 = (0, 0, 0, c11, c12, c13, c14, c15) in limb[0..7] LE
	// i.e. s2[3] = c11, s2[4] = c12, s2[5] = c13, s2[6] = c14, s2[7] = c15.
	st(s2, 0, 0); st(s2, 1, 0); st(s2, 2, 0)
	st(s2, 3, c(11)); st(s2, 4, c(12)); st(s2, 5, c(13))
	st(s2, 6, c(14)); st(s2, 7, c(15))

	// s3 = (0, 0, 0, c12, c13, c14, c15, 0)
	st(s3, 0, 0); st(s3, 1, 0); st(s3, 2, 0)
	st(s3, 3, c(12)); st(s3, 4, c(13)); st(s3, 5, c(14))
	st(s3, 6, c(15)); st(s3, 7, 0)

	// s4 = (c8, c9, c10, 0, 0, 0, c14, c15)
	st(s4, 0, c(8)); st(s4, 1, c(9)); st(s4, 2, c(10))
	st(s4, 3, 0); st(s4, 4, 0); st(s4, 5, 0)
	st(s4, 6, c(14)); st(s4, 7, c(15))

	// s5 = (c9, c10, c11, c13, c14, c15, c13, c8)
	st(s5, 0, c(9)); st(s5, 1, c(10)); st(s5, 2, c(11))
	st(s5, 3, c(13)); st(s5, 4, c(14)); st(s5, 5, c(15))
	st(s5, 6, c(13)); st(s5, 7, c(8))

	// s6 = (c11, c12, c13, 0, 0, 0, c8, c10)
	st(s6, 0, c(11)); st(s6, 1, c(12)); st(s6, 2, c(13))
	st(s6, 3, 0); st(s6, 4, 0); st(s6, 5, 0)
	st(s6, 6, c(8)); st(s6, 7, c(10))

	// s7 = (c12, c13, c14, c15, 0, 0, c9, c11)
	st(s7, 0, c(12)); st(s7, 1, c(13)); st(s7, 2, c(14))
	st(s7, 3, c(15)); st(s7, 4, 0); st(s7, 5, 0)
	st(s7, 6, c(9)); st(s7, 7, c(11))

	// s8 = (c13, c14, c15, c8, c9, c10, 0, c12)
	st(s8, 0, c(13)); st(s8, 1, c(14)); st(s8, 2, c(15))
	st(s8, 3, c(8)); st(s8, 4, c(9)); st(s8, 5, c(10))
	st(s8, 6, 0); st(s8, 7, c(12))

	// s9 = (c14, c15, 0, c9, c10, c11, 0, c13)
	st(s9, 0, c(14)); st(s9, 1, c(15)); st(s9, 2, 0)
	st(s9, 3, c(9)); st(s9, 4, c(10)); st(s9, 5, c(11))
	st(s9, 6, 0); st(s9, 7, c(13))

	// Accumulator: r = s1 + 2*s2 + 2*s3 + s4 + s5 (positives), then
	// subtract s6 + s7 + s8 + s9.
	//
	// We use a signed 9-limb accumulator (8 × u32 + 1 × i64 carry word).
	// To keep arithmetic in u32 lanes, we run the running sum as
	// (acc, carryOut) and apply mod-p corrections only at the end.

	// Initialise acc = s1.
	const acc: i32 = FIELD_TMP + 0 * FIELD_TMP_STRIDE
	for (let i: i32 = 0; i < 8; i++) st(acc, i, ld(s1, i))
	store<u32>(acc + 32, 0)  // 9th limb = 0

	add9(acc, s2, false)   // acc += s2
	add9(acc, s2, false)   // acc += s2 (so +2*s2 total)
	add9(acc, s3, false)
	add9(acc, s3, false)   // +2*s3
	add9(acc, s4, false)
	add9(acc, s5, false)
	add9(acc, s6, true)    // acc -= s6
	add9(acc, s7, true)
	add9(acc, s8, true)
	add9(acc, s9, true)

	// Final fix-up: acc may be in (-4p, +6p) range; normalize to [0, p).
	// Strategy:
	//   1. If the 9th limb is negative (msb set), add p repeatedly until
	//      acc is non-negative. Worst case: +4 additions.
	//   2. Subtract p as many times as fits (up to 5 times) while acc >= p.

	const pBuf: i32 = FIELD_TMP +  2 * FIELD_TMP_STRIDE
	loadP(pBuf)
	// Make 9-limb p (pad with 0 at limb[8]).
	store<u32>(pBuf + 32, 0)

	// Phase 1: while top limb is negative (interpreted as i32), add p.
	// Worst case: acc started at -4.0001p (max negative for HMV §2.27),
	// so up to 5 add-p iterations are needed. Bumped to 6 for headroom.
	for (let k: i32 = 0; k < 6; k++) {
		const topI: i32 = load<i32>(acc + 32)
		const isNeg: u32 = ((topI >> 31) & 1) as u32
		condAdd9(acc, pBuf, isNeg)
	}

	// Phase 2: while acc >= p, subtract p. Worst case: acc = 7p after
	// phase 1 (max positive for HMV §2.27 is +7p with all +s_i terms at
	// limit and all -s_i terms zero), requiring 7 subtractions. Bumped
	// to 8 for headroom.
	for (let k: i32 = 0; k < 8; k++) {
		// Compare acc with p (both 9 limbs).
		// acc >= p iff acc - p has no borrow (top limb non-negative).
		condSub9IfGe(acc, pBuf)
	}

	// Write acc[0..7] to out.
	for (let i: i32 = 0; i < 8; i++) st(out, i, ld(acc, i))
}

// Add or subtract a 9-limb buffer (b padded to 9 limbs internally if 8 given)
// into `acc` (also 9 limbs). If `sub` is true, b is subtracted instead.
@inline
function add9(acc: i32, b: i32, sub: bool): void {
	if (sub) {
		// acc -= b. Signed-borrow propagation through 9 limbs.
		let borrow: i64 = 0
		for (let i: i32 = 0; i < 8; i++) {
			const ai: i64 = (load<u32>(acc + (i << 2)) as i64)
			const bi: i64 = (load<u32>(b   + (i << 2)) as i64)
			const d: i64 = ai - bi - borrow
			store<u32>(acc + (i << 2), (d as u32))
			borrow = (d >> 32) & 1
		}
		// 9th limb (signed). b only has 8 limbs valid; treat b[8] as 0.
		const a8: i64 = (load<i32>(acc + 32) as i64)
		const d8: i64 = a8 - borrow
		store<i32>(acc + 32, d8 as i32)
	} else {
		let carry: u64 = 0
		for (let i: i32 = 0; i < 8; i++) {
			const ai: u64 = (load<u32>(acc + (i << 2)) as u64)
			const bi: u64 = (load<u32>(b   + (i << 2)) as u64)
			const s: u64 = ai + bi + carry
			store<u32>(acc + (i << 2), (s as u32))
			carry = s >> 32
		}
		const a8: i64 = (load<i32>(acc + 32) as i64)
		const s8: i64 = a8 + (carry as i64)
		store<i32>(acc + 32, s8 as i32)
	}
}

// Conditionally add 9-limb p (in pBuf) to acc (9 limbs). cond is 0 or 1.
@inline
function condAdd9(acc: i32, pBuf: i32, cond: u32): void {
	const mask: u32 = ((-(cond as i32)) as u32)
	let carry: u64 = 0
	for (let i: i32 = 0; i < 8; i++) {
		const ai: u64 = (load<u32>(acc + (i << 2)) as u64)
		const pi: u64 = (load<u32>(pBuf + (i << 2)) as u64) & (mask as u64)
		const s: u64 = ai + pi + carry
		store<u32>(acc + (i << 2), (s as u32))
		carry = s >> 32
	}
	const a8: i64 = (load<i32>(acc + 32) as i64)
	const s8: i64 = a8 + (carry as i64)
	store<i32>(acc + 32, s8 as i32)
}

// If acc >= p (in pBuf), subtract p. Else leave alone. Both inputs are
// 9-limb signed. Implementation: compute (acc - p), if the resulting 9th
// limb is >= 0 (no borrow), commit the difference; else keep acc.
//
// GOTCHA: 9th limb is kept in a `d8` local, NOT stored at `tmp + 32`
// (= FIELD_TMP slot 4, which feSqrt / feInv use for the exponent buffer).
@inline
function condSub9IfGe(acc: i32, pBuf: i32): void {
	const tmp: i32 = FIELD_TMP + 3 * FIELD_TMP_STRIDE  // 8 limbs only; 9th lives in d8 local
	let borrow: i64 = 0
	for (let i: i32 = 0; i < 8; i++) {
		const ai: i64 = (load<u32>(acc + (i << 2)) as i64)
		const pi: i64 = (load<u32>(pBuf + (i << 2)) as i64)
		const d: i64 = ai - pi - borrow
		store<u32>(tmp + (i << 2), (d as u32))
		borrow = (d >> 32) & 1
	}
	const a8: i64 = (load<i32>(acc + 32) as i64)
	const d8: i64 = a8 - borrow

	// Commit tmp to acc iff d8 >= 0 (i.e. acc was >= p).
	const cond: u32 = (((d8 >> 63) & 1) ^ 1) as u32   // 1 if d8 >= 0, else 0
	const mask: u32 = ((-(cond as i32)) as u32)
	for (let i: i32 = 0; i < 8; i++) {
		const va: u32 = load<u32>(tmp + (i << 2))
		const vb: u32 = load<u32>(acc + (i << 2))
		store<u32>(acc + (i << 2), (va & mask) | (vb & ~mask))
	}
	// 9th limb ct-select: use d8 local instead of a load from tmp + 32.
	const va8: i32 = d8 as i32
	const vb8: i32 = load<i32>(acc + 32)
	store<i32>(acc + 32, ((va8 & (mask as i32)) | (vb8 & (~mask as i32))))
}

export function feSqr(out: i32, a: i32): void {
	feMul(out, a, a)
}

// ── feInv: a^(p-2) via Fermat ──────────────────────────────────────────────
//
// p - 2 = 2^256 - 2^224 + 2^192 + 2^96 - 3 (SP 800-186 §3.2.1.3).
// Constant-time square-and-multiply scan over the public exponent;
// addition-chain exploration and the RustCrypto comparison live in
// docs/asm_p256.md#feinv-chain.

/**
 * out = a^(-1) mod p, via Fermat (a^(p-2)). Constant-time over the
 * exponent bits since (p - 2) is a public constant — we use a fixed
 * binary scan over its bytes, multiplying conditionally on each bit
 * without branching on a's value.
 */
export function feInv(out: i32, a: i32): void {
	// (p - 2) in LE limb order (limb[0] = LSB, limb[7] = MSB):
	//   limb[0] = 0xFFFFFFFD  (= 0xFFFFFFFF - 2; bit 1 cleared at LSB)
	//   limb[1] = 0xFFFFFFFF
	//   limb[2] = 0xFFFFFFFF
	//   limb[3] = 0x00000000
	//   limb[4] = 0x00000000
	//   limb[5] = 0x00000000
	//   limb[6] = 0x00000001  (the +2^192 bit of the Solinas form)
	//   limb[7] = 0xFFFFFFFF
	//
	// Derivation from SP 800-186 §3.2.1.3 form of p:
	//   p = 2^256 - 2^224 + 2^192 + 2^96 - 1, BE 32-hex form
	//       ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
	//   p - 2 last byte 0xfd; bytes 0..30 unchanged. Reverse to LE words.
	const pmTmp: i32 = FIELD_TMP + 4 * FIELD_TMP_STRIDE  // 32-byte scratch
	store<u32>(pmTmp +  0, 0xFFFFFFFD)  // limb[0], LSB
	store<u32>(pmTmp +  4, 0xFFFFFFFF)
	store<u32>(pmTmp +  8, 0xFFFFFFFF)
	store<u32>(pmTmp + 12, 0x00000000)
	store<u32>(pmTmp + 16, 0x00000000)
	store<u32>(pmTmp + 20, 0x00000000)
	store<u32>(pmTmp + 24, 0x00000001)
	store<u32>(pmTmp + 28, 0xFFFFFFFF)  // limb[7], MSB

	// Use accumulator slot and a' slot.
	const acc: i32 = FIELD_TMP + 5 * FIELD_TMP_STRIDE
	const aCopy: i32 = FIELD_TMP + 6 * FIELD_TMP_STRIDE
	feOne(acc)
	feCopy(aCopy, a)

	// Square-and-multiply, MSB to LSB.
	// limb[7] (MSB) first.
	for (let limbIdx: i32 = 7; limbIdx >= 0; limbIdx--) {
		const w: u32 = load<u32>(pmTmp + (limbIdx << 2))
		for (let bitIdx: i32 = 31; bitIdx >= 0; bitIdx--) {
			feSqr(acc, acc)
			const bit: u32 = (w >> (bitIdx as u32)) & 1
			// Conditional multiply: compute acc * a unconditionally into a
			// scratch slot, then ct-select between (acc, scratch) on `bit`.
			// Slot 15 (= s9) is overwritten by feReduce on every feMul call,
			// so its post-call content is junk we don't care about; we just
			// need a writable destination that is not aliased by feMul's own
			// FIELD_TMP slots 0..14.
			const tmpSlot: i32 = FIELD_TMP + 15 * FIELD_TMP_STRIDE
			feMul(tmpSlot, acc, aCopy)
			// ct-select: if bit, acc = tmpSlot; else keep acc.
			const mask: u32 = ((-(bit as i32)) as u32)
			for (let k: i32 = 0; k < 8; k++) {
				const va: u32 = load<u32>(tmpSlot + (k << 2))
				const vb: u32 = load<u32>(acc + (k << 2))
				store<u32>(acc + (k << 2), (va & mask) | (vb & ~mask))
			}
		}
	}

	feCopy(out, acc)
}

// ── feSqrt: a^((p+1)/4) mod p (square root for p ≡ 3 (mod 4)) ──────────────
//
// P-256 has p ≡ 3 (mod 4); sqrt candidate = a^((p+1)/4) per Fermat.
// (p+1)/4 = 2^254 - 2^222 + 2^190 + 2^94 (SP 800-186 §3.2.1.3).
// Bits set: {94, 190, 222..253}. LE limb form below.
//
// Caller verifies the candidate squares back to the input; non-residue
// inputs return junk. Bit-by-bit derivation: docs/asm_p256.md#fesqrt-exponent.

/**
 * out = a^((p+1)/4) mod p. Square-and-multiply over the public
 * constant (p+1)/4. Used by point decompression to recover y from x.
 */
export function feSqrt(out: i32, a: i32): void {
	// 32-byte LE limb form of (p+1)/4.
	const eTmp: i32 = FIELD_TMP + 4 * FIELD_TMP_STRIDE
	store<u32>(eTmp +  0, 0)                     // limb[0]
	store<u32>(eTmp +  4, 0)                     // limb[1]
	store<u32>(eTmp +  8, 0x40000000)            // limb[2], bit 94
	store<u32>(eTmp + 12, 0)                     // limb[3]
	store<u32>(eTmp + 16, 0)                     // limb[4]
	store<u32>(eTmp + 20, 0x40000000)            // limb[5], bit 190
	store<u32>(eTmp + 24, 0xC0000000)            // limb[6], bits 222 + 223
	store<u32>(eTmp + 28, 0x3FFFFFFF)            // limb[7], bits 224..253

	// Square-and-multiply scan from MSB to LSB.
	const acc: i32 = FIELD_TMP + 5 * FIELD_TMP_STRIDE
	const aCopy: i32 = FIELD_TMP + 6 * FIELD_TMP_STRIDE
	feOne(acc)
	feCopy(aCopy, a)

	for (let limbIdx: i32 = 7; limbIdx >= 0; limbIdx--) {
		const w: u32 = load<u32>(eTmp + (limbIdx << 2))
		for (let bitIdx: i32 = 31; bitIdx >= 0; bitIdx--) {
			feSqr(acc, acc)
			const bit: u32 = (w >> (bitIdx as u32)) & 1
			const tmpSlot: i32 = FIELD_TMP + 15 * FIELD_TMP_STRIDE
			feMul(tmpSlot, acc, aCopy)
			const mask: u32 = ((-(bit as i32)) as u32)
			for (let k: i32 = 0; k < 8; k++) {
				const va: u32 = load<u32>(tmpSlot + (k << 2))
				const vb: u32 = load<u32>(acc + (k << 2))
				store<u32>(acc + (k << 2), (va & mask) | (vb & ~mask))
			}
		}
	}

	feCopy(out, acc)
}

// ── Boolean / sign helpers ─────────────────────────────────────────────────

/**
 * Returns 1 if a == 0 (mod p) in canonical form, 0 otherwise. Reads
 * the 8 limbs and OR-folds. Result is 1 iff every limb is zero.
 * Assumes input is canonical (< p) — feAdd / feSub / feMul / feSqr
 * all return canonical limb form so this is normally automatic.
 */
export function feIsZero(a: i32): i32 {
	let r: u32 = 0
	for (let i: i32 = 0; i < 8; i++) {
		r |= ld(a, i)
	}
	// r == 0 iff every limb was 0. Convert to {0, 1} without branches.
	const x: u32 = r | ((-(r as i32)) as u32)  // msb = 1 iff r != 0
	return ((1 as u32) - (x >> 31)) as i32
}

/**
 * Returns the LSB of the canonical encoding (limb[0] bit 0). Used by
 * SEC1 §2.3.4 point decompression to select the correct y parity.
 */
export function feIsOdd(a: i32): i32 {
	return (ld(a, 0) & 1) as i32
}

/**
 * Returns 1 if a == b (canonical), 0 otherwise. XOR-accumulate over
 * 8 × u32 limbs read via the field-element stride; hand-rolled rather
 * than ctEqual because the input is limb-strided, not byte-contiguous.
 */
export function feIsEqual(a: i32, b: i32): i32 {
	let r: u32 = 0
	for (let i: i32 = 0; i < 8; i++) {
		r |= ld(a, i) ^ ld(b, i)
	}
	const x: u32 = r | ((-(r as i32)) as u32)
	return ((1 as u32) - (x >> 31)) as i32
}

/**
 * Returns 1 if a < p (canonical field element), 0 otherwise. Subtracts
 * p limb-wise; the final borrow is set iff a < p. The difference is
 * discarded. Mirrors `scalarIsCanonical` in scalar.ts but for the
 * LE u32 limb form and the field prime p (not the curve order n).
 *
 * Internal field outputs (feAdd / feSub / feMul / feSqr) are canonical
 * by construction; only `feFromBytes` on adversarial wire data can
 * produce a non-canonical limb representation. `pointDecompress` is
 * the sole call site so far, rejecting compressed pks whose x bytes
 * exceed the field prime per SEC 1 §2.3.4 strict-decode.
 */
export function feIsCanonical(a: i32): i32 {
	const pBuf:    i32 = FIELD_TMP + 0 * FIELD_TMP_STRIDE
	const diffBuf: i32 = FIELD_TMP + 1 * FIELD_TMP_STRIDE
	loadP(pBuf)
	return (sub8(diffBuf, a, pBuf) as i32)
}

// ── Constant-time conditional helpers ──────────────────────────────────────

/**
 * Conditionally swap two field elements in place. `swap` must be 0 or 1.
 * XOR-mask swap, branchless.
 */
export function feCondSwap(a: i32, b: i32, swap: i32): void {
	const mask: u32 = ((-(swap & 1)) as u32)
	for (let i: i32 = 0; i < 8; i++) {
		const ai: u32 = ld(a, i)
		const bi: u32 = ld(b, i)
		const t:  u32 = mask & (ai ^ bi)
		st(a, i, ai ^ t)
		st(b, i, bi ^ t)
	}
}

/**
 * Conditionally negate: out = neg ? -a : a. `neg` must be 0 or 1.
 * Both branches always execute; result is selected limb-wise.
 */
export function feCondNeg(out: i32, a: i32, neg: i32): void {
	const negBuf: i32 = FIELD_TMP + 0 * FIELD_TMP_STRIDE  // OK to alias with feNeg's slot
	feNeg(negBuf, a)
	const mask: u32 = ((-(neg & 1)) as u32)
	for (let i: i32 = 0; i < 8; i++) {
		const va: u32 = ld(negBuf, i)
		const vb: u32 = ld(a, i)
		st(out, i, (va & mask) | (vb & ~mask))
	}
}

// ── Curve constant b: from SP 800-186 §3.2.1.3 ─────────────────────────────
//
// b = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
//   (32 BE hex digits). LE limbs below reverse the 8 BE u32 words.

@inline
export function loadB(dst: i32): void {
	st(dst, 0, 0x27D2604B)
	st(dst, 1, 0x3BCE3C3E)
	st(dst, 2, 0xCC53B0F6)
	st(dst, 3, 0x651D06B0)
	st(dst, 4, 0x769886BC)
	st(dst, 5, 0xB3EBBD55)
	st(dst, 6, 0xAA3A93E7)
	st(dst, 7, 0x5AC635D8)
}

// 3*b mod p is not pinned; point.ts derives it via two feAdd from loadB
// (AGENTS.md §5: no embedded derived crypto constants).
// a = -3 = p - 3 (SP 800-186 §3.2.1.3, Koblitz form) is consumed inline
// by the RCB algorithm 4 specialisation (eprint 2015/1060 Theorem 1);
// not materialised as a separate constant.

// ── Internal: exposed feReduce for unit testing the reduction step ─────────
//
// Test surface: substrate gate test verifies that a manually-staged
// 16-limb product (e.g. p * 1 = p, or (p-1) * (p-1) etc.) reduces to
// the expected canonical form. Not part of the public ABI.

export function _testFeReduce(out: i32): void {
	feReduce(out)
}

// Internal: expose the 16-limb intermediate offset for unit tests that
// stage a synthetic c[0..15] product to exercise the Solinas reduction
// in isolation.
export function _testGetMulIntOffset(): i32 {
	return MUL_INT_LO
}
