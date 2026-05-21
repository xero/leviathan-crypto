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
// src/asm/curve25519/scalar.ts
//
// Scalar arithmetic modulo L, the order of the edwards25519 base point.
// RFC 8032 §5.1: L = 2^252 + 27742317777372353535851937790883648493.
//
// Operations:
//  - scalarClamp:      RFC 7748 §5 / RFC 8032 §5.1.5 clamp on 32 bytes
//  - scalarReduce:     32 bytes → 32 bytes mod L
//  - scalarReduce64:   64 bytes → 32 bytes mod L (hash output → scalar)
//  - scalarAdd:        (a + b) mod L
//  - scalarMulAdd:     (a*b + c) mod L, the Ed25519 signing equation
//  - scalarIsCanonical: returns 1 iff s < L
//
// Internal representation: 32 bytes little-endian for inputs / outputs.
// Reductions use bit-by-bit schoolbook division (260 iterations for 64
// → 32, 4 iterations for 32 → 32). Constant-time throughout: every
// subtract / select is mask-driven.

import { FIELD_TMP_OFFSET } from './buffers'

// ── Curve order L per RFC 8032 §5.1 ─────────────────────────────────────────
//
// L = 2^252 + 27742317777372353535851937790883648493
// Decimal: 7237005577332262213973186563042994240857116359379907606001950938285454250989
// Hex:     0x10000000000000000000000000000000 14DEF9DEA2F79CD65812631A5CF5D3ED
//
// 32-byte LE encoding (low byte first), 16 bytes are non-trivial:
const L0:  u8 = 0xED
const L1:  u8 = 0xD3
const L2:  u8 = 0xF5
const L3:  u8 = 0x5C
const L4:  u8 = 0x1A
const L5:  u8 = 0x63
const L6:  u8 = 0x12
const L7:  u8 = 0x58
const L8:  u8 = 0xD6
const L9:  u8 = 0x9C
const L10: u8 = 0xF7
const L11: u8 = 0xA2
const L12: u8 = 0xDE
const L13: u8 = 0xF9
const L14: u8 = 0xDE
const L15: u8 = 0x14
// L[16..30] = 0
const L31: u8 = 0x10

@inline
function lByte(i: i32): u8 {
	if (i < 16) {
		if (i ==  0) return L0
		if (i ==  1) return L1
		if (i ==  2) return L2
		if (i ==  3) return L3
		if (i ==  4) return L4
		if (i ==  5) return L5
		if (i ==  6) return L6
		if (i ==  7) return L7
		if (i ==  8) return L8
		if (i ==  9) return L9
		if (i == 10) return L10
		if (i == 11) return L11
		if (i == 12) return L12
		if (i == 13) return L13
		if (i == 14) return L14
		return L15
	}
	if (i == 31) return L31
	return 0
}

// ── scalarClamp ─────────────────────────────────────────────────────────────

/**
 * Clamp a 32-byte scalar per RFC 7748 §5 / RFC 8032 §5.1.5.
 *
 * Operations on the 32-byte LE scalar:
 *   scalar[0]  &= 248   (clear bits 0, 1, 2)
 *   scalar[31] &= 127   (clear bit 255, the high bit)
 *   scalar[31] |= 64    (set bit 254)
 *
 * The clamp ensures:
 *   - scalar is a multiple of 8 (cofactor clearing, eliminates small-
 *     subgroup attacks)
 *   - scalar's high two bits are exactly 01 (so the scalar is in the
 *     range [2^254, 2^255), giving a uniformly-distributed clamp output
 *     and making the Montgomery ladder's loop count fixed at 255)
 */
export function scalarClamp(out: i32, src: i32): void {
	// Copy all 32 bytes first (out may equal src).
	if (out != src) {
		memory.copy(out, src, 32)
	}
	const b0:  u8 = load<u8>(out +  0) & 0xF8       // clear bits 0,1,2
	const b31: u8 = (load<u8>(out + 31) & 0x7F) | 0x40  // clear bit 7, set bit 6
	store<u8>(out +  0, b0)
	store<u8>(out + 31, b31)
}

// ── 64-byte arithmetic helpers (constant-time, byte-level) ─────────────────
//
// Used by scalarReduce / scalarReduce64 / scalarAdd / scalarMulAdd
// internally. Operate on raw byte buffers in linear memory.

// Compare two 32-byte LE values constant-time. Returns 1 if a < b, else 0.
@inline
function ctLessThan32(a: i32, b: i32): i32 {
	let borrow: i32 = 0
	for (let i: i32 = 0; i < 32; i++) {
		const ai: i32 = load<u8>(a + i) as i32
		const bi: i32 = load<u8>(b + i) as i32
		borrow = (ai - bi - borrow) >> 31 & 1
	}
	return borrow
}

// Subtract L from a 33-byte LE value in place: a -= L (only if a >= L).
// Used after additions where the sum may overflow into byte 32.
// Returns 1 if a subtraction occurred (i.e. value was >= L), 0 otherwise.
@inline
function ctSubL33(a: i32): i32 {
	// First compute a - L (signed-borrow); if negative, mask out.
	const tmp: i32 = FIELD_TMP_OFFSET  // 33 bytes scratch
	let borrow: i32 = 0
	for (let i: i32 = 0; i < 33; i++) {
		const ai: i32 = load<u8>(a + i) as i32
		const li: i32 = i < 32 ? (lByte(i) as i32) : 0
		const v:  i32 = ai - li - borrow
		store<u8>(tmp + i, (v & 0xFF) as u8)
		borrow = (v >> 31) & 1
	}
	// If borrow == 0, a >= L: commit tmp to a.
	const mask: i32 = (borrow ^ 1)  // 1 if subtracted, 0 if not
	const m8: u8 = (-mask) as u8     // 0xFF or 0x00
	for (let i: i32 = 0; i < 33; i++) {
		const ai: u8 = load<u8>(a + i)
		const ti: u8 = load<u8>(tmp + i)
		store<u8>(a + i, (ai & ~m8) | (ti & m8))
	}
	return mask
}

// ── scalarIsCanonical ──────────────────────────────────────────────────────

/**
 * Returns 1 if the 32-byte LE scalar s is in [0, L), 0 otherwise.
 * Used by the strict-verification posture in Ed25519 verify.
 */
export function scalarIsCanonical(s: i32): i32 {
	// Build L in a scratch buffer and compare s < L.
	const lbuf: i32 = FIELD_TMP_OFFSET
	for (let i: i32 = 0; i < 32; i++) {
		store<u8>(lbuf + i, lByte(i))
	}
	return ctLessThan32(s, lbuf)
}

// ── scalarReduce (32-byte input) ────────────────────────────────────────────

/**
 * Reduce a 32-byte LE value mod L. Since the input is at most ~2^256,
 * and L > 2^252, at most ~2^4 = 16 subtractions of L are needed.
 *
 * Implementation: at most 16 iterations of "if value >= L, subtract L".
 * Constant-time via mask-driven conditional subtract.
 */
export function scalarReduce(out: i32, src: i32): void {
	// Copy src to a 33-byte work buffer (byte 32 = 0).
	const work: i32 = FIELD_TMP_OFFSET + 33  // 33 bytes, after the lByte scratch
	memory.copy(work, src, 32)
	store<u8>(work + 32, 0)

	// Subtract L up to 16 times. Each subtract is constant-time and
	// no-ops when value < L.
	for (let i: i32 = 0; i < 16; i++) {
		ctSubL33(work)
	}

	memory.copy(out, work, 32)
}

// ── scalarReduce64 (64-byte input) ──────────────────────────────────────────

export function scalarReduce64(out: i32, src: i32): void {
	// We process bits from the high half (bytes 32..63, msb first) into
	// a 33-byte accumulator that holds the running remainder.
	const work: i32 = FIELD_TMP_OFFSET + 64   // 33 bytes
	// Start with remainder = the high 32 bytes of src, reduced if needed.
	memory.copy(work, src + 32, 32)
	store<u8>(work + 32, 0)
	// Reduce the high half mod L (at most 16 subtractions).
	for (let i: i32 = 0; i < 16; i++) {
		ctSubL33(work)
	}

	// Now shift in bits from the low half (bytes 0..31), msb of byte 31
	// first. For each bit:
	//   work = (work << 1) | bit
	//   if work >= L, work -= L
	for (let byteIdx: i32 = 31; byteIdx >= 0; byteIdx--) {
		const byte: u8 = load<u8>(src + byteIdx)
		for (let bitIdx: i32 = 7; bitIdx >= 0; bitIdx--) {
			// Shift work left by 1, propagating carry through bytes.
			let carry: u32 = 0
			for (let k: i32 = 0; k < 33; k++) {
				const wk: u32 = load<u8>(work + k) as u32
				const newWk: u32 = ((wk << 1) | carry) & 0xFF
				carry = (wk >> 7) & 1
				store<u8>(work + k, newWk as u8)
			}
			// OR in the next bit from src.
			const bit: u8 = ((byte as u32 >> (bitIdx as u32)) & 1) as u8
			store<u8>(work + 0, load<u8>(work + 0) | bit)
			// Conditional subtract L. work fits in 33 bytes since at any
			// point work < 2*L < 2^253.
			ctSubL33(work)
		}
	}

	memory.copy(out, work, 32)
}

// ── scalarAdd ───────────────────────────────────────────────────────────────

/**
 * out = (a + b) mod L. Inputs and output are 32-byte LE.
 */
export function scalarAdd(out: i32, a: i32, b: i32): void {
	// Sum into 33-byte work buffer (byte 32 = 0 + carry).
	const work: i32 = FIELD_TMP_OFFSET + 128  // 33 bytes
	let carry: u32 = 0
	for (let i: i32 = 0; i < 32; i++) {
		const sum: u32 = (load<u8>(a + i) as u32) + (load<u8>(b + i) as u32) + carry
		store<u8>(work + i, (sum & 0xFF) as u8)
		carry = sum >> 8
	}
	store<u8>(work + 32, carry as u8)

	// Subtract L up to twice (a + b < 2L since both inputs < L).
	ctSubL33(work)
	ctSubL33(work)

	memory.copy(out, work, 32)
}

// ── scalarMulAdd ────────────────────────────────────────────────────────────

/**
 * out = (a*b + c) mod L. Inputs and output are 32-byte LE.
 * Used by Ed25519 sign: s = (r + k*a) mod L (where r and a are the
 * ephemeral nonce and secret scalar respectively, k = SHA-512(R || A
 * || M) reduced).
 *
 * Implementation: byte-level schoolbook multiplication producing a
 * 64-byte intermediate, byte-level addition of c, then scalarReduce64.
 * Constant-time throughout (no branches on operand bytes).
 */
export function scalarMulAdd(out: i32, a: i32, b: i32, c: i32): void {
	// 64-byte product buffer.
	const prod: i32 = FIELD_TMP_OFFSET + 192  // 64 bytes
	memory.fill(prod, 0, 64)

	// Schoolbook 32x32 → 64 byte multiplication, with running carry.
	for (let i: i32 = 0; i < 32; i++) {
		const ai: u32 = load<u8>(a + i) as u32
		let carry: u32 = 0
		for (let j: i32 = 0; j < 32; j++) {
			const bj: u32 = load<u8>(b + j) as u32
			const pij: u32 = load<u8>(prod + i + j) as u32
			const tmp: u32 = pij + ai * bj + carry
			store<u8>(prod + i + j, (tmp & 0xFF) as u8)
			carry = tmp >> 8
		}
		// Propagate final carry through remaining bytes. Fixed iteration
		// (no early-exit on carry == 0) so runtime is independent of
		// secret operand bytes; adding 0 is a byte no-op and keeps carry 0.
		for (let k: i32 = i + 32; k < 64; k++) {
			const pk: u32 = load<u8>(prod + k) as u32
			const tmp: u32 = pk + carry
			store<u8>(prod + k, (tmp & 0xFF) as u8)
			carry = tmp >> 8
		}
	}

	// Add c (32 bytes) to prod (64 bytes).
	let carry: u32 = 0
	for (let i: i32 = 0; i < 32; i++) {
		const pi: u32 = load<u8>(prod + i) as u32
		const ci: u32 = load<u8>(c + i) as u32
		const tmp: u32 = pi + ci + carry
		store<u8>(prod + i, (tmp & 0xFF) as u8)
		carry = tmp >> 8
	}
	// Propagate carry into the upper bytes. Fixed iteration for CT.
	for (let k: i32 = 32; k < 64; k++) {
		const pk: u32 = load<u8>(prod + k) as u32
		const tmp: u32 = pk + carry
		store<u8>(prod + k, (tmp & 0xFF) as u8)
		carry = tmp >> 8
	}

	// Reduce 64 bytes to 32 mod L.
	scalarReduce64(out, prod)
}
