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
// src/asm/p256/scalar.ts
//
// Scalar arithmetic modulo n, the order of the P-256 base point.
// SP 800-186 §3.2.1.3, FIPS 186-5 §6.
//
// n (decimal) = 115792089210356248762697446949407573529996955224135760342
//                422259061068512044369
//
// n (hex, BE) = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
//               BCE6FAAD A7179E84 F3B9CAC2 FC632551
//
// Internal representation: 32 bytes big-endian per FIPS 186-5 §6 wire
// form. All scalar arithmetic operates byte-level on BE buffers,
// mirroring the curve25519 byte-level scalar reductions (but with n
// substituted for L and BE substituted for LE byte order).
//
// Operations:
//   scalarFromBytes / scalarToBytes : 32-byte BE copy in / out
//   scalarIsCanonical(s)            : 1 iff s ∈ [0, n)
//   scalarIsZero(s)                 : 1 iff s == 0
//   scalarReduce(out, src32)        : reduce a 32-byte BE input mod n
//   scalarReduce64(out, src64)      : reduce a 64-byte BE input mod n
//                                      (HMAC chain output, see RFC 6979)
//   scalarAdd(out, a, b)            : (a + b) mod n
//   scalarSub(out, a, b)            : (a - b) mod n
//   scalarMul(out, a, b)            : (a * b) mod n
//   scalarInv(out, a)               : a^(n-2) mod n (Fermat)
//   scalarNegate(out, a)            : (-a) mod n = n - a if a != 0 else 0
//   scalarIsHighS(s)                : 1 iff s > n/2 (RFC 6979 §3.5 low-S)
//
// Constant-time discipline: every operation runs a fixed-length loop
// with mask-driven conditional selects. No branches on secret bytes,
// no early returns. scalarInv's exponent (n-2) is a public constant,
// so its bit scan is fixed.

import {FIELD_TMP, FIELD_TMP_STRIDE} from './buffers'

// ── Curve order n (BE bytes) ───────────────────────────────────────────────
//
// n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
//
// SP 800-186 §3.2.1.3 publishes n with this big-endian form; bytes
// below are transcribed from the spec text verbatim. Per AGENTS.md §5
// the spec is the authority — no value here is sourced from a planning
// document or test vector.

const N00: u8 = 0xFF; const N01: u8 = 0xFF; const N02: u8 = 0xFF; const N03: u8 = 0xFF
const N04: u8 = 0x00; const N05: u8 = 0x00; const N06: u8 = 0x00; const N07: u8 = 0x00
const N08: u8 = 0xFF; const N09: u8 = 0xFF; const N10: u8 = 0xFF; const N11: u8 = 0xFF
const N12: u8 = 0xFF; const N13: u8 = 0xFF; const N14: u8 = 0xFF; const N15: u8 = 0xFF
const N16: u8 = 0xBC; const N17: u8 = 0xE6; const N18: u8 = 0xFA; const N19: u8 = 0xAD
const N20: u8 = 0xA7; const N21: u8 = 0x17; const N22: u8 = 0x9E; const N23: u8 = 0x84
const N24: u8 = 0xF3; const N25: u8 = 0xB9; const N26: u8 = 0xCA; const N27: u8 = 0xC2
const N28: u8 = 0xFC; const N29: u8 = 0x63; const N30: u8 = 0x25; const N31: u8 = 0x51

// ── n / 2 (rounded down) for low-S enforcement, RFC 6979 §3.5 ──────────────
//
// n is odd (LSB = 0x51), so n / 2 (integer division) = (n - 1) / 2.
//
// Derivation reproducible from the SP 800-186 hex form of n:
//   (n - 1) = ...FC632550, all other bytes unchanged.
//   Right-shift by 1 over the 8 BE u32 words yields:
//
//   (n-1)/2 = 7FFFFFFF 80000000 7FFFFFFF FFFFFFFF
//             DE737D56 D38BCF42 79DCE561 7E3192A8
//
// No value here is taken from a planning document; every byte is the
// right-shifted half of the SP 800-186 spec word it overlays.

const NH00: u8 = 0x7F; const NH01: u8 = 0xFF; const NH02: u8 = 0xFF; const NH03: u8 = 0xFF
const NH04: u8 = 0x80; const NH05: u8 = 0x00; const NH06: u8 = 0x00; const NH07: u8 = 0x00
const NH08: u8 = 0x7F; const NH09: u8 = 0xFF; const NH10: u8 = 0xFF; const NH11: u8 = 0xFF
const NH12: u8 = 0xFF; const NH13: u8 = 0xFF; const NH14: u8 = 0xFF; const NH15: u8 = 0xFF
const NH16: u8 = 0xDE; const NH17: u8 = 0x73; const NH18: u8 = 0x7D; const NH19: u8 = 0x56
const NH20: u8 = 0xD3; const NH21: u8 = 0x8B; const NH22: u8 = 0xCF; const NH23: u8 = 0x42
const NH24: u8 = 0x79; const NH25: u8 = 0xDC; const NH26: u8 = 0xE5; const NH27: u8 = 0x61
const NH28: u8 = 0x7E; const NH29: u8 = 0x31; const NH30: u8 = 0x92; const NH31: u8 = 0xA8

@inline
function nByte(i: i32): u8 {
	switch (i) {
		case  0: return N00; case  1: return N01; case  2: return N02; case  3: return N03
		case  4: return N04; case  5: return N05; case  6: return N06; case  7: return N07
		case  8: return N08; case  9: return N09; case 10: return N10; case 11: return N11
		case 12: return N12; case 13: return N13; case 14: return N14; case 15: return N15
		case 16: return N16; case 17: return N17; case 18: return N18; case 19: return N19
		case 20: return N20; case 21: return N21; case 22: return N22; case 23: return N23
		case 24: return N24; case 25: return N25; case 26: return N26; case 27: return N27
		case 28: return N28; case 29: return N29; case 30: return N30; default:  return N31
	}
}

@inline
function nHalfByte(i: i32): u8 {
	switch (i) {
		case  0: return NH00; case  1: return NH01; case  2: return NH02; case  3: return NH03
		case  4: return NH04; case  5: return NH05; case  6: return NH06; case  7: return NH07
		case  8: return NH08; case  9: return NH09; case 10: return NH10; case 11: return NH11
		case 12: return NH12; case 13: return NH13; case 14: return NH14; case 15: return NH15
		case 16: return NH16; case 17: return NH17; case 18: return NH18; case 19: return NH19
		case 20: return NH20; case 21: return NH21; case 22: return NH22; case 23: return NH23
		case 24: return NH24; case 25: return NH25; case 26: return NH26; case 27: return NH27
		case 28: return NH28; case 29: return NH29; case 30: return NH30; default:  return NH31
	}
}

// ── BE arithmetic helpers ───────────────────────────────────────────────────
//
// We process MSB-at-byte-0 BE buffers. Subtraction iterates from LSB
// (byte 31) to MSB (byte 0); addition does the same. Borrow / carry
// flow from byte 31 to byte 0 (opposite of LE).

// Build n at dst (32 bytes BE).
@inline
function loadN(dst: i32): void {
	for (let i: i32 = 0; i < 32; i++) {
		store<u8>(dst + i, nByte(i))
	}
}

// Build n/2 (rounded down) at dst (32 bytes BE).
@inline
function loadNHalf(dst: i32): void {
	for (let i: i32 = 0; i < 32; i++) {
		store<u8>(dst + i, nHalfByte(i))
	}
}

// 32-byte BE comparison: returns 1 if a < b, else 0.
@inline
function ctLessThan32BE(a: i32, b: i32): i32 {
	let borrow: i32 = 0
	// Iterate LSB to MSB (byte 31 down to byte 0).
	for (let i: i32 = 31; i >= 0; i--) {
		const ai: i32 = load<u8>(a + i) as i32
		const bi: i32 = load<u8>(b + i) as i32
		borrow = ((ai - bi - borrow) >> 31) & 1
	}
	return borrow
}

// Subtract n from a 33-byte BE value in place: a -= n (only if a >= n).
// a is laid out with a[0] = high overflow byte, a[1..32] = the 32-byte
// payload (BE). Returns 1 if a subtraction occurred (i.e. value was >= n),
// 0 otherwise.
@inline
function ctSubN33BE(a: i32): i32 {
	const tmp: i32 = FIELD_TMP + 0 * FIELD_TMP_STRIDE  // 33 bytes scratch
	let borrow: i32 = 0
	// Iterate LSB (byte 32) to MSB (byte 0).
	for (let i: i32 = 32; i >= 0; i--) {
		const ai: i32 = load<u8>(a + i) as i32
		const ni: i32 = i == 0 ? 0 : (nByte(i - 1) as i32)  // n occupies bytes 1..32
		const v:  i32 = ai - ni - borrow
		store<u8>(tmp + i, (v & 0xFF) as u8)
		borrow = (v >> 31) & 1
	}
	// If borrow == 0, a >= n: commit tmp to a.
	const mask: i32 = (borrow ^ 1)  // 1 if subtracted, 0 if not
	const m8: u8 = (-mask) as u8     // 0xFF or 0x00
	for (let i: i32 = 0; i <= 32; i++) {
		const ai: u8 = load<u8>(a + i)
		const ti: u8 = load<u8>(tmp + i)
		store<u8>(a + i, (ai & ~m8) | (ti & m8))
	}
	return mask
}

// ── Public scalar API ──────────────────────────────────────────────────────

/**
 * out = copy of src (32 bytes BE). Sole purpose is documentation of
 * the wire-form contract: callers that hand the WASM a 32-byte buffer
 * are passing BE bytes per FIPS 186-5 §6.
 */
export function scalarFromBytes(out: i32, src: i32): void {
	memory.copy(out, src, 32)
}

export function scalarToBytes(out: i32, src: i32): void {
	memory.copy(out, src, 32)
}

/**
 * Returns 1 if s is in [0, n), 0 otherwise. Mirrors curve25519's
 * scalarIsCanonical for the strict-verification posture: FIPS 186-5
 * §6.5.3 rejects r ∉ [1, n-1] and s ∉ [1, n-1] in ECDSA verify.
 * (The is-non-zero check is separate; this function does NOT reject 0.)
 */
export function scalarIsCanonical(s: i32): i32 {
	const nbuf: i32 = FIELD_TMP + 1 * FIELD_TMP_STRIDE
	loadN(nbuf)
	return ctLessThan32BE(s, nbuf)
}

/**
 * Returns 1 if s == 0, 0 otherwise. Constant-time OR-fold of all 32
 * bytes.
 */
export function scalarIsZero(s: i32): i32 {
	let r: i32 = 0
	for (let i: i32 = 0; i < 32; i++) {
		r |= load<u8>(s + i) as i32
	}
	const x: i32 = r | (-r)  // msb = 1 iff r != 0
	return 1 - ((x >>> 31) as i32)
}

/**
 * Returns 1 if s > n/2 (rounded down), 0 otherwise. Used by ECDSA sign
 * to enforce the RFC 6979 §3.5 low-S normalisation: when s is "high",
 * substitute s ← n - s before emitting.
 *
 * Equivalently: s > (n-1)/2. We compare s against n/2 = (n-1)/2 (since
 * n is odd). Returns 1 iff s > n/2, i.e. nHalf < s.
 */
export function scalarIsHighS(s: i32): i32 {
	const nh: i32 = FIELD_TMP + 1 * FIELD_TMP_STRIDE
	loadNHalf(nh)
	return ctLessThan32BE(nh, s)
}

// ── scalarReduce (32-byte input) ────────────────────────────────────────────

/**
 * Reduce a 32-byte BE value mod n. Since the input is at most 2^256 - 1
 * and n > 2^254, at most ~2^2 = 4 subtractions of n bring the value
 * into [0, n). Constant-time via mask-driven conditional subtract.
 *
 * Used at signing time to project (e := H(M)) into Z_n per FIPS 186-5
 * §6.4 step 4, and at verify time for the same purpose.
 */
export function scalarReduce(out: i32, src: i32): void {
	// Copy src into a 33-byte BE work buffer with a leading 0 overflow byte.
	const work: i32 = FIELD_TMP + 2 * FIELD_TMP_STRIDE   // 33 bytes
	store<u8>(work, 0)
	memory.copy(work + 1, src, 32)

	// Subtract n up to 4 times (input < 2^256 < 4n suffices).
	for (let i: i32 = 0; i < 4; i++) {
		ctSubN33BE(work)
	}

	memory.copy(out, work + 1, 32)
}

// ── scalarReduce64 (64-byte input) ──────────────────────────────────────────

/**
 * Reduce a 64-byte BE value mod n. Bit-by-bit binary division: the
 * high-half byte stream is initialised as the running remainder, then
 * the low half is shifted in MSB-first, with conditional subtract of
 * n after each bit. Constant-time throughout: every bit drives a fixed
 * sequence of subtractions.
 *
 * Mirrors curve25519's scalarReduce64 with byte order flipped (BE) and
 * the modulus substituted (n vs L). Slower than a Barrett / Montgomery
 * reduction but simple enough to inspect line-by-line. The RFC 6979 K
 * derivation only produces 32 bytes at a time per HMAC, so this helper
 * is currently NOT exercised by the production sign path; it is kept
 * for parity with curve25519 and for the scalar-mult product reduction
 * inside ./scalar.ts (scalarMul). See the scalarMul comment for the
 * call sequence that drives it.
 */
export function scalarReduce64(out: i32, src: i32): void {
	const work: i32 = FIELD_TMP + 2 * FIELD_TMP_STRIDE   // 33 bytes
	// Initialise remainder with src high-half (bytes 0..31 in BE = MSBs).
	store<u8>(work, 0)
	memory.copy(work + 1, src, 32)
	// Reduce the high half mod n (at most 4 subtractions).
	for (let i: i32 = 0; i < 4; i++) {
		ctSubN33BE(work)
	}

	// Shift in bits from the low half (bytes 32..63 of src), MSB first.
	// For each bit:
	//   work = (work << 1) | bit
	//   if work >= n, work -= n
	for (let byteIdx: i32 = 32; byteIdx < 64; byteIdx++) {
		const byte: u8 = load<u8>(src + byteIdx)
		for (let bitIdx: i32 = 7; bitIdx >= 0; bitIdx--) {
			// Shift work left by 1, MSB-to-LSB byte direction (BE).
			let carry: u32 = 0
			for (let k: i32 = 32; k >= 0; k--) {
				const wk: u32 = load<u8>(work + k) as u32
				const newWk: u32 = ((wk << 1) | carry) & 0xFF
				carry = (wk >> 7) & 1
				store<u8>(work + k, newWk as u8)
			}
			// OR in the next bit from src.
			const bit: u8 = ((byte as u32 >> (bitIdx as u32)) & 1) as u8
			store<u8>(work + 32, load<u8>(work + 32) | bit)
			// Conditional subtract n. work fits in 33 bytes since at any
			// point work < 2n < 2^257.
			ctSubN33BE(work)
		}
	}

	memory.copy(out, work + 1, 32)
}

// ── scalarAdd / scalarSub / scalarNegate ───────────────────────────────────

/**
 * out = (a + b) mod n. Inputs and output are 32-byte BE.
 */
export function scalarAdd(out: i32, a: i32, b: i32): void {
	const work: i32 = FIELD_TMP + 6 * FIELD_TMP_STRIDE  // 33 bytes
	let carry: u32 = 0
	for (let i: i32 = 31; i >= 0; i--) {
		const sum: u32 = (load<u8>(a + i) as u32) + (load<u8>(b + i) as u32) + carry
		store<u8>(work + i + 1, (sum & 0xFF) as u8)
		carry = sum >> 8
	}
	store<u8>(work, carry as u8)

	// Subtract n up to twice (a + b < 2n).
	ctSubN33BE(work)
	ctSubN33BE(work)

	memory.copy(out, work + 1, 32)
}

/**
 * out = (a - b) mod n. Inputs and output are 32-byte BE.
 */
export function scalarSub(out: i32, a: i32, b: i32): void {
	const diff: i32 = FIELD_TMP + 8 * FIELD_TMP_STRIDE  // 32 bytes
	let borrow: u32 = 0
	for (let i: i32 = 31; i >= 0; i--) {
		const ai: i32 = load<u8>(a + i) as i32
		const bi: i32 = load<u8>(b + i) as i32
		const v:  i32 = ai - bi - (borrow as i32)
		store<u8>(diff + i, (v & 0xFF) as u8)
		borrow = ((v >> 31) & 1) as u32
	}
	// If borrow, add n once.
	const nbuf: i32 = FIELD_TMP + 9 * FIELD_TMP_STRIDE
	loadN(nbuf)
	const corr: i32 = FIELD_TMP + 10 * FIELD_TMP_STRIDE
	let c: u32 = 0
	for (let i: i32 = 31; i >= 0; i--) {
		const sum: u32 = (load<u8>(diff + i) as u32) + (load<u8>(nbuf + i) as u32) + c
		store<u8>(corr + i, (sum & 0xFF) as u8)
		c = sum >> 8
	}
	// Select diff or corr based on borrow.
	const mask: u8 = (-(borrow as i32)) as u8
	for (let i: i32 = 0; i < 32; i++) {
		const vd: u8 = load<u8>(diff + i)
		const vc: u8 = load<u8>(corr + i)
		store<u8>(out + i, (vc & mask) | (vd & ~mask))
	}
}

/**
 * out = (n - a) mod n. If a == 0, out = 0; else out = n - a.
 */
export function scalarNegate(out: i32, a: i32): void {
	const zero: i32 = FIELD_TMP + 11 * FIELD_TMP_STRIDE
	memory.fill(zero, 0, 32)
	scalarSub(out, zero, a)
}

// ── scalarMul ───────────────────────────────────────────────────────────────

/**
 * out = (a * b) mod n. Inputs and output are 32-byte BE.
 *
 * Implementation: byte-level schoolbook multiplication producing a
 * 64-byte BE intermediate, then scalarReduce64. Constant-time
 * throughout (no branches on operand bytes).
 *
 * Mirrors curve25519's scalarMulAdd minus the +c term and with BE
 * indexing throughout. Total cost: 32*32 = 1024 byte multiplies
 * (each fits in u32) plus the ~520 iterations of scalarReduce64
 * (each running 32 byte subtractions). The runtime is dwarfed by
 * the scalar-mult point-mul in any signing operation; no benefit
 * from premature Barrett optimization.
 */
export function scalarMul(out: i32, a: i32, b: i32): void {
	// 64-byte BE product buffer.
	const prod: i32 = FIELD_TMP + 12 * FIELD_TMP_STRIDE  // 64 bytes (overlaps slot 13)
	memory.fill(prod, 0, 64)

	// Schoolbook 32x32 → 64 bytes BE. Index from the LSB end:
	//   a[31-i] * b[31-j] contributes to prod[63 - (i + j)] and prod[62 - (i + j)] (carry).
	for (let i: i32 = 0; i < 32; i++) {
		const ai: u32 = load<u8>(a + 31 - i) as u32  // LSB of a first
		let carry: u32 = 0
		for (let j: i32 = 0; j < 32; j++) {
			const bj: u32 = load<u8>(b + 31 - j) as u32
			const dest: i32 = prod + 63 - (i + j)
			const cur: u32 = load<u8>(dest) as u32
			const t: u32 = cur + ai * bj + carry
			store<u8>(dest, (t & 0xFF) as u8)
			carry = t >> 8
		}
		// Propagate final carry through remaining bytes; fixed iteration
		// (no early-exit) so runtime does not depend on operand bytes.
		for (let k: i32 = 32 + i; k < 64; k++) {
			const dest: i32 = prod + 63 - k
			if (dest < prod) break  // bounds guard (i==31, k==63 reaches dest=prod)
			const cur: u32 = load<u8>(dest) as u32
			const t: u32 = cur + carry
			store<u8>(dest, (t & 0xFF) as u8)
			carry = t >> 8
		}
	}

	// Reduce 64 bytes BE to 32 BE mod n.
	scalarReduce64(out, prod)
}

// ── scalarInv: a^(n-2) via Fermat ──────────────────────────────────────────
//
// n - 2 BE = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC63254F
//   (same as n with the last byte 0x4F instead of 0x51).
//
// Square-and-multiply scan over the public constant (n-2). Constant-
// time over the secret operand a; the loop count is fixed at 256
// iterations. Conditional multiply via mask-select (always compute,
// commit on bit).

/**
 * out = a^(-1) mod n via Fermat (a^(n-2)). Caller must ensure
 * a ∈ [1, n-1] (i.e. a != 0); a = 0 returns 0 from this implementation
 * (not an error, but mathematically undefined). The sign / verify
 * call sites guarantee a is canonical and nonzero by virtue of the
 * RFC 6979 K-derivation rejection sampling (which guarantees
 * k ∈ [1, n-1]) and the verify-side strict-gate (which rejects
 * s ∉ [1, n-1] before invoking the inverse).
 */
export function scalarInv(out: i32, a: i32): void {
	// 32-byte BE encoding of (n - 2).
	const eTmp: i32 = FIELD_TMP + 9 * FIELD_TMP_STRIDE  // 32 bytes
	for (let i: i32 = 0; i < 32; i++) {
		store<u8>(eTmp + i, nByte(i))
	}
	// Subtract 2 from the LSB byte.
	store<u8>(eTmp + 31, load<u8>(eTmp + 31) - 2)

	// acc = 1, aCopy = a
	const acc: i32 = FIELD_TMP + 10 * FIELD_TMP_STRIDE
	const aCopy: i32 = FIELD_TMP + 11 * FIELD_TMP_STRIDE
	memory.fill(acc, 0, 32)
	store<u8>(acc + 31, 1)
	memory.copy(aCopy, a, 32)

	// Square-and-multiply, MSB-first over the BE byte stream.
	for (let byteIdx: i32 = 0; byteIdx < 32; byteIdx++) {
		const byte: u32 = load<u8>(eTmp + byteIdx) as u32
		for (let bitIdx: i32 = 7; bitIdx >= 0; bitIdx--) {
			// Square: acc = acc * acc (mod n).
			scalarMul(acc, acc, acc)
			const bit: u32 = (byte >> (bitIdx as u32)) & 1
			// tmp = acc * a
			const tmpSlot: i32 = FIELD_TMP + 15 * FIELD_TMP_STRIDE
			scalarMul(tmpSlot, acc, aCopy)
			// ct-select acc = bit ? tmp : acc
			const mask: u8 = (-(bit as i32)) as u8
			for (let k: i32 = 0; k < 32; k++) {
				const va: u8 = load<u8>(tmpSlot + k)
				const vb: u8 = load<u8>(acc + k)
				store<u8>(acc + k, (va & mask) | (vb & ~mask))
			}
		}
	}

	memory.copy(out, acc, 32)
}
