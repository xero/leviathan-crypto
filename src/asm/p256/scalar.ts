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
// Scalar arithmetic mod n (P-256 base-point order), SP 800-186 §3.2.1.3,
// FIPS 186-5 §6.
//
// n (hex, BE) = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
//               BCE6FAAD A7179E84 F3B9CAC2 FC632551
//
// 32-byte BE wire form throughout. Byte-level reductions mirror
// curve25519/scalar.ts with n substituted for L and BE for LE.
//
// Constant-time: every operation is a fixed-length loop with mask-driven
// selects. scalarInv's exponent (n-2) is a public constant; its bit scan
// is fixed.

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
 * Reduce a 64-byte BE value mod n. High half initialises the running
 * remainder; low half shifts in MSB-first with conditional subtract of n
 * per bit. Constant-time.
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
 * out = (a * b) mod n. 32-byte BE in / out. Byte-level schoolbook
 * (1024 u32 multiplies) into a 64-byte BE intermediate, then
 * scalarReduce64. Constant-time.
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

// ── scalarInv: a^(-1) mod n via Bernstein-Yang safegcd ─────────────────────
//
// Reference: Bernstein & Yang, "Fast constant-time gcd computation and
// modular inversion", eprint 2019/266, §11 "Modular inverse".
//
// Algorithm overview:
//
//   The divstep function (Definition 11.3 of eprint 2019/266):
//
//     divstep(δ, f, g):
//       if δ > 0 and g is odd:
//         return (1 - δ, g, (g - f) / 2)
//       else:
//         return (1 + δ, f, (g + (g & 1) · f) / 2)
//
//   For modular inverse: track (u, v) such that a·u ≡ f (mod n) and
//   a·v ≡ g (mod n). Initialize:
//
//     f = n, g = a, u = 0, v = 1, δ = 1
//
//   After iter(256) divsteps (Theorem 11.2: iter = ⌈(49·256+80)/17⌉ = 743),
//   we have g = 0 and f = ±gcd(n, a) = ±1 (since n is prime, a ∈ [1, n-1]).
//   The invariant a·u ≡ f (mod n) gives a^{-1} = sign(f) · u (mod n).
//
//   Per-divstep update of (u, v) parallels (f, g):
//     swap_cond = (δ > 0) AND (g & 1)
//     (f', g') = swap_cond ? (g, (g - f) / 2)        : (f, (g + (g & 1)·f) / 2)
//     (u', v') = swap_cond ? (v, (v - u) / 2 mod n)  : (u, (v + (g & 1)·u) / 2 mod n)
//     δ'       = swap_cond ? (1 - δ)                 : (1 + δ)
//
// Internal representation:
//   f, g: 9 × u32 LE limbs, signed two's complement. Theorem 11.4 bounds
//   |f|, |g| < 2^256 throughout; the 9th limb absorbs sign extension.
//
//   u, v: 8 × u32 LE limbs, unsigned in [0, n).
//
//   Per-divstep update of v (and similarly for the v' = (v + sign·u)/2
//   mod n case) computes v_pre = v + sign·u as a 9-limb signed value,
//   reduces to [0, n) by conditional add / sub of n, then halves
//   modularly by adding n if odd and right-shifting.
//
// Constant-time discipline:
//   Every conditional in the divstep is on a secret-derived value
//   (g & 1 depends on a's history; δ > 0 depends on past `g & 1` bits).
//   All conditional ops use mask-driven selects and unconditional
//   loops over fixed limb counts. No branch on secret data.
//
// Cost (versus the previous windowed Fermat at ~6.5 ms):
//   743 divsteps × ~85 u32 ops each ≈ 63,000 u32 ops + BE↔LE conversion.
//   Target: ~250-400 µs per scalarInv. ~15-25× faster than windowed.
//
// Audit references:
//   - eprint 2019/266 §11.3 (Definition: divstep)
//   - eprint 2019/266 §11.2 (Theorem: iteration bound)
//   - eprint 2019/266 §11.4 (Theorem: magnitude bound)

// 8-limb LE u32 form of n (the P-256 curve order), reconstructed from
// SP 800-186 §3.2.1.3 via the N00..N31 BE byte constants above. Public
// constant; not derived from any planning document.
//
//   n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
//       BCE6FAAD A7179E84 F3B9CAC2 FC632551   (32 BE hex digits)
//
//   n_le[0] = 0xFC632551  (LSB)
//   n_le[7] = 0xFFFFFFFF  (MSB)
@inline
function loadNLE(buf: i32): void {
	store<u32>(buf +  0, 0xFC632551)
	store<u32>(buf +  4, 0xF3B9CAC2)
	store<u32>(buf +  8, 0xA7179E84)
	store<u32>(buf + 12, 0xBCE6FAAD)
	store<u32>(buf + 16, 0xFFFFFFFF)
	store<u32>(buf + 20, 0xFFFFFFFF)
	store<u32>(buf + 24, 0x00000000)
	store<u32>(buf + 28, 0xFFFFFFFF)
}

// Convert 32 BE bytes at `src` to 8 LE u32 limbs at `dst`.
@inline
function beBytesToLE(dst: i32, src: i32): void {
	for (let i: i32 = 0; i < 8; i++) {
		const base: i32 = src + 28 - (i << 2)
		const v: u32 =
			((load<u8>(base    ) as u32) << 24) |
			((load<u8>(base + 1) as u32) << 16) |
			((load<u8>(base + 2) as u32) <<  8) |
			 (load<u8>(base + 3) as u32)
		store<u32>(dst + (i << 2), v)
	}
}

// Convert 8 LE u32 limbs at `src` to 32 BE bytes at `dst`.
@inline
function leToBytesBE(dst: i32, src: i32): void {
	for (let i: i32 = 0; i < 8; i++) {
		const v: u32 = load<u32>(src + (i << 2))
		const base: i32 = dst + 28 - (i << 2)
		store<u8>(base    , ((v >> 24) & 0xff) as u8)
		store<u8>(base + 1, ((v >> 16) & 0xff) as u8)
		store<u8>(base + 2, ((v >>  8) & 0xff) as u8)
		store<u8>(base + 3,  (v        & 0xff) as u8)
	}
}

// Arithmetic right shift by 1 of a 9-limb signed two's complement
// value. The MSB of limb 8 (sign bit) is preserved by using an i32
// arithmetic shift on the top limb; the bit shifted out of limb i+1
// becomes bit 31 of new limb i.
@inline
function arithShr1_9(buf: i32): void {
	const topOld: i32 = load<i32>(buf + 32)
	const topNew: i32 = topOld >> 1
	store<i32>(buf + 32, topNew)
	let prevBit: u32 = (topOld & 1) as u32
	for (let i: i32 = 7; i >= 0; i--) {
		const v: u32 = load<u32>(buf + (i << 2))
		const newV: u32 = (prevBit << 31) | (v >> 1)
		store<u32>(buf + (i << 2), newV)
		prevBit = v & 1
	}
}

// Conditionally add n (8 LE limbs at `n_le`) to a 9-limb signed value
// at `buf`. `cond` is 0 or 1. n is added if cond = 1.
@inline
function condAddN9(buf: i32, n_le: i32, cond: u32): void {
	const mask: u32 = ((-(cond as i32)) as u32)
	let carry: u64 = 0
	for (let i: i32 = 0; i < 8; i++) {
		const v:  u64 = load<u32>(buf + (i << 2)) as u64
		const nv: u64 = (load<u32>(n_le + (i << 2)) as u64) & (mask as u64)
		const s:  u64 = v + nv + carry
		store<u32>(buf + (i << 2), s as u32)
		carry = s >> 32
	}
	const v9: u32 = load<u32>(buf + 32)
	store<u32>(buf + 32, v9 + (carry as u32))
}

// Conditionally subtract n from a 9-limb signed value. cond is 0 or 1.
@inline
function condSubN9(buf: i32, n_le: i32, cond: u32): void {
	const mask: u32 = ((-(cond as i32)) as u32)
	let borrow: u64 = 0
	for (let i: i32 = 0; i < 8; i++) {
		const v:  u64 = load<u32>(buf + (i << 2)) as u64
		const nv: u64 = (load<u32>(n_le + (i << 2)) as u64) & (mask as u64)
		const d:  u64 = v - nv - borrow
		store<u32>(buf + (i << 2), d as u32)
		borrow = (d >> 63) & 1
	}
	const v9: u32 = load<u32>(buf + 32)
	store<u32>(buf + 32, v9 - (borrow as u32))
}

// Test if a 9-limb signed value is >= n. Branchless: compute the
// subtraction and inspect the borrow + top-limb sign bit. Discards the
// difference; the caller separately decides whether to commit it.
@inline
function geN9(buf: i32, n_le: i32): u32 {
	let borrow: u64 = 0
	for (let i: i32 = 0; i < 8; i++) {
		const v:  u64 = load<u32>(buf + (i << 2)) as u64
		const nv: u64 = load<u32>(n_le + (i << 2)) as u64
		const d:  u64 = v - nv - borrow
		borrow = (d >> 63) & 1
	}
	// Top limb signed: subtract just borrow.
	const top: i32 = load<i32>(buf + 32)
	const topAfter: i32 = top - (borrow as i32)
	// value >= n iff (value - n) >= 0 iff topAfter is non-negative.
	return ((topAfter >> 31) ^ -1) as u32 & 1
}

/**
 * out = a^(-1) mod n via Bernstein-Yang safegcd (eprint 2019/266 §11).
 *
 * Caller must ensure a ∈ [1, n-1]; a = 0 returns 0 (mathematically
 * undefined). The sign / verify call sites guarantee a is canonical
 * and nonzero per RFC 6979 K-derivation and the verify strict-gate.
 *
 * Constant-time over the secret a. The 743-divstep iteration count is
 * the public bound from eprint 2019/266 Theorem 11.2.
 */
export function scalarInv(out: i32, a: i32): void {
	// Scratch layout in FIELD_TMP starting at offset slot 4 (byte 128):
	//   off 128: f       (36 bytes, 9 LE u32 limbs, signed)
	//   off 164: g       (36 bytes, 9 LE u32 limbs, signed)
	//   off 200: u       (32 bytes, 8 LE u32 limbs, unsigned in [0, n))
	//   off 232: v       (32 bytes, 8 LE u32 limbs, unsigned in [0, n))
	//   off 264: n_le    (32 bytes, 8 LE u32 limbs)
	//   off 296: tmpF    (36 bytes)
	//   off 332: tmpG    (36 bytes)
	//   off 368: tmpU    (36 bytes — sized for the 9-limb stage)
	//   off 404: tmpV    (36 bytes)
	// Total: 312 bytes, well within FIELD_TMP (1024 bytes).
	// FIELD_TMP is otherwise unused during scalarInv (scalarMul / point ops
	// are not called from here).
	const base: i32 = FIELD_TMP + 128
	const f:    i32 = base +   0
	const g:    i32 = base +  36
	const u:    i32 = base +  72
	const v:    i32 = base + 104
	const nLE:  i32 = base + 136
	const tmpF: i32 = base + 168
	const tmpG: i32 = base + 204
	const tmpU: i32 = base + 240
	const tmpV: i32 = base + 276

	// Initialise n_le and (f, g, u, v).
	loadNLE(nLE)

	// f = n (8 limbs from nLE) extended to 9 limbs with sign-limb = 0.
	memory.copy(f, nLE, 32)
	store<u32>(f + 32, 0)

	// g = a (8 LE limbs from BE bytes) extended with sign-limb = 0.
	beBytesToLE(g, a)
	store<u32>(g + 32, 0)

	// u = 0 (all 8 limbs zero).
	memory.fill(u, 0, 32)

	// v = 1 (LSB = 1, rest zero).
	memory.fill(v, 0, 32)
	store<u32>(v, 1)

	let delta: i32 = 1

	// 743 divsteps (eprint 2019/266 Theorem 11.2 for 256-bit inputs).
	for (let step: i32 = 0; step < 743; step++) {
		const deltaPos: u32 = (delta > 0 ? 1 : 0) as u32
		const gLsb:     u32 = load<u32>(g) & 1
		const swapCond: u32 = deltaPos & gLsb

		const maskSwap: u32 = ((-(swapCond as i32)) as u32)
		const useCond:  u32 = swapCond | gLsb
		const maskUse:  u32 = ((-(useCond as i32)) as u32)
		const maskNeg:  u32 = maskSwap

		// tmpF = swap_cond ? g : f  (9-limb ct-select)
		for (let i: i32 = 0; i < 9; i++) {
			const fv: u32 = load<u32>(f + (i << 2))
			const gv: u32 = load<u32>(g + (i << 2))
			store<u32>(tmpF + (i << 2), (gv & maskSwap) | (fv & ~maskSwap))
		}

		// tmpG = g + (swap_cond ? -1 : g_lsb) · f, as 9-limb signed.
		//   For sign = -1: add ~f and carry-in 1 (two's complement of f)
		//   For sign = +1: add f
		//   For sign =  0: add 0
		// Encoded via maskUse / maskNeg + initial carry = swapCond.
		{
			let carry: u64 = swapCond as u64
			for (let i: i32 = 0; i < 9; i++) {
				const gv:  u64 = load<u32>(g + (i << 2)) as u64
				const fEff: u32 = (load<u32>(f + (i << 2)) ^ maskNeg) & maskUse
				const s:   u64 = gv + (fEff as u64) + carry
				store<u32>(tmpG + (i << 2), s as u32)
				carry = s >> 32
			}
			// 10th-limb carry dropped (Theorem 11.4 magnitude bound).
		}

		// tmpG /= 2 (arithmetic shift right by 1, sign-preserving).
		arithShr1_9(tmpG)

		// tmpU = swap_cond ? v : u  (8-limb ct-select; 9th limb unused).
		for (let i: i32 = 0; i < 8; i++) {
			const uv: u32 = load<u32>(u + (i << 2))
			const vv: u32 = load<u32>(v + (i << 2))
			store<u32>(tmpU + (i << 2), (vv & maskSwap) | (uv & ~maskSwap))
		}

		// tmpV = v + (swap_cond ? -1 : g_lsb) · u, as 9-limb signed.
		//   Same mask-driven mul-add pattern as for f, but u is 8-limb;
		//   the 9th limb of u's two's-complement extension is
		//   (maskNeg AND maskUse) — all-ones when negating u, zero otherwise.
		{
			let carry: u64 = swapCond as u64
			for (let i: i32 = 0; i < 8; i++) {
				const vv:  u64 = load<u32>(v + (i << 2)) as u64
				const uEff: u32 = (load<u32>(u + (i << 2)) ^ maskNeg) & maskUse
				const s:   u64 = vv + (uEff as u64) + carry
				store<u32>(tmpV + (i << 2), s as u32)
				carry = s >> 32
			}
			// 9th limb: v_high (0) + sign-extended-u_high (maskNeg & maskUse) + carry.
			const u9: u32 = maskNeg & maskUse
			const s9: u64 = (u9 as u64) + carry
			store<u32>(tmpV + 32, s9 as u32)
		}

		// Reduce tmpV to [0, n):
		//   if tmpV < 0 (sign bit set): tmpV += n
		const vNeg: u32 = ((load<i32>(tmpV + 32) >> 31) as u32) & 1
		condAddN9(tmpV, nLE, vNeg)
		//   if tmpV >= n: tmpV -= n
		const vGe: u32 = geN9(tmpV, nLE)
		condSubN9(tmpV, nLE, vGe)

		// Modular halve: if tmpV is odd, add n (n is odd, so tmpV + n is
		// even), then arithmetic-shift right by 1. Result is in [0, n).
		const vOdd: u32 = load<u32>(tmpV) & 1
		condAddN9(tmpV, nLE, vOdd)
		arithShr1_9(tmpV)

		// Commit: tmpF → f, tmpG → g, tmpU → u, tmpV[0..7] → v.
		memory.copy(f, tmpF, 36)
		memory.copy(g, tmpG, 36)
		memory.copy(u, tmpU, 32)
		memory.copy(v, tmpV, 32)

		// δ_new = swap_cond ? (1 - δ) : (1 + δ)
		// Branch-free: δ_new = (1 - 2·swap_cond) · δ + 1
		delta = (1 - 2 * (swapCond as i32)) * delta + 1
	}

	// At termination: f = ±1 (since gcd(n, a) = 1) and a·u ≡ f (mod n).
	// If f is negative (sign bit of limb 8 set), negate u mod n.
	const fNeg: u32 = ((load<i32>(f + 32) >> 31) as u32) & 1

	// Compute (n - u) into tmpU (8-limb), constant-time. n - u ∈ (0, n] for
	// u ∈ [0, n); for u = 0 it equals n, which is non-canonical. The valid
	// inverse case has u ∈ [1, n-1] so n - u is in [1, n-1]. We still
	// produce the canonical answer by handling the u = 0 corner: if u = 0,
	// don't subtract from n; return 0. This corner is mathematically
	// degenerate (a = 0 input), but the wipe shape stays uniform.
	{
		let borrow: u64 = 0
		for (let i: i32 = 0; i < 8; i++) {
			const nv: u64 = load<u32>(nLE + (i << 2)) as u64
			const uv: u64 = load<u32>(u + (i << 2)) as u64
			const d:  u64 = nv - uv - borrow
			store<u32>(tmpU + (i << 2), d as u32)
			borrow = (d >> 63) & 1
		}
	}

	// If u was zero, tmpU is now n; mask it to zero in that case to keep
	// canonical. Test: u == 0 by OR-folding limbs.
	let uOr: u32 = 0
	for (let i: i32 = 0; i < 8; i++) uOr |= load<u32>(u + (i << 2))
	const uZero: u32 = (uOr | ((-(uOr as i32)) as u32)) >> 31 ^ 1  // 1 if u == 0
	// If u was zero, force tmpU to zero. (Mask: 0 if u == 0, ~0 otherwise.)
	const tmpUMask: u32 = ((-(((1 - uZero) as i32))) as u32)
	for (let i: i32 = 0; i < 8; i++) {
		const w: u32 = load<u32>(tmpU + (i << 2))
		store<u32>(tmpU + (i << 2), w & tmpUMask)
	}

	// out_le = fNeg ? tmpU : u
	const maskFNeg: u32 = ((-(fNeg as i32)) as u32)
	for (let i: i32 = 0; i < 8; i++) {
		const uv:  u32 = load<u32>(u    + (i << 2))
		const tv:  u32 = load<u32>(tmpU + (i << 2))
		store<u32>(tmpV + (i << 2), (tv & maskFNeg) | (uv & ~maskFNeg))
	}

	// Convert tmpV (LE limbs) to 32 BE bytes at out.
	leToBytesBE(out, tmpV)
}
