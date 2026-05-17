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
// src/asm/curve25519/montgomery.ts
//
// X25519 Montgomery ladder per RFC 7748 §5. Constant-time, u-coordinate
// only, no v-coordinate. The ladder maintains two projective points
// (X2:Z2), (X3:Z3) (each two field elements, no Y); each iteration of
// the loop processes one bit of the (clamped) scalar via cswap-and-step.
//
// Caller contract: scalar MUST be already clamped (low 3 bits zeroed,
// bit 254 set, bit 255 cleared). The substrate does not re-clamp; the
// x25519Keygen / x25519DH wrappers in ./x25519.ts handle clamping.

import {
	feAdd, feSub, feMul, feSqr, feMul121666,
	feInv, feFromBytes, feToBytes, feCondSwap,
} from './field'

import { LADDER_TMP_OFFSET, LADDER_TMP_STRIDE } from './buffers'

// ── x25519Ladder ────────────────────────────────────────────────────────────

/**
 * X25519 scalar multiplication: out = X25519(scalar, u).
 *
 * @param out      32-byte output buffer (u-coordinate of [scalar] * U)
 * @param scalar   32-byte LE scalar, MUST be pre-clamped per RFC 7748 §5
 * @param u        32-byte LE u-coordinate of the input point
 *
 * Algorithm (RFC 7748 §5):
 *   x_1 = u
 *   (x_2, z_2) = (1, 0)        # R0
 *   (x_3, z_3) = (u, 1)        # R1
 *   swap = 0
 *   for t = 254 down to 0:
 *     k_t = bit t of scalar
 *     swap ^= k_t
 *     cswap(swap, x_2, x_3); cswap(swap, z_2, z_3)
 *     swap = k_t
 *
 *     A  = x_2 + z_2;  AA = A^2
 *     B  = x_2 - z_2;  BB = B^2
 *     E  = AA - BB
 *     C  = x_3 + z_3
 *     D  = x_3 - z_3
 *     DA = D * A
 *     CB = C * B
 *     x_3 = (DA + CB)^2
 *     z_3 = x_1 * (DA - CB)^2
 *     x_2 = AA * BB
 *     z_2 = E * (AA + 121665 * E)        # a24 = 121665 per §5
 *
 *   cswap(swap, x_2, x_3); cswap(swap, z_2, z_3)
 *   return x_2 * (z_2 ^ (p - 2))
 */
export function x25519Ladder(out: i32, scalar: i32, u: i32): void {
	// 12-slot layout in LADDER_TMP. Each slot is one field element (40 B).
	//
	//   0 x1   (constant input)
	//   1 x2   2 z2   (ladder state R0)
	//   3 x3   4 z3   (ladder state R1)
	//   5 SCR_A   (holds A in early step, reused as scratch for x3-new
	//              and z3-new computation, and for z2-new intermediate)
	//   6 AA
	//   7 SCR_B   (holds B in early step, reused as scratch later)
	//   8 BB
	//   9 E
	//  10 CB    (briefly holds C, then C*B)
	//  11 DA    (briefly holds D, then D*A)
	const x1:     i32 = LADDER_TMP_OFFSET +  0 * LADDER_TMP_STRIDE
	const x2:     i32 = LADDER_TMP_OFFSET +  1 * LADDER_TMP_STRIDE
	const z2:     i32 = LADDER_TMP_OFFSET +  2 * LADDER_TMP_STRIDE
	const x3:     i32 = LADDER_TMP_OFFSET +  3 * LADDER_TMP_STRIDE
	const z3:     i32 = LADDER_TMP_OFFSET +  4 * LADDER_TMP_STRIDE
	const SCR_A:  i32 = LADDER_TMP_OFFSET +  5 * LADDER_TMP_STRIDE
	const AA:     i32 = LADDER_TMP_OFFSET +  6 * LADDER_TMP_STRIDE
	const SCR_B:  i32 = LADDER_TMP_OFFSET +  7 * LADDER_TMP_STRIDE
	const BB:     i32 = LADDER_TMP_OFFSET +  8 * LADDER_TMP_STRIDE
	const E:      i32 = LADDER_TMP_OFFSET +  9 * LADDER_TMP_STRIDE
	const CB:     i32 = LADDER_TMP_OFFSET + 10 * LADDER_TMP_STRIDE
	const DA:     i32 = LADDER_TMP_OFFSET + 11 * LADDER_TMP_STRIDE

	// Decode u-coordinate (feFromBytes masks bit 255 per RFC 7748 §5).
	feFromBytes(x1, u)

	// Initialise R0 = (1, 0), R1 = (u, 1).
	store<i64>(x2 +  0, 1); store<i64>(x2 +  8, 0); store<i64>(x2 + 16, 0); store<i64>(x2 + 24, 0); store<i64>(x2 + 32, 0)
	store<i64>(z2 +  0, 0); store<i64>(z2 +  8, 0); store<i64>(z2 + 16, 0); store<i64>(z2 + 24, 0); store<i64>(z2 + 32, 0)
	memory.copy(x3, x1, 40)
	store<i64>(z3 +  0, 1); store<i64>(z3 +  8, 0); store<i64>(z3 + 16, 0); store<i64>(z3 + 24, 0); store<i64>(z3 + 32, 0)

	let swap: i32 = 0
	for (let t: i32 = 254; t >= 0; t--) {
		const byteIdx: i32 = t >> 3
		const bitIdx:  i32 = t & 7
		const kt: i32 = (load<u8>(scalar + byteIdx) as i32 >> bitIdx) & 1
		const sw: i32 = swap ^ kt

		feCondSwap(x2, x3, sw)
		feCondSwap(z2, z3, sw)
		swap = kt

		// A = x2 + z2, AA = A^2
		feAdd(SCR_A, x2, z2)
		feSqr(AA, SCR_A)

		// B = x2 - z2, BB = B^2
		feSub(SCR_B, x2, z2)
		feSqr(BB, SCR_B)

		// E = AA - BB
		feSub(E, AA, BB)

		// C = x3 + z3 (held in CB slot before being overwritten by C*B)
		// D = x3 - z3 (held in DA slot before being overwritten by D*A)
		feAdd(CB, x3, z3)
		feSub(DA, x3, z3)

		// DA = D * A, CB = C * B
		feMul(DA, DA, SCR_A)
		feMul(CB, CB, SCR_B)

		// z2_new = E * (AA + 121665 * E). Computed BEFORE x2_new so AA is
		// still live. Uses SCR_A and SCR_B as scratch (both dead since
		// step 4).
		feMul121666(SCR_A, E)
		feAdd(SCR_A, AA, SCR_A)
		feMul(z2, E, SCR_A)

		// x2_new = AA * BB
		feMul(x2, AA, BB)

		// x3_new = (DA + CB)^2
		feAdd(SCR_A, DA, CB)
		feSqr(x3, SCR_A)

		// z3_new = x1 * (DA - CB)^2
		feSub(SCR_B, DA, CB)
		feSqr(SCR_B, SCR_B)
		feMul(z3, x1, SCR_B)
	}

	// Final unswap (RFC 7748 §5 last cswap, controlled by the most-
	// recently-seen bit).
	feCondSwap(x2, x3, swap)
	feCondSwap(z2, z3, swap)

	// Affine-conversion: x_out = x2 * z2^(p-2). Reuse z3 as inverse slot.
	feInv(z3, z2)
	feMul(x2, x2, z3)
	feToBytes(out, x2)
}
