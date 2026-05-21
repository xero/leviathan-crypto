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
// src/asm/blake3/compress.ts
//
// BLAKE3 compression function, v128-internal SIMD.
// BLAKE3 specification §2.2 (compression function) and §2.2 Table 2
// (message permutation). The 7-round permutation E(m, v) is the
// BLAKE2s round function with a fixed round count.
//
// State layout: 4 v128 row registers, each holding 4 × u32 lanes.
//   row0 = [v0, v1,  v2,  v3 ]   = h0..h3
//   row1 = [v4, v5,  v6,  v7 ]   = h4..h7
//   row2 = [v8, v9,  v10, v11]   = IV0..IV3
//   row3 = [v12,v13, v14, v15]   = counterLo, counterHi, blockLen, flags
//
// Column G_0..G_3 run all four columns in parallel; one v128 op per state
// update step. Diagonal G_4..G_7 are made columnar by rotating rows
// 1, 2, 3 left by 1, 2, 3 lanes respectively, then the same column
// pipeline runs and the rotations are undone.

import { MSG_OFFSET } from './buffers'

// BLAKE3 §2.2 Table 1, IV constants. Identical to the SHA-256 initial
// hash values per FIPS 180-4 §5.3.3 (BLAKE3 inherits the BLAKE2s setup).
// Exported so chunk / parent / XOF code can seed CVs.
export const BLAKE3_IV0: u32 = 0x6a09e667
export const BLAKE3_IV1: u32 = 0xbb67ae85
export const BLAKE3_IV2: u32 = 0x3c6ef372
export const BLAKE3_IV3: u32 = 0xa54ff53a
export const BLAKE3_IV4: u32 = 0x510e527f
export const BLAKE3_IV5: u32 = 0x9b05688c
export const BLAKE3_IV6: u32 = 0x1f83d9ab
export const BLAKE3_IV7: u32 = 0x5be0cd19

// BLAKE3 §2.2 Table 2, message permutation σ applied between rounds.
// After each round (except the last), new_m[i] = old_m[SIGMA[i]].
const SIGMA: StaticArray<i32> = [
	2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
]

// Element-wise 32-bit right rotate over i32x4 lanes.
@inline
function rotr32_v(x: v128, n: u32): v128 {
	return v128.or(i32x4.shr_u(x, n), i32x4.shl(x, 32 - n))
}

// Build a v128 with 4 i32 lanes from runtime u32 values.
@inline
function pack4_u32(w0: u32, w1: u32, w2: u32, w3: u32): v128 {
	return i32x4.replace_lane(
		i32x4.replace_lane(
			i32x4.replace_lane(i32x4.splat(w0 as i32), 1, w1 as i32),
			2, w2 as i32,
		),
		3, w3 as i32,
	)
}

/**
 * Single-block BLAKE3 compression, BLAKE3 §2.2.
 *
 * Reads the 32-byte input chaining value at `cvOff`, the 64-byte message
 * block at `blockOff`, and the supplied counter / block_len / flags, and
 * writes the full 64-byte compression output at `outOff`. The first 32
 * bytes of the output are the next chaining value used by chunk / parent
 * assembly; the full 64 bytes are the XOF block used by the §2.6 reader.
 *
 * The message block is staged into MSG_OFFSET and permuted in place
 * between rounds, so the caller's `blockOff` buffer is left intact unless
 * `blockOff == MSG_OFFSET`.
 */
export function compress(
	cvOff:     i32,
	blockOff:  i32,
	counterLo: u32,
	counterHi: u32,
	blockLen:  u32,
	flags:     u32,
	outOff:    i32,
): void {
	// Stage caller's message into scratch so the round-wise permutation
	// can mutate freely without disturbing the caller's input region.
	if (blockOff != MSG_OFFSET) memory.copy(MSG_OFFSET, blockOff, 64)

	// Initial state, BLAKE3 §2.2:
	//   v0..v3   = h0..h3
	//   v4..v7   = h4..h7
	//   v8..v11  = IV0..IV3
	//   v12..v15 = t0, t1, b, d
	let row0: v128 = v128.load(cvOff)
	let row1: v128 = v128.load(cvOff + 16)
	let row2: v128 = pack4_u32(BLAKE3_IV0, BLAKE3_IV1, BLAKE3_IV2, BLAKE3_IV3)
	let row3: v128 = pack4_u32(counterLo, counterHi, blockLen, flags)

	// 7-round keyed permutation E(m, v), BLAKE3 §2.2.
	for (let r: i32 = 0; r < 7; r++) {
		// Pull message words for this round. Column G consumes m0..m7
		// (m_{2i+0} and m_{2i+1} for i=0..3); diagonal G consumes m8..m15.
		const m0123: v128 = v128.load(MSG_OFFSET +  0)  // [m0, m1, m2, m3]
		const m4567: v128 = v128.load(MSG_OFFSET + 16)  // [m4, m5, m6, m7]
		const m89ab: v128 = v128.load(MSG_OFFSET + 32)  // [m8, m9, m10, m11]
		const mcdef: v128 = v128.load(MSG_OFFSET + 48)  // [m12, m13, m14, m15]

		// Column G_0..G_3 inputs.
		//   m_col_lo = [m0, m2, m4, m6]  (m_{2i+0} for i=0..3)
		//   m_col_hi = [m1, m3, m5, m7]  (m_{2i+1} for i=0..3)
		const mColLo: v128 = v128.shuffle<i32>(m0123, m4567, 0, 2, 4, 6)
		const mColHi: v128 = v128.shuffle<i32>(m0123, m4567, 1, 3, 5, 7)

		// Column G in parallel across all four columns of the state.
		// BLAKE3 §2.2 G function, rotations R1=16, R2=12, R3=8, R4=7.
		row0 = v128.add<i32>(v128.add<i32>(row0, row1), mColLo)
		row3 = rotr32_v(v128.xor(row3, row0), 16)
		row2 = v128.add<i32>(row2, row3)
		row1 = rotr32_v(v128.xor(row1, row2), 12)
		row0 = v128.add<i32>(v128.add<i32>(row0, row1), mColHi)
		row3 = rotr32_v(v128.xor(row3, row0), 8)
		row2 = v128.add<i32>(row2, row3)
		row1 = rotr32_v(v128.xor(row1, row2), 7)

		// Diagonalize so that (v0,v5,v10,v15), (v1,v6,v11,v12),
		// (v2,v7,v8,v13), (v3,v4,v9,v14) become the columns of the
		// rotated view: shift row1 left 1, row2 left 2, row3 left 3.
		row1 = v128.shuffle<i32>(row1, row1, 1, 2, 3, 0)
		row2 = v128.shuffle<i32>(row2, row2, 2, 3, 0, 1)
		row3 = v128.shuffle<i32>(row3, row3, 3, 0, 1, 2)

		// Diagonal G_4..G_7 inputs.
		//   m_diag_lo = [m8, m10, m12, m14]
		//   m_diag_hi = [m9, m11, m13, m15]
		const mDiagLo: v128 = v128.shuffle<i32>(m89ab, mcdef, 0, 2, 4, 6)
		const mDiagHi: v128 = v128.shuffle<i32>(m89ab, mcdef, 1, 3, 5, 7)

		row0 = v128.add<i32>(v128.add<i32>(row0, row1), mDiagLo)
		row3 = rotr32_v(v128.xor(row3, row0), 16)
		row2 = v128.add<i32>(row2, row3)
		row1 = rotr32_v(v128.xor(row1, row2), 12)
		row0 = v128.add<i32>(v128.add<i32>(row0, row1), mDiagHi)
		row3 = rotr32_v(v128.xor(row3, row0), 8)
		row2 = v128.add<i32>(row2, row3)
		row1 = rotr32_v(v128.xor(row1, row2), 7)

		// Undiagonalize.
		row1 = v128.shuffle<i32>(row1, row1, 3, 0, 1, 2)
		row2 = v128.shuffle<i32>(row2, row2, 2, 3, 0, 1)
		row3 = v128.shuffle<i32>(row3, row3, 1, 2, 3, 0)

		// BLAKE3 §2.2: "After each round (except the last...) the message
		// words are permuted according to Table 2." Skip after round 7.
		if (r < 6) {
			const p0  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 0]) << 2))
			const p1  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 1]) << 2))
			const p2  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 2]) << 2))
			const p3  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 3]) << 2))
			const p4  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 4]) << 2))
			const p5  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 5]) << 2))
			const p6  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 6]) << 2))
			const p7  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 7]) << 2))
			const p8  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 8]) << 2))
			const p9  = load<u32>(MSG_OFFSET + (unchecked(SIGMA[ 9]) << 2))
			const p10 = load<u32>(MSG_OFFSET + (unchecked(SIGMA[10]) << 2))
			const p11 = load<u32>(MSG_OFFSET + (unchecked(SIGMA[11]) << 2))
			const p12 = load<u32>(MSG_OFFSET + (unchecked(SIGMA[12]) << 2))
			const p13 = load<u32>(MSG_OFFSET + (unchecked(SIGMA[13]) << 2))
			const p14 = load<u32>(MSG_OFFSET + (unchecked(SIGMA[14]) << 2))
			const p15 = load<u32>(MSG_OFFSET + (unchecked(SIGMA[15]) << 2))
			store<u32>(MSG_OFFSET +  0, p0 ); store<u32>(MSG_OFFSET +  4, p1 )
			store<u32>(MSG_OFFSET +  8, p2 ); store<u32>(MSG_OFFSET + 12, p3 )
			store<u32>(MSG_OFFSET + 16, p4 ); store<u32>(MSG_OFFSET + 20, p5 )
			store<u32>(MSG_OFFSET + 24, p6 ); store<u32>(MSG_OFFSET + 28, p7 )
			store<u32>(MSG_OFFSET + 32, p8 ); store<u32>(MSG_OFFSET + 36, p9 )
			store<u32>(MSG_OFFSET + 40, p10); store<u32>(MSG_OFFSET + 44, p11)
			store<u32>(MSG_OFFSET + 48, p12); store<u32>(MSG_OFFSET + 52, p13)
			store<u32>(MSG_OFFSET + 56, p14); store<u32>(MSG_OFFSET + 60, p15)
		}
	}

	// Feed-forward output, BLAKE3 §2.2:
	//   h'_0..h'_7  = v_0..v_7  XOR v_8..v_15
	//   h'_8..h'_15 = v_8..v_15 XOR h_0..h_7
	const h0: v128 = v128.load(cvOff)
	const h1: v128 = v128.load(cvOff + 16)

	v128.store(outOff +  0, v128.xor(row0, row2))
	v128.store(outOff + 16, v128.xor(row1, row3))
	v128.store(outOff + 32, v128.xor(row2, h0))
	v128.store(outOff + 48, v128.xor(row3, h1))
}
