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
// src/asm/blake3/compress_simd.ts
//
// BLAKE3 compress4, v128-external SIMD, BLAKE3 §2.2 (compression
// function, including the G quarter-round) lane-parallelized per §5.3
// (SIMD).
//
// Four independent compress operations in parallel; lane K of every
// v128 op corresponds to compress operation K (K ∈ {0..3}). Each of the
// 16 state words v[0..15] is a v128 holding lane K of the K-th compress.
// Each of the 16 message words m[0..15] is likewise a v128 with lane K
// drawn from message-block K.
//
// No row / column shuffles within G (each lane is its own independent
// state), and the BLAKE3 §2.2 Table 2 σ permutation operates on whole
// per-lane message registers as register renames between rounds.
//
// All four lanes share a single flags value (BLAKE3 §2.2, the "d"
// input), so this routine is for batches of same-mode work, e.g. four
// non-final chunk blocks or four sibling parents at one tree level.
// Other inputs (CV, message block, counter, block_len) are per lane,
// gathered from the COMPRESS4_* staging buffers.

import {
	COMPRESS4_CV_IN_OFFSET,
	COMPRESS4_MSG_IN_OFFSET,
	COMPRESS4_CTR_IN_OFFSET,
	COMPRESS4_BLEN_IN_OFFSET,
	COMPRESS4_FLAGS_IN_OFFSET,
	COMPRESS4_OUT_OFFSET,
} from './buffers'
import {
	BLAKE3_IV0, BLAKE3_IV1, BLAKE3_IV2, BLAKE3_IV3,
} from './compress'

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

// Element-wise 32-bit right rotate over i32x4 lanes.
@inline
function rotr32_4(x: v128, n: u32): v128 {
	return v128.or(i32x4.shr_u(x, n), i32x4.shl(x, 32 - n))
}

// Gather lane-K input across 4 buffers spaced `stride` bytes apart.
// Returns a v128 where lane K = u32 at base + K*stride + off.
@inline
function gather(base: i32, stride: i32, off: i32): v128 {
	return pack4_u32(
		load<u32>(base + 0 * stride + off),
		load<u32>(base + 1 * stride + off),
		load<u32>(base + 2 * stride + off),
		load<u32>(base + 3 * stride + off),
	)
}

/**
 * BLAKE3 compress, four lanes in parallel (v128-external SIMD).
 *
 * Inputs (staged at the COMPRESS4_* buffers, lane K at the K-th slot):
 *   - COMPRESS4_CV_IN:    4 × 32-byte input chaining values
 *   - COMPRESS4_MSG_IN:   4 × 64-byte message blocks
 *   - COMPRESS4_CTR_IN:   4 × 8-byte u64 counters (lo at +0, hi at +4)
 *   - COMPRESS4_BLEN_IN:  4 × 4-byte block_len values (BLAKE3 §2.2 "b")
 *   - COMPRESS4_FLAGS_IN: 1 × 4-byte flags value, shared across all lanes
 *
 * Output: COMPRESS4_OUT, 4 × 64 bytes. Compress K's full output occupies
 * bytes K*64 .. K*64+63; the first 32 bytes are the next CV (h'_0..h'_7)
 * and the rest are the XOF half (h'_8..h'_15), bit-equivalent to
 * compress() at COMPRESS_OUT for the same inputs.
 */
export function compress4(): void {
	// Initial state, BLAKE3 §2.2, lane-parallel:
	//   v0..v3   = h0..h3 (per-lane CV halves)
	//   v4..v7   = h4..h7
	//   v8..v11  = IV0..IV3 (splatted across lanes)
	//   v12, v13 = counterLo, counterHi (per lane)
	//   v14      = block_len (per lane)
	//   v15      = flags (shared, splatted)
	let v0: v128 = gather(COMPRESS4_CV_IN_OFFSET, 32,  0)
	let v1: v128 = gather(COMPRESS4_CV_IN_OFFSET, 32,  4)
	let v2: v128 = gather(COMPRESS4_CV_IN_OFFSET, 32,  8)
	let v3: v128 = gather(COMPRESS4_CV_IN_OFFSET, 32, 12)
	let v4: v128 = gather(COMPRESS4_CV_IN_OFFSET, 32, 16)
	let v5: v128 = gather(COMPRESS4_CV_IN_OFFSET, 32, 20)
	let v6: v128 = gather(COMPRESS4_CV_IN_OFFSET, 32, 24)
	let v7: v128 = gather(COMPRESS4_CV_IN_OFFSET, 32, 28)

	// Save initial CV for the §2.2 feed-forward output.
	const h0 = v0, h1 = v1, h2 = v2, h3 = v3
	const h4 = v4, h5 = v5, h6 = v6, h7 = v7

	let v8:  v128 = i32x4.splat(BLAKE3_IV0 as i32)
	let v9:  v128 = i32x4.splat(BLAKE3_IV1 as i32)
	let v10: v128 = i32x4.splat(BLAKE3_IV2 as i32)
	let v11: v128 = i32x4.splat(BLAKE3_IV3 as i32)
	let v12: v128 = gather(COMPRESS4_CTR_IN_OFFSET, 8, 0)
	let v13: v128 = gather(COMPRESS4_CTR_IN_OFFSET, 8, 4)
	let v14: v128 = gather(COMPRESS4_BLEN_IN_OFFSET, 4, 0)
	let v15: v128 = i32x4.splat(load<i32>(COMPRESS4_FLAGS_IN_OFFSET))

	// Message: 16 v128 registers, each holding lane K of m[i] from block K.
	let m0:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64,  0)
	let m1:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64,  4)
	let m2:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64,  8)
	let m3:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 12)
	let m4:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 16)
	let m5:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 20)
	let m6:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 24)
	let m7:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 28)
	let m8:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 32)
	let m9:  v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 36)
	let m10: v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 40)
	let m11: v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 44)
	let m12: v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 48)
	let m13: v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 52)
	let m14: v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 56)
	let m15: v128 = gather(COMPRESS4_MSG_IN_OFFSET, 64, 60)

	// 7-round keyed permutation E(m, v), BLAKE3 §2.2.
	// Per round: 4 column G calls then 4 diagonal G calls. The G function,
	// BLAKE3 §2.2, rotations R1=16, R2=12, R3=8, R4=7:
	//   a = a + b + mx;  d = (d xor a).rotr(16);  c = c + d;  b = (b xor c).rotr(12);
	//   a = a + b + my;  d = (d xor a).rotr(8);   c = c + d;  b = (b xor c).rotr(7);
	for (let r: i32 = 0; r < 7; r++) {
		// Column G_0..G_3: (v0,v4,v8,v12,m0,m1) (v1,v5,v9,v13,m2,m3)
		//                  (v2,v6,v10,v14,m4,m5) (v3,v7,v11,v15,m6,m7)
		v0  = v128.add<i32>(v128.add<i32>(v0,  v4 ), m0)
		v12 = rotr32_4(v128.xor(v12, v0), 16)
		v8  = v128.add<i32>(v8, v12)
		v4  = rotr32_4(v128.xor(v4,  v8), 12)
		v0  = v128.add<i32>(v128.add<i32>(v0,  v4 ), m1)
		v12 = rotr32_4(v128.xor(v12, v0), 8)
		v8  = v128.add<i32>(v8, v12)
		v4  = rotr32_4(v128.xor(v4,  v8), 7)

		v1  = v128.add<i32>(v128.add<i32>(v1,  v5 ), m2)
		v13 = rotr32_4(v128.xor(v13, v1), 16)
		v9  = v128.add<i32>(v9, v13)
		v5  = rotr32_4(v128.xor(v5,  v9), 12)
		v1  = v128.add<i32>(v128.add<i32>(v1,  v5 ), m3)
		v13 = rotr32_4(v128.xor(v13, v1), 8)
		v9  = v128.add<i32>(v9, v13)
		v5  = rotr32_4(v128.xor(v5,  v9), 7)

		v2  = v128.add<i32>(v128.add<i32>(v2,  v6 ), m4)
		v14 = rotr32_4(v128.xor(v14, v2), 16)
		v10 = v128.add<i32>(v10, v14)
		v6  = rotr32_4(v128.xor(v6,  v10), 12)
		v2  = v128.add<i32>(v128.add<i32>(v2,  v6 ), m5)
		v14 = rotr32_4(v128.xor(v14, v2), 8)
		v10 = v128.add<i32>(v10, v14)
		v6  = rotr32_4(v128.xor(v6,  v10), 7)

		v3  = v128.add<i32>(v128.add<i32>(v3,  v7 ), m6)
		v15 = rotr32_4(v128.xor(v15, v3), 16)
		v11 = v128.add<i32>(v11, v15)
		v7  = rotr32_4(v128.xor(v7,  v11), 12)
		v3  = v128.add<i32>(v128.add<i32>(v3,  v7 ), m7)
		v15 = rotr32_4(v128.xor(v15, v3), 8)
		v11 = v128.add<i32>(v11, v15)
		v7  = rotr32_4(v128.xor(v7,  v11), 7)

		// Diagonal G_4..G_7: (v0,v5,v10,v15,m8,m9) (v1,v6,v11,v12,m10,m11)
		//                    (v2,v7,v8,v13,m12,m13) (v3,v4,v9,v14,m14,m15)
		v0  = v128.add<i32>(v128.add<i32>(v0,  v5 ), m8)
		v15 = rotr32_4(v128.xor(v15, v0), 16)
		v10 = v128.add<i32>(v10, v15)
		v5  = rotr32_4(v128.xor(v5,  v10), 12)
		v0  = v128.add<i32>(v128.add<i32>(v0,  v5 ), m9)
		v15 = rotr32_4(v128.xor(v15, v0), 8)
		v10 = v128.add<i32>(v10, v15)
		v5  = rotr32_4(v128.xor(v5,  v10), 7)

		v1  = v128.add<i32>(v128.add<i32>(v1,  v6 ), m10)
		v12 = rotr32_4(v128.xor(v12, v1), 16)
		v11 = v128.add<i32>(v11, v12)
		v6  = rotr32_4(v128.xor(v6,  v11), 12)
		v1  = v128.add<i32>(v128.add<i32>(v1,  v6 ), m11)
		v12 = rotr32_4(v128.xor(v12, v1), 8)
		v11 = v128.add<i32>(v11, v12)
		v6  = rotr32_4(v128.xor(v6,  v11), 7)

		v2  = v128.add<i32>(v128.add<i32>(v2,  v7 ), m12)
		v13 = rotr32_4(v128.xor(v13, v2), 16)
		v8  = v128.add<i32>(v8, v13)
		v7  = rotr32_4(v128.xor(v7,  v8), 12)
		v2  = v128.add<i32>(v128.add<i32>(v2,  v7 ), m13)
		v13 = rotr32_4(v128.xor(v13, v2), 8)
		v8  = v128.add<i32>(v8, v13)
		v7  = rotr32_4(v128.xor(v7,  v8), 7)

		v3  = v128.add<i32>(v128.add<i32>(v3,  v4 ), m14)
		v14 = rotr32_4(v128.xor(v14, v3), 16)
		v9  = v128.add<i32>(v9, v14)
		v4  = rotr32_4(v128.xor(v4,  v9), 12)
		v3  = v128.add<i32>(v128.add<i32>(v3,  v4 ), m15)
		v14 = rotr32_4(v128.xor(v14, v3), 8)
		v9  = v128.add<i32>(v9, v14)
		v4  = rotr32_4(v128.xor(v4,  v9), 7)

		// Message permutation σ between rounds (skip after round 7).
		// BLAKE3 §2.2 Table 2: new_m[i] = old_m[SIGMA[i]] with
		// SIGMA = [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8].
		// Whole-register renames keep the per-lane partitioning.
		if (r < 6) {
			const t0  = m2,  t1  = m6,  t2  = m3,  t3  = m10
			const t4  = m7,  t5  = m0,  t6  = m4,  t7  = m13
			const t8  = m1,  t9  = m11, t10 = m12, t11 = m5
			const t12 = m9,  t13 = m14, t14 = m15, t15 = m8
			m0  = t0;  m1  = t1;  m2  = t2;  m3  = t3
			m4  = t4;  m5  = t5;  m6  = t6;  m7  = t7
			m8  = t8;  m9  = t9;  m10 = t10; m11 = t11
			m12 = t12; m13 = t13; m14 = t14; m15 = t15
		}
	}

	// Feed-forward output, BLAKE3 §2.2:
	//   h'_0..h'_7   = v_0..v_7  XOR v_8..v_15  (next CV)
	//   h'_8..h'_15  = v_8..v_15 XOR h_0..h_7   (XOF tail)
	v0 = v128.xor(v0, v8)
	v1 = v128.xor(v1, v9)
	v2 = v128.xor(v2, v10)
	v3 = v128.xor(v3, v11)
	v4 = v128.xor(v4, v12)
	v5 = v128.xor(v5, v13)
	v6 = v128.xor(v6, v14)
	v7 = v128.xor(v7, v15)
	v8  = v128.xor(v8,  h0)
	v9  = v128.xor(v9,  h1)
	v10 = v128.xor(v10, h2)
	v11 = v128.xor(v11, h3)
	v12 = v128.xor(v12, h4)
	v13 = v128.xor(v13, h5)
	v14 = v128.xor(v14, h6)
	v15 = v128.xor(v15, h7)

	// Deinterleave by lane: compress K's 16 output words become 64 bytes
	// at COMPRESS4_OUT + K*64. extract_lane requires a compile-time
	// constant lane index, so the 64 stores are unrolled explicitly.
	const w = COMPRESS4_OUT_OFFSET

	// Lane 0 (compress 0): bytes 0-63
	store<u32>(w +   0, i32x4.extract_lane(v0,  0) as u32); store<u32>(w +   4, i32x4.extract_lane(v1,  0) as u32)
	store<u32>(w +   8, i32x4.extract_lane(v2,  0) as u32); store<u32>(w +  12, i32x4.extract_lane(v3,  0) as u32)
	store<u32>(w +  16, i32x4.extract_lane(v4,  0) as u32); store<u32>(w +  20, i32x4.extract_lane(v5,  0) as u32)
	store<u32>(w +  24, i32x4.extract_lane(v6,  0) as u32); store<u32>(w +  28, i32x4.extract_lane(v7,  0) as u32)
	store<u32>(w +  32, i32x4.extract_lane(v8,  0) as u32); store<u32>(w +  36, i32x4.extract_lane(v9,  0) as u32)
	store<u32>(w +  40, i32x4.extract_lane(v10, 0) as u32); store<u32>(w +  44, i32x4.extract_lane(v11, 0) as u32)
	store<u32>(w +  48, i32x4.extract_lane(v12, 0) as u32); store<u32>(w +  52, i32x4.extract_lane(v13, 0) as u32)
	store<u32>(w +  56, i32x4.extract_lane(v14, 0) as u32); store<u32>(w +  60, i32x4.extract_lane(v15, 0) as u32)

	// Lane 1 (compress 1): bytes 64-127
	store<u32>(w +  64, i32x4.extract_lane(v0,  1) as u32); store<u32>(w +  68, i32x4.extract_lane(v1,  1) as u32)
	store<u32>(w +  72, i32x4.extract_lane(v2,  1) as u32); store<u32>(w +  76, i32x4.extract_lane(v3,  1) as u32)
	store<u32>(w +  80, i32x4.extract_lane(v4,  1) as u32); store<u32>(w +  84, i32x4.extract_lane(v5,  1) as u32)
	store<u32>(w +  88, i32x4.extract_lane(v6,  1) as u32); store<u32>(w +  92, i32x4.extract_lane(v7,  1) as u32)
	store<u32>(w +  96, i32x4.extract_lane(v8,  1) as u32); store<u32>(w + 100, i32x4.extract_lane(v9,  1) as u32)
	store<u32>(w + 104, i32x4.extract_lane(v10, 1) as u32); store<u32>(w + 108, i32x4.extract_lane(v11, 1) as u32)
	store<u32>(w + 112, i32x4.extract_lane(v12, 1) as u32); store<u32>(w + 116, i32x4.extract_lane(v13, 1) as u32)
	store<u32>(w + 120, i32x4.extract_lane(v14, 1) as u32); store<u32>(w + 124, i32x4.extract_lane(v15, 1) as u32)

	// Lane 2 (compress 2): bytes 128-191
	store<u32>(w + 128, i32x4.extract_lane(v0,  2) as u32); store<u32>(w + 132, i32x4.extract_lane(v1,  2) as u32)
	store<u32>(w + 136, i32x4.extract_lane(v2,  2) as u32); store<u32>(w + 140, i32x4.extract_lane(v3,  2) as u32)
	store<u32>(w + 144, i32x4.extract_lane(v4,  2) as u32); store<u32>(w + 148, i32x4.extract_lane(v5,  2) as u32)
	store<u32>(w + 152, i32x4.extract_lane(v6,  2) as u32); store<u32>(w + 156, i32x4.extract_lane(v7,  2) as u32)
	store<u32>(w + 160, i32x4.extract_lane(v8,  2) as u32); store<u32>(w + 164, i32x4.extract_lane(v9,  2) as u32)
	store<u32>(w + 168, i32x4.extract_lane(v10, 2) as u32); store<u32>(w + 172, i32x4.extract_lane(v11, 2) as u32)
	store<u32>(w + 176, i32x4.extract_lane(v12, 2) as u32); store<u32>(w + 180, i32x4.extract_lane(v13, 2) as u32)
	store<u32>(w + 184, i32x4.extract_lane(v14, 2) as u32); store<u32>(w + 188, i32x4.extract_lane(v15, 2) as u32)

	// Lane 3 (compress 3): bytes 192-255
	store<u32>(w + 192, i32x4.extract_lane(v0,  3) as u32); store<u32>(w + 196, i32x4.extract_lane(v1,  3) as u32)
	store<u32>(w + 200, i32x4.extract_lane(v2,  3) as u32); store<u32>(w + 204, i32x4.extract_lane(v3,  3) as u32)
	store<u32>(w + 208, i32x4.extract_lane(v4,  3) as u32); store<u32>(w + 212, i32x4.extract_lane(v5,  3) as u32)
	store<u32>(w + 216, i32x4.extract_lane(v6,  3) as u32); store<u32>(w + 220, i32x4.extract_lane(v7,  3) as u32)
	store<u32>(w + 224, i32x4.extract_lane(v8,  3) as u32); store<u32>(w + 228, i32x4.extract_lane(v9,  3) as u32)
	store<u32>(w + 232, i32x4.extract_lane(v10, 3) as u32); store<u32>(w + 236, i32x4.extract_lane(v11, 3) as u32)
	store<u32>(w + 240, i32x4.extract_lane(v12, 3) as u32); store<u32>(w + 244, i32x4.extract_lane(v13, 3) as u32)
	store<u32>(w + 248, i32x4.extract_lane(v14, 3) as u32); store<u32>(w + 252, i32x4.extract_lane(v15, 3) as u32)
}
