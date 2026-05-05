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
// src/asm/aes/aes.ts
//
// AES-128/192/256 encrypt + decrypt — bitsliced over v128 (8 blocks parallel).
// Spec: NIST FIPS 197-upd1 (2023), §5.1, §5.2, §5.3.5, Appendix B.
// Bitsliced layout, ShiftRows-as-shuffle, MixColumns formulas:
//   Käsper-Schwabe 2009 (CHES) §4.1, §4.3, §4.4 + Appendix A.
// S-box (forward + inverse): imported from sbox.ts (Canright tower-field).
//
// Decrypt uses the FIPS 197 §5.3.5 Equivalent Inverse Cipher: the round
// loop mirrors encrypt (InvSubBytes / InvShiftRows / InvMixColumns /
// AddRoundKey), and round keys 1..Nr-1 have InvMixColumns applied at
// key-schedule time so that AddRoundKey reuses the existing structure.
//
// All three key sizes share one parameterised key schedule (FIPS 197 §5.2
// Algorithm 2, with the AES-256 extra-SubWord branch on lines 11–12) and
// one parameterised round loop driven by an Nr value persisted in
// NR_BUFFER between loadKey() and encryptBlock_8x()/decryptBlock_8x().

import {
	KEY_OFFSET,
	BLOCK_PT_OFFSET, BLOCK_CT_OFFSET,
	BLOCK_PT_8X_OFFSET, BLOCK_CT_8X_OFFSET,
	ROUND_KEYS_OFFSET,
	BITSLICED_STATE_OFFSET,
	KEY_SCHEDULE_SCRATCH_OFFSET, KEY_SCHEDULE_SCRATCH_SIZE,
	INV_ROUND_KEYS_OFFSET,
	NR_OFFSET,
	H_OFFSET,
} from './buffers'
import { sboxBitsliced, invSboxBitsliced } from './sbox'
import { gf128InitTable } from './gf128'

// ── Bitsliced state slot helpers ────────────────────────────────────────────

@inline function bget(k: i32): v128 {
	return v128.load(BITSLICED_STATE_OFFSET + (k << 4));
}
@inline function bset(k: i32, v: v128): void {
	v128.store(BITSLICED_STATE_OFFSET + (k << 4), v);
}

// ── Bit transposition (Käsper-Schwabe §4.1) ─────────────────────────────────
//
// Input: 128 bytes at `srcOffset`, organised as 8 contiguous 16-byte AES blocks
// in FIPS 197 input-byte order.
//
// Output: 8 v128 registers at `dstOffset`. Register state[k] holds bit-k from
// every byte across all 8 blocks. Within state[k], byte position j ∈ {0..15}
// corresponds to AES state row r = j/4, column c = j%4 (row-major). Within
// byte j of state[k], the 8 bits are bit-k of that state-position from blocks
// 0..7.
//
// FIPS 197 §3.4: state[r,c] = in[r + 4c]. So bitsliced byte j corresponds to
// plaintext byte at offset (j%4)*4 + j/4 within each block. The K-S layout
// fuses a per-block 4×4 byte transpose ("row-by-row" reorder) with an 8×8
// bit-matrix transpose at every byte position. The two factors operate on
// orthogonal axes — byte position vs. bit-position-within-byte — so they
// commute, and the K-S transpose is its own inverse: transposeIn and
// transposeOut share one implementation modulo source/destination offsets.
//
// Implementation: K-S §4.1 layered XOR/shuffle. The byte-shuffle pattern
// [0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15] is self-inverse (it represents
// the 4×4 transpose of an AES state square). The 8×8 bit-matrix transpose
// uses three delta-swap stages with strides {4, 2, 1} and masks {0x0F, 0x33,
// 0x55} (Hacker's Delight §7-2). 92 v128 operations total — replaces ~2050
// scalar bit-gathers from the prior implementation.

@inline function transpose8x8(srcOffset: i32, dstOffset: i32): void {
	// Step A — load 8 input registers and apply the per-register byte-shuffle.
	// The shuffle is its own inverse, so the same indices serve transposeIn
	// (FIPS column-major → K-S row-by-row) and transposeOut (the inverse).
	let a0 = v128.shuffle<i8>(
		v128.load(srcOffset +   0), v128.load(srcOffset +   0),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	let a1 = v128.shuffle<i8>(
		v128.load(srcOffset +  16), v128.load(srcOffset +  16),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	let a2 = v128.shuffle<i8>(
		v128.load(srcOffset +  32), v128.load(srcOffset +  32),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	let a3 = v128.shuffle<i8>(
		v128.load(srcOffset +  48), v128.load(srcOffset +  48),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	let a4 = v128.shuffle<i8>(
		v128.load(srcOffset +  64), v128.load(srcOffset +  64),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	let a5 = v128.shuffle<i8>(
		v128.load(srcOffset +  80), v128.load(srcOffset +  80),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	let a6 = v128.shuffle<i8>(
		v128.load(srcOffset +  96), v128.load(srcOffset +  96),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	let a7 = v128.shuffle<i8>(
		v128.load(srcOffset + 112), v128.load(srcOffset + 112),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);

	// Step B — 8×8 bit-matrix transpose, replicated across all 16 byte
	// positions. After all three stages, M[b][k] = (bit-k of byte j of input
	// register b after step A) ends up at (bit-b of byte j of output register
	// k). Verification: standard delta-swap of an N×N bit-matrix where each
	// stage flips bits whose row/column indices differ in the given bit
	// position — three stages compose to a full row/column swap.
	const M_0F = i8x16.splat(<i8>0x0F);
	const M_33 = i8x16.splat(<i8>0x33);
	const M_55 = i8x16.splat(<i8>0x55);

	let t: v128;

	// Stage 1 — stride 4, shift 4. Pairs (0,4) (1,5) (2,6) (3,7).
	t  = v128.and(v128.xor(a4, i8x16.shr_u(a0, 4)), M_0F);
	a4 = v128.xor(a4, t);
	a0 = v128.xor(a0, i8x16.shl(t, 4));
	t  = v128.and(v128.xor(a5, i8x16.shr_u(a1, 4)), M_0F);
	a5 = v128.xor(a5, t);
	a1 = v128.xor(a1, i8x16.shl(t, 4));
	t  = v128.and(v128.xor(a6, i8x16.shr_u(a2, 4)), M_0F);
	a6 = v128.xor(a6, t);
	a2 = v128.xor(a2, i8x16.shl(t, 4));
	t  = v128.and(v128.xor(a7, i8x16.shr_u(a3, 4)), M_0F);
	a7 = v128.xor(a7, t);
	a3 = v128.xor(a3, i8x16.shl(t, 4));

	// Stage 2 — stride 2, shift 2. Pairs (0,2) (1,3) (4,6) (5,7).
	t  = v128.and(v128.xor(a2, i8x16.shr_u(a0, 2)), M_33);
	a2 = v128.xor(a2, t);
	a0 = v128.xor(a0, i8x16.shl(t, 2));
	t  = v128.and(v128.xor(a3, i8x16.shr_u(a1, 2)), M_33);
	a3 = v128.xor(a3, t);
	a1 = v128.xor(a1, i8x16.shl(t, 2));
	t  = v128.and(v128.xor(a6, i8x16.shr_u(a4, 2)), M_33);
	a6 = v128.xor(a6, t);
	a4 = v128.xor(a4, i8x16.shl(t, 2));
	t  = v128.and(v128.xor(a7, i8x16.shr_u(a5, 2)), M_33);
	a7 = v128.xor(a7, t);
	a5 = v128.xor(a5, i8x16.shl(t, 2));

	// Stage 3 — stride 1, shift 1. Pairs (0,1) (2,3) (4,5) (6,7).
	t  = v128.and(v128.xor(a1, i8x16.shr_u(a0, 1)), M_55);
	a1 = v128.xor(a1, t);
	a0 = v128.xor(a0, i8x16.shl(t, 1));
	t  = v128.and(v128.xor(a3, i8x16.shr_u(a2, 1)), M_55);
	a3 = v128.xor(a3, t);
	a2 = v128.xor(a2, i8x16.shl(t, 1));
	t  = v128.and(v128.xor(a5, i8x16.shr_u(a4, 1)), M_55);
	a5 = v128.xor(a5, t);
	a4 = v128.xor(a4, i8x16.shl(t, 1));
	t  = v128.and(v128.xor(a7, i8x16.shr_u(a6, 1)), M_55);
	a7 = v128.xor(a7, t);
	a6 = v128.xor(a6, i8x16.shl(t, 1));

	// Step C — store transposed result.
	v128.store(dstOffset +   0, a0);
	v128.store(dstOffset +  16, a1);
	v128.store(dstOffset +  32, a2);
	v128.store(dstOffset +  48, a3);
	v128.store(dstOffset +  64, a4);
	v128.store(dstOffset +  80, a5);
	v128.store(dstOffset +  96, a6);
	v128.store(dstOffset + 112, a7);
}

/** 8-blocks input → bitsliced state. K-S §4.1 layered XOR/shuffle. */
function transposeIn(): void {
	transpose8x8(BLOCK_PT_8X_OFFSET, BITSLICED_STATE_OFFSET);
}

/** Bitsliced state → 8-blocks output. Same kernel — the K-S transpose is its
 *  own inverse (byte-shuffle and bit-transpose are involutions on orthogonal
 *  axes). */
function transposeOut(): void {
	transpose8x8(BITSLICED_STATE_OFFSET, BLOCK_CT_8X_OFFSET);
}

// ── Single-block transpose (BLOCK_PT/CT direct path) ───────────────────────
//
// `encryptBlock` / `decryptBlock` sit on the per-block hot path of AES-GCM-SIV
// (`sivCtrXform` calls them once per counter block). The 8×8 transpose above
// is amortised across 8 parallel blocks; for the atomic case we previously
// padded BLOCK_PT_8X with 7 zero blocks and then ran the full 8x transpose,
// which paid 92 v128 ops per direction plus a 112-byte zero-fill per call.
//
// `transposeIn1` / `transposeOut1` work directly on the 16-byte BLOCK_PT
// and BLOCK_CT buffers and never touch BLOCK_PT_8X / BLOCK_CT_8X. The
// bitsliced state register state[k] still holds bit-k of byte-j across
// 8 lanes; the single-block path populates lane 0 (bit 0 of each state[k]
// byte) and leaves lanes 1..7 of each byte zero. The 8x kernel then runs
// as before — its work on the dummy lanes is unchanged (it computes
// AES(0) seven times in parallel and we ignore the result), but we save
// the input-side byte-fill and 4× the transpose op count.

/**
 * Single-block transposeIn — read BLOCK_PT (16 bytes), produce a bitsliced
 * state where lane 0 of each state[k] byte holds block-0's bit-k and lanes
 * 1..7 are zero.
 *
 * Steps:
 *   1. Apply the K-S §4.1 4×4 byte-shuffle (FIPS column-major →
 *      K-S row-by-row). The shuffle is identical to step A of `transpose8x8`.
 *   2. For each bit k ∈ {0..7}: state[k][j] = (shuffled[j] >> k) & 1, with
 *      bits 1..7 of each byte zeroed (the dummy lanes).
 */
@inline function transposeIn1(): void {
	const blk = v128.shuffle<i8>(
		v128.load(BLOCK_PT_OFFSET), v128.load(BLOCK_PT_OFFSET),
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	const ONE = i8x16.splat(<i8>1);
	v128.store(BITSLICED_STATE_OFFSET +   0, v128.and(blk, ONE));
	v128.store(BITSLICED_STATE_OFFSET +  16, v128.and(i8x16.shr_u(blk, 1), ONE));
	v128.store(BITSLICED_STATE_OFFSET +  32, v128.and(i8x16.shr_u(blk, 2), ONE));
	v128.store(BITSLICED_STATE_OFFSET +  48, v128.and(i8x16.shr_u(blk, 3), ONE));
	v128.store(BITSLICED_STATE_OFFSET +  64, v128.and(i8x16.shr_u(blk, 4), ONE));
	v128.store(BITSLICED_STATE_OFFSET +  80, v128.and(i8x16.shr_u(blk, 5), ONE));
	v128.store(BITSLICED_STATE_OFFSET +  96, v128.and(i8x16.shr_u(blk, 6), ONE));
	v128.store(BITSLICED_STATE_OFFSET + 112, v128.and(i8x16.shr_u(blk, 7), ONE));
}

/**
 * Single-block transposeOut — read the bitsliced state, reconstruct block 0
 * by extracting bit-0 of each state[k] byte and writing the result to
 * BLOCK_CT. Bits 1..7 of each state[k] byte hold AES(0) results for the
 * seven dummy lanes and are masked out.
 *
 * Steps (inverse of `transposeIn1`):
 *   1. For each k: take bit 0 of state[k] byte j, shift left by k, OR into
 *      the running accumulator.
 *   2. Apply the K-S §4.1 4×4 byte-shuffle (self-inverse — restores FIPS
 *      column-major byte order) and store to BLOCK_CT.
 */
@inline function transposeOut1(): void {
	const ONE = i8x16.splat(<i8>1);
	let out = v128.and(v128.load(BITSLICED_STATE_OFFSET +   0), ONE);
	out = v128.or(out, i8x16.shl(v128.and(v128.load(BITSLICED_STATE_OFFSET +  16), ONE), 1));
	out = v128.or(out, i8x16.shl(v128.and(v128.load(BITSLICED_STATE_OFFSET +  32), ONE), 2));
	out = v128.or(out, i8x16.shl(v128.and(v128.load(BITSLICED_STATE_OFFSET +  48), ONE), 3));
	out = v128.or(out, i8x16.shl(v128.and(v128.load(BITSLICED_STATE_OFFSET +  64), ONE), 4));
	out = v128.or(out, i8x16.shl(v128.and(v128.load(BITSLICED_STATE_OFFSET +  80), ONE), 5));
	out = v128.or(out, i8x16.shl(v128.and(v128.load(BITSLICED_STATE_OFFSET +  96), ONE), 6));
	out = v128.or(out, i8x16.shl(v128.and(v128.load(BITSLICED_STATE_OFFSET + 112), ONE), 7));
	out = v128.shuffle<i8>(out, out,
		0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	);
	v128.store(BLOCK_CT_OFFSET, out);
}

// ── ShiftRows (Käsper-Schwabe §4.3 + FIPS 197 §5.1.2) ──────────────────────
//
// In K-S' row-major bitsliced layout, ShiftRows permutes the 16 bytes in
// each bitsliced register according to a uniform pattern. Per design notes
// §3, the shuffle indices are [0,1,2,3, 5,6,7,4, 10,11,8,9, 15,12,13,14].
// InvShiftRows is the inverse permutation [0,1,2,3, 7,4,5,6, 10,11,8,9,
// 13,14,15,12] (row 0 unchanged; row 1 right-by-1; row 2 self-inverse;
// row 3 right-by-3) — FIPS 197 §5.3.1.

/**
 * Apply ShiftRows uniformly to all 8 bitsliced state registers.
 * Reference: Käsper-Schwabe 2009 §4.3.
 */
function shiftRows(): void {
	for (let k: i32 = 0; k < 8; k++) {
		const r = bget(k);
		bset(k, v128.shuffle<i8>(r, r,
			0, 1, 2, 3,
			5, 6, 7, 4,
			10, 11, 8, 9,
			15, 12, 13, 14,
		));
	}
}

/**
 * Apply InvShiftRows uniformly to all 8 bitsliced state registers.
 * Reference: FIPS 197 §5.3.1 (inverse permutation of `shiftRows`).
 */
function invShiftRows(): void {
	for (let k: i32 = 0; k < 8; k++) {
		const r = bget(k);
		bset(k, v128.shuffle<i8>(r, r,
			0, 1, 2, 3,
			7, 4, 5, 6,
			10, 11, 8, 9,
			13, 14, 15, 12,
		));
	}
}

// ── MixColumns (Käsper-Schwabe §4.4 + Appendix A) ──────────────────────────
//
// In bitsliced row-major layout, "shift one row down" = byte rotation by 4
// (= bit rotation by 32) within each 128-bit register. K-S writes this as
// `rl32`. Two-row-down = `rl64` = byte rotation by 8.
//
// Per K-S Appendix A:
//   b[0] = (a[7] ⊕ rl32 a[7]) ⊕ rl32 a[0] ⊕ rl64(a[0] ⊕ rl32 a[0])
//   b[1] = (a[0] ⊕ rl32 a[0]) ⊕ (a[7] ⊕ rl32 a[7]) ⊕ rl32 a[1] ⊕ rl64(a[1] ⊕ rl32 a[1])
//   ... (full table in design notes §4)

/**
 * "Look one row down" byte permutation: dst[p] = src[(p+4) mod 16].
 * Used by K-S MixColumns to bring a_{i+1,j} into position (i,j).
 *
 * Note on K-S' "rl32" notation: the K-S paper writes this as "rotate left by
 * 32 bits", but the operational meaning (per K-S §4.4) is to produce a
 * register where byte at row-major index p reads from row p/4+1's value at
 * column p%4 — i.e., shift the indices DOWN by 4. That's what this shuffle
 * implements. Verified against FIPS 197 §5.1.3 by single-bit input
 * cross-check during development.
 */
@inline function rl32(x: v128): v128 {
	return v128.shuffle<i8>(x, x,
		4, 5, 6, 7,
		8, 9, 10, 11,
		12, 13, 14, 15,
		0, 1, 2, 3,
	);
}

/** "Look two rows down": dst[p] = src[(p+8) mod 16]. */
@inline function rl64(x: v128): v128 {
	return v128.shuffle<i8>(x, x,
		8, 9, 10, 11,
		12, 13, 14, 15,
		0, 1, 2, 3,
		4, 5, 6, 7,
	);
}

/**
 * MixColumns over bitsliced state.
 * Reference: Käsper-Schwabe 2009 §4.4 + Appendix A (full equations).
 */
function mixColumns(): void {
	const a0 = bget(0);
	const a1 = bget(1);
	const a2 = bget(2);
	const a3 = bget(3);
	const a4 = bget(4);
	const a5 = bget(5);
	const a6 = bget(6);
	const a7 = bget(7);

	const r0 = rl32(a0);
	const r1 = rl32(a1);
	const r2 = rl32(a2);
	const r3 = rl32(a3);
	const r4 = rl32(a4);
	const r5 = rl32(a5);
	const r6 = rl32(a6);
	const r7 = rl32(a7);

	// Shared subexpressions: a[k] ⊕ rl32 a[k].
	const s0 = v128.xor(a0, r0);
	const s1 = v128.xor(a1, r1);
	const s2 = v128.xor(a2, r2);
	const s3 = v128.xor(a3, r3);
	const s4 = v128.xor(a4, r4);
	const s5 = v128.xor(a5, r5);
	const s6 = v128.xor(a6, r6);
	const s7 = v128.xor(a7, r7);

	// rl64 of the shared subexpressions.
	const rs0 = rl64(s0);
	const rs1 = rl64(s1);
	const rs2 = rl64(s2);
	const rs3 = rl64(s3);
	const rs4 = rl64(s4);
	const rs5 = rl64(s5);
	const rs6 = rl64(s6);
	const rs7 = rl64(s7);

	// b[0] = s7 ⊕ r0 ⊕ rs0
	bset(0, v128.xor(v128.xor(s7, r0), rs0));
	// b[1] = s0 ⊕ s7 ⊕ r1 ⊕ rs1
	bset(1, v128.xor(v128.xor(s0, s7), v128.xor(r1, rs1)));
	// b[2] = s1 ⊕ r2 ⊕ rs2
	bset(2, v128.xor(v128.xor(s1, r2), rs2));
	// b[3] = s2 ⊕ s7 ⊕ r3 ⊕ rs3
	bset(3, v128.xor(v128.xor(s2, s7), v128.xor(r3, rs3)));
	// b[4] = s3 ⊕ s7 ⊕ r4 ⊕ rs4
	bset(4, v128.xor(v128.xor(s3, s7), v128.xor(r4, rs4)));
	// b[5] = s4 ⊕ r5 ⊕ rs5
	bset(5, v128.xor(v128.xor(s4, r5), rs5));
	// b[6] = s5 ⊕ r6 ⊕ rs6
	bset(6, v128.xor(v128.xor(s5, r6), rs6));
	// b[7] = s6 ⊕ r7 ⊕ rs7
	bset(7, v128.xor(v128.xor(s6, r7), rs7));
}

/**
 * InvMixColumns over bitsliced state.
 *
 * Applies the FIPS 197 §5.3.3 inverse-MixColumns matrix to each column:
 *
 *     b[i,j] = 0E·a[i,j] ⊕ 0B·a[i+1,j] ⊕ 0D·a[i+2,j] ⊕ 09·a[i+3,j]
 *
 * Bit equations derived by expanding the GF(2⁸) multiplications {0x09,
 * 0x0B, 0x0D, 0x0E} via mul02 = (x<<1) ⊕ (x[7]·0x1B). The four "row"
 * inputs come from rl32 / rl64 / rl96 (= rl32 ∘ rl64) byte rotations of
 * each bit-slice register, mirroring the forward `mixColumns` structure.
 *
 * The inverse mix matrix is denser than the forward mix matrix, so this
 * function is ~3× the size of `mixColumns`. Verified against FIPS 197
 * §B inverse-cipher example via the `aes_decrypt.test.ts` gate.
 */
function invMixColumns(): void {
	const a0 = bget(0);
	const a1 = bget(1);
	const a2 = bget(2);
	const a3 = bget(3);
	const a4 = bget(4);
	const a5 = bget(5);
	const a6 = bget(6);
	const a7 = bget(7);

	// Row +1 (rl32), +2 (rl64), +3 (rl96 = rl32 ∘ rl64).
	const b0 = rl32(a0); const b1 = rl32(a1); const b2 = rl32(a2); const b3 = rl32(a3);
	const b4 = rl32(a4); const b5 = rl32(a5); const b6 = rl32(a6); const b7 = rl32(a7);
	const c0 = rl64(a0); const c1 = rl64(a1); const c2 = rl64(a2); const c3 = rl64(a3);
	const c4 = rl64(a4); const c5 = rl64(a5); const c6 = rl64(a6); const c7 = rl64(a7);
	const d0 = rl32(c0); const d1 = rl32(c1); const d2 = rl32(c2); const d3 = rl32(c3);
	const d4 = rl32(c4); const d5 = rl32(c5); const d6 = rl32(c6); const d7 = rl32(c7);

	// Each output bit-k slice is mul0E(a)[k] ⊕ mul0B(b)[k] ⊕ mul0D(c)[k] ⊕ mul09(d)[k].
	// mul0E[k]: bit-k of (0x0E · x) — depends on bits as derived from mul02 expansion.
	//   mul0E[0]: x_5 ⊕ x_6 ⊕ x_7
	//   mul0E[1]: x_0 ⊕ x_5
	//   mul0E[2]: x_0 ⊕ x_1 ⊕ x_6
	//   mul0E[3]: x_0 ⊕ x_1 ⊕ x_2 ⊕ x_5 ⊕ x_6
	//   mul0E[4]: x_1 ⊕ x_2 ⊕ x_3 ⊕ x_5
	//   mul0E[5]: x_2 ⊕ x_3 ⊕ x_4 ⊕ x_6
	//   mul0E[6]: x_3 ⊕ x_4 ⊕ x_5 ⊕ x_7
	//   mul0E[7]: x_4 ⊕ x_5 ⊕ x_6
	// mul0B[k]:
	//   mul0B[0]: x_0 ⊕ x_5 ⊕ x_7
	//   mul0B[1]: x_0 ⊕ x_1 ⊕ x_5 ⊕ x_6 ⊕ x_7
	//   mul0B[2]: x_1 ⊕ x_2 ⊕ x_6 ⊕ x_7
	//   mul0B[3]: x_0 ⊕ x_2 ⊕ x_3 ⊕ x_5
	//   mul0B[4]: x_1 ⊕ x_3 ⊕ x_4 ⊕ x_5 ⊕ x_6 ⊕ x_7
	//   mul0B[5]: x_2 ⊕ x_4 ⊕ x_5 ⊕ x_6 ⊕ x_7
	//   mul0B[6]: x_3 ⊕ x_5 ⊕ x_6 ⊕ x_7
	//   mul0B[7]: x_4 ⊕ x_6 ⊕ x_7
	// mul0D[k]:
	//   mul0D[0]: x_0 ⊕ x_5 ⊕ x_6
	//   mul0D[1]: x_1 ⊕ x_5 ⊕ x_7
	//   mul0D[2]: x_0 ⊕ x_2 ⊕ x_6
	//   mul0D[3]: x_0 ⊕ x_1 ⊕ x_3 ⊕ x_5 ⊕ x_6 ⊕ x_7
	//   mul0D[4]: x_1 ⊕ x_2 ⊕ x_4 ⊕ x_5 ⊕ x_7
	//   mul0D[5]: x_2 ⊕ x_3 ⊕ x_5 ⊕ x_6
	//   mul0D[6]: x_3 ⊕ x_4 ⊕ x_6 ⊕ x_7
	//   mul0D[7]: x_4 ⊕ x_5 ⊕ x_7
	// mul09[k]:
	//   mul09[0]: x_0 ⊕ x_5
	//   mul09[1]: x_1 ⊕ x_5 ⊕ x_6
	//   mul09[2]: x_2 ⊕ x_6 ⊕ x_7
	//   mul09[3]: x_0 ⊕ x_3 ⊕ x_5 ⊕ x_7
	//   mul09[4]: x_1 ⊕ x_4 ⊕ x_5 ⊕ x_6
	//   mul09[5]: x_2 ⊕ x_5 ⊕ x_6 ⊕ x_7
	//   mul09[6]: x_3 ⊕ x_6 ⊕ x_7
	//   mul09[7]: x_4 ⊕ x_7

	// b[0] = (a5 ⊕ a6 ⊕ a7) ⊕ (b0 ⊕ b5 ⊕ b7) ⊕ (c0 ⊕ c5 ⊕ c6) ⊕ (d0 ⊕ d5)
	bset(0, v128.xor(
		v128.xor(v128.xor(v128.xor(a5, a6), a7), v128.xor(v128.xor(b0, b5), b7)),
		v128.xor(v128.xor(v128.xor(c0, c5), c6), v128.xor(d0, d5)),
	));
	// b[1] = (a0 ⊕ a5) ⊕ (b0 ⊕ b1 ⊕ b5 ⊕ b6 ⊕ b7) ⊕ (c1 ⊕ c5 ⊕ c7) ⊕ (d1 ⊕ d5 ⊕ d6)
	bset(1, v128.xor(
		v128.xor(v128.xor(a0, a5), v128.xor(v128.xor(v128.xor(b0, b1), v128.xor(b5, b6)), b7)),
		v128.xor(v128.xor(v128.xor(c1, c5), c7), v128.xor(v128.xor(d1, d5), d6)),
	));
	// b[2] = (a0 ⊕ a1 ⊕ a6) ⊕ (b1 ⊕ b2 ⊕ b6 ⊕ b7) ⊕ (c0 ⊕ c2 ⊕ c6) ⊕ (d2 ⊕ d6 ⊕ d7)
	bset(2, v128.xor(
		v128.xor(v128.xor(v128.xor(a0, a1), a6), v128.xor(v128.xor(b1, b2), v128.xor(b6, b7))),
		v128.xor(v128.xor(v128.xor(c0, c2), c6), v128.xor(v128.xor(d2, d6), d7)),
	));
	// b[3] = (a0 ⊕ a1 ⊕ a2 ⊕ a5 ⊕ a6) ⊕ (b0 ⊕ b2 ⊕ b3 ⊕ b5) ⊕ (c0 ⊕ c1 ⊕ c3 ⊕ c5 ⊕ c6 ⊕ c7) ⊕ (d0 ⊕ d3 ⊕ d5 ⊕ d7)
	bset(3, v128.xor(
		v128.xor(
			v128.xor(v128.xor(v128.xor(a0, a1), v128.xor(a2, a5)), a6),
			v128.xor(v128.xor(b0, b2), v128.xor(b3, b5)),
		),
		v128.xor(
			v128.xor(v128.xor(v128.xor(c0, c1), v128.xor(c3, c5)), v128.xor(c6, c7)),
			v128.xor(v128.xor(d0, d3), v128.xor(d5, d7)),
		),
	));
	// b[4] = (a1 ⊕ a2 ⊕ a3 ⊕ a5) ⊕ (b1 ⊕ b3 ⊕ b4 ⊕ b5 ⊕ b6 ⊕ b7) ⊕ (c1 ⊕ c2 ⊕ c4 ⊕ c5 ⊕ c7) ⊕ (d1 ⊕ d4 ⊕ d5 ⊕ d6)
	bset(4, v128.xor(
		v128.xor(
			v128.xor(v128.xor(a1, a2), v128.xor(a3, a5)),
			v128.xor(v128.xor(v128.xor(b1, b3), v128.xor(b4, b5)), v128.xor(b6, b7)),
		),
		v128.xor(
			v128.xor(v128.xor(v128.xor(c1, c2), v128.xor(c4, c5)), c7),
			v128.xor(v128.xor(d1, d4), v128.xor(d5, d6)),
		),
	));
	// b[5] = (a2 ⊕ a3 ⊕ a4 ⊕ a6) ⊕ (b2 ⊕ b4 ⊕ b5 ⊕ b6 ⊕ b7) ⊕ (c2 ⊕ c3 ⊕ c5 ⊕ c6) ⊕ (d2 ⊕ d5 ⊕ d6 ⊕ d7)
	bset(5, v128.xor(
		v128.xor(
			v128.xor(v128.xor(a2, a3), v128.xor(a4, a6)),
			v128.xor(v128.xor(v128.xor(b2, b4), v128.xor(b5, b6)), b7),
		),
		v128.xor(
			v128.xor(v128.xor(c2, c3), v128.xor(c5, c6)),
			v128.xor(v128.xor(d2, d5), v128.xor(d6, d7)),
		),
	));
	// b[6] = (a3 ⊕ a4 ⊕ a5 ⊕ a7) ⊕ (b3 ⊕ b5 ⊕ b6 ⊕ b7) ⊕ (c3 ⊕ c4 ⊕ c6 ⊕ c7) ⊕ (d3 ⊕ d6 ⊕ d7)
	bset(6, v128.xor(
		v128.xor(
			v128.xor(v128.xor(a3, a4), v128.xor(a5, a7)),
			v128.xor(v128.xor(b3, b5), v128.xor(b6, b7)),
		),
		v128.xor(
			v128.xor(v128.xor(c3, c4), v128.xor(c6, c7)),
			v128.xor(v128.xor(d3, d6), d7),
		),
	));
	// b[7] = (a4 ⊕ a5 ⊕ a6) ⊕ (b4 ⊕ b6 ⊕ b7) ⊕ (c4 ⊕ c5 ⊕ c7) ⊕ (d4 ⊕ d7)
	bset(7, v128.xor(
		v128.xor(v128.xor(v128.xor(a4, a5), a6), v128.xor(v128.xor(b4, b6), b7)),
		v128.xor(v128.xor(v128.xor(c4, c5), c7), v128.xor(d4, d7)),
	));
}

// ── AddRoundKey (Käsper-Schwabe §4.5 + FIPS 197 §5.1.4) ────────────────────
//
// Each round key occupies 8 v128 (128 bytes) at ROUND_KEYS_OFFSET +
// roundIdx * 128 (forward, encrypt) or INV_ROUND_KEYS_OFFSET + roundIdx * 128
// (EqInvCipher-form, decrypt). AddRoundKey is 8 plain v128 XORs.

@inline function rkget(round: i32, k: i32): v128 {
	return v128.load(ROUND_KEYS_OFFSET + (round << 7) + (k << 4));
}

@inline function invRkget(round: i32, k: i32): v128 {
	return v128.load(INV_ROUND_KEYS_OFFSET + (round << 7) + (k << 4));
}

/** XOR forward round-key `roundIdx` into the bitsliced state. */
function addRoundKey(roundIdx: i32): void {
	for (let k: i32 = 0; k < 8; k++) {
		bset(k, v128.xor(bget(k), rkget(roundIdx, k)));
	}
}

/** XOR EqInvCipher round-key `roundIdx` into the bitsliced state. Used by
 *  `decryptBlock_8x`. INV_ROUND_KEYS holds K[0] and K[Nr] as plain copies of
 *  the forward keys; rounds 1..Nr-1 hold InvMixColumns-transformed keys. */
function addInvRoundKey(roundIdx: i32): void {
	for (let k: i32 = 0; k < 8; k++) {
		bset(k, v128.xor(bget(k), invRkget(roundIdx, k)));
	}
}

// ── AES key schedule (FIPS 197 §5.2 Algorithm 2) ───────────────────────────
//
// Computes (Nr+1) round keys (16·(Nr+1) bytes byte-level) from the keyLen-byte
// master key at KEY_OFFSET. Round keys are then bitsliced (each one duplicates
// across 8 "blocks" and is transposed) to ROUND_KEYS_OFFSET.
//
// Single algorithm parameterised by `keyLen` ∈ {16, 24, 32}: derives Nk =
// keyLen/4 ∈ {4, 6, 8} and Nr = Nk + 6 ∈ {10, 12, 14}. The AES-256-only
// extra-SubWord branch (FIPS 197 §5.2 Algorithm 2 lines 11–12) fires only
// when both `Nk > 6` and `i mod Nk == 4`, i.e. for keyLen=32 at i ∈
// {12, 20, 28, 36, 44, 52}. For keyLen ∈ {16, 24} the branch is unreachable
// (the first conditional `i mod Nk == 0` precludes it for keyLen=24, and
// `Nk > 6` precludes it for keyLen=16).

/** AES Rcon[j] = (x^(j-1), 0, 0, 0) in GF(2⁸). FIPS 197 Table 5. */
@inline function rcon(j: i32): u8 {
	switch (j) {
		case 1:  return 0x01;
		case 2:  return 0x02;
		case 3:  return 0x04;
		case 4:  return 0x08;
		case 5:  return 0x10;
		case 6:  return 0x20;
		case 7:  return 0x40;
		case 8:  return 0x80;
		case 9:  return 0x1b;
		case 10: return 0x36;
		default: return 0;
	}
}

/**
 * AES forward S-box on 4 packed bytes — Boyar-Peralta scalar circuit.
 *
 * Reference: J. Boyar and R. Peralta, "A New Combinational Logic
 * Minimization Technique with Applications to Cryptology", NIST 2010
 * (tsapps.nist.gov/publication/get_pdf.cfm?pub_id=902701) and "A small
 * depth-16 circuit for the AES S-box", IACR ePrint 2011/332. Canonical
 * straight-line program: cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt
 * (113 gates: 32 AND, 81 XOR/XNOR; depth 27).
 *
 * Used by `keyExpansion` for the SubWord step. Replaces the previous
 * single-byte path that ran the full 8-block bitsliced pipeline (~380
 * v128 ops + 128-byte memory.fill per byte). The scalar SLP runs once
 * per call regardless of how many of the 4 input bit-positions are
 * populated, so packing 4 bytes per call is essentially free.
 *
 * Layout: each input byte j ∈ {0..3} of `w` is bitsliced across the low
 * 4 bit-positions of 8 i32 SLP registers (U0..U7 in MSB-first AES bit
 * order: bit-7 of byte j → bit j of U0, bit-0 of byte j → bit j of U7).
 * Output S0..S7 unpack symmetrically. Bits ≥ 4 of the SLP registers are
 * not meaningful — XOR keeps them zero, but the four output XNOR gates
 * (S1, S2, S6, S7) leave bits 4..31 set; the unpack masks via `& 1` so
 * those high bits are inert.
 *
 * The SLP is the *full* AES S-box: GF(2⁸) inversion + AES affine M with
 * the 0x63 constant absorbed into the four output XNOR gates (MSB-first
 * S1, S2, S6, S7 = LSB-first bits 6, 5, 1, 0 of 0x63, FIPS 197 §5.1.1).
 *
 * @param w  4 input bytes packed little-endian.
 * @returns  4 output bytes packed little-endian.
 */
function sboxWord(w: u32): u32 {
	// pack4: bit-7 of byte j → bit j of U0 ; bit-0 of byte j → bit j of U7.
	let U0: i32 = 0, U1: i32 = 0, U2: i32 = 0, U3: i32 = 0;
	let U4: i32 = 0, U5: i32 = 0, U6: i32 = 0, U7: i32 = 0;
	for (let j: i32 = 0; j < 4; j++) {
		const b = <i32>((w >> (j << 3)) & 0xff);
		U0 |= ((b >> 7) & 1) << j;
		U1 |= ((b >> 6) & 1) << j;
		U2 |= ((b >> 5) & 1) << j;
		U3 |= ((b >> 4) & 1) << j;
		U4 |= ((b >> 3) & 1) << j;
		U5 |= ((b >> 2) & 1) << j;
		U6 |= ((b >> 1) & 1) << j;
		U7 |= ((b >> 0) & 1) << j;
	}

	// ── Boyar-Peralta SLP (verbatim from SLP_AES_113.txt) ──────────────
	// Linear top layer (y-variables): 23 XORs.
	const y14 = U3 ^ U5;
	const y13 = U0 ^ U6;
	const y9  = U0 ^ U3;
	const y8  = U0 ^ U5;
	const t0  = U1 ^ U2;
	const y1  = t0  ^ U7;
	const y4  = y1  ^ U3;
	const y12 = y13 ^ y14;
	const y2  = y1  ^ U0;
	const y5  = y1  ^ U6;
	const y3  = y5  ^ y8;
	const t1  = U4  ^ y12;
	const y15 = t1  ^ U5;
	const y20 = t1  ^ U1;
	const y6  = y15 ^ U7;
	const y10 = y15 ^ t0;
	const y11 = y20 ^ y9;
	const y7  = U7  ^ y11;
	const y17 = y10 ^ y11;
	const y19 = y10 ^ y8;
	const y16 = t0  ^ y11;
	const y21 = y13 ^ y16;
	const y18 = U0  ^ y16;

	// Nonlinear middle layer (t-variables): 32 ANDs interleaved with XORs.
	const t2  = y12 & y15;
	const t3  = y3  & y6;
	const t4  = t3  ^ t2;
	const t5  = y4  & U7;
	const t6  = t5  ^ t2;
	const t7  = y13 & y16;
	const t8  = y5  & y1;
	const t9  = t8  ^ t7;
	const t10 = y2  & y7;
	const t11 = t10 ^ t7;
	const t12 = y9  & y11;
	const t13 = y14 & y17;
	const t14 = t13 ^ t12;
	const t15 = y8  & y10;
	const t16 = t15 ^ t12;
	const t17 = t4  ^ y20;
	const t18 = t6  ^ t16;
	const t19 = t9  ^ t14;
	const t20 = t11 ^ t16;
	const t21 = t17 ^ t14;
	const t22 = t18 ^ y19;
	const t23 = t19 ^ y21;
	const t24 = t20 ^ y18;
	const t25 = t21 ^ t22;
	const t26 = t21 & t23;
	const t27 = t24 ^ t26;
	const t28 = t25 & t27;
	const t29 = t28 ^ t22;
	const t30 = t23 ^ t24;
	const t31 = t22 ^ t26;
	const t32 = t31 & t30;
	const t33 = t32 ^ t24;
	const t34 = t23 ^ t33;
	const t35 = t27 ^ t33;
	const t36 = t24 & t35;
	const t37 = t36 ^ t34;
	const t38 = t27 ^ t36;
	const t39 = t29 & t38;
	const t40 = t25 ^ t39;
	const t41 = t40 ^ t37;
	const t42 = t29 ^ t33;
	const t43 = t29 ^ t40;
	const t44 = t33 ^ t37;
	const t45 = t42 ^ t41;

	// 18 ANDs producing z-variables.
	const z0  = t44 & y15;
	const z1  = t37 & y6;
	const z2  = t33 & U7;
	const z3  = t43 & y16;
	const z4  = t40 & y1;
	const z5  = t29 & y7;
	const z6  = t42 & y11;
	const z7  = t45 & y17;
	const z8  = t41 & y10;
	const z9  = t44 & y12;
	const z10 = t37 & y3;
	const z11 = t33 & y4;
	const z12 = t43 & y13;
	const z13 = t40 & y5;
	const z14 = t29 & y2;
	const z15 = t42 & y9;
	const z16 = t45 & y14;
	const z17 = t41 & y8;

	// Linear bottom layer (tc + S variables): 30 XOR/XNORs.
	// `#` in the SLP is XNOR, written here as `~(a ^ b)` — the four output
	// XNORs absorb the AES affine constant 0x63.
	const tc1  = z15 ^ z16;
	const tc2  = z10 ^ tc1;
	const tc3  = z9  ^ tc2;
	const tc4  = z0  ^ z2;
	const tc5  = z1  ^ z0;
	const tc6  = z3  ^ z4;
	const tc7  = z12 ^ tc4;
	const tc8  = z7  ^ tc6;
	const tc9  = z8  ^ tc7;
	const tc10 = tc8 ^ tc9;
	const tc11 = tc6 ^ tc5;
	const tc12 = z3  ^ z5;
	const tc13 = z13 ^ tc1;
	const tc14 = tc4 ^ tc12;
	const S3   = tc3  ^ tc11;
	const tc16 = z6   ^ tc8;
	const tc17 = z14  ^ tc10;
	const tc18 = tc13 ^ tc14;
	const S7   = ~(z12  ^ tc18);
	const tc20 = z15  ^ tc16;
	const tc21 = tc2  ^ z11;
	const S0   = tc3  ^ tc16;
	const S6   = ~(tc10 ^ tc18);
	const S4   = tc14 ^ S3;
	const S1   = ~(S3   ^ tc16);
	const tc26 = tc17 ^ tc20;
	const S2   = ~(tc26 ^ z17);
	const S5   = tc21 ^ tc17;

	// unpack4: bit j of S0 → bit-7 of output byte j ; bit j of S7 → bit-0.
	let out: u32 = 0;
	for (let j: i32 = 0; j < 4; j++) {
		let b: i32 = 0;
		b |= ((S0 >> j) & 1) << 7;
		b |= ((S1 >> j) & 1) << 6;
		b |= ((S2 >> j) & 1) << 5;
		b |= ((S3 >> j) & 1) << 4;
		b |= ((S4 >> j) & 1) << 3;
		b |= ((S5 >> j) & 1) << 2;
		b |= ((S6 >> j) & 1) << 1;
		b |= ((S7 >> j) & 1) << 0;
		out |= (<u32>b) << (j << 3);
	}
	return out;
}

/**
 * AES key expansion — parameterised on key length.
 *
 * Reference: FIPS 197 §5.2 Algorithm 2 (the unified pseudocode). Reads
 * `keyLen` bytes at KEY_OFFSET; writes `(Nr+1)` byte-level round keys
 * (16·(Nr+1) bytes ∈ {176, 208, 240}) into KEY_SCHEDULE_SCRATCH; then
 * bit-slices each round key (Käsper-Schwabe §4.5 layout) into ROUND_KEYS,
 * builds the EqInvCipher decrypt schedule into INV_ROUND_KEYS (FIPS 197
 * §5.3.5), and persists Nr to NR_BUFFER.
 *
 * @param keyLen  16, 24, or 32 — the AES key length in bytes.
 */
function keyExpansion(keyLen: i32): void {
	// Algorithm 2 parameters.
	const Nk: i32 = keyLen >> 2;        // 4 / 6 / 8 — words in master key.
	const Nr: i32 = Nk + 6;             // 10 / 12 / 14 — round count.
	const totalWords: i32 = (Nr + 1) << 2;  // 44 / 52 / 60 — total schedule words.

	// Byte-level scratch lives in its own 256-byte buffer (buffers.ts), sized
	// for AES-256's 240-byte schedule. The earlier piggy-backing on the tail
	// of ROUND_KEYS_BUFFER collided with rounds 11–13 once AES-256 lands; the
	// dedicated buffer eliminates that trap.
	const SCRATCH = KEY_SCHEDULE_SCRATCH_OFFSET;

	// Step 1 — copy the master key as the first Nk words.
	memory.copy(SCRATCH, KEY_OFFSET, keyLen);

	// Step 2 — derive remaining (totalWords - Nk) words. FIPS 197 §5.2
	// Algorithm 2 lines 7–15:
	//   for i in [Nk, 4*(Nr+1)):
	//     temp = w[i-1]
	//     if i mod Nk == 0:        temp = SubWord(RotWord(temp)) ⊕ Rcon[i/Nk]
	//     else if Nk > 6 && i mod Nk == 4:
	//                              temp = SubWord(temp)        ← AES-256 only
	//     w[i] = w[i-Nk] ⊕ temp
	for (let i: i32 = Nk; i < totalWords; i++) {
		// temp = w[i-1] (4 bytes).
		let t0 = load<u8>(SCRATCH + (i - 1) * 4);
		let t1 = load<u8>(SCRATCH + (i - 1) * 4 + 1);
		let t2 = load<u8>(SCRATCH + (i - 1) * 4 + 2);
		let t3 = load<u8>(SCRATCH + (i - 1) * 4 + 3);

		if (i % Nk == 0) {
			// RotWord then SubWord on (t0,t1,t2,t3) = SubWord on (t1,t2,t3,t0).
			// One sboxWord call replaces 4 single-byte applications.
			const rotated = (<u32>t1)
				| ((<u32>t2) << 8)
				| ((<u32>t3) << 16)
				| ((<u32>t0) << 24);
			const subbed = sboxWord(rotated);
			t0 = (<u8>subbed) ^ rcon(i / Nk);
			t1 = <u8>(subbed >> 8);
			t2 = <u8>(subbed >> 16);
			t3 = <u8>(subbed >> 24);
		} else if (Nk > 6 && i % Nk == 4) {
			// AES-256 only — extra SubWord, no RotWord, no Rcon.
			const packed = (<u32>t0)
				| ((<u32>t1) << 8)
				| ((<u32>t2) << 16)
				| ((<u32>t3) << 24);
			const subbed = sboxWord(packed);
			t0 = <u8>subbed;
			t1 = <u8>(subbed >> 8);
			t2 = <u8>(subbed >> 16);
			t3 = <u8>(subbed >> 24);
		}

		// w[i] = w[i-Nk] ⊕ temp.
		store<u8>(SCRATCH + i * 4,     load<u8>(SCRATCH + (i - Nk) * 4)     ^ t0);
		store<u8>(SCRATCH + i * 4 + 1, load<u8>(SCRATCH + (i - Nk) * 4 + 1) ^ t1);
		store<u8>(SCRATCH + i * 4 + 2, load<u8>(SCRATCH + (i - Nk) * 4 + 2) ^ t2);
		store<u8>(SCRATCH + i * 4 + 3, load<u8>(SCRATCH + (i - Nk) * 4 + 3) ^ t3);
	}

	// Step 3 — bitslice each of the (Nr+1) round keys. For each round key,
	// fill BLOCK_PT_8X with 8 copies of the 16-byte key, transpose, then copy
	// bitsliced state to ROUND_KEYS_OFFSET + round*128.
	for (let round: i32 = 0; round < Nr + 1; round++) {
		for (let b: i32 = 0; b < 8; b++) {
			for (let p: i32 = 0; p < 16; p++) {
				store<u8>(BLOCK_PT_8X_OFFSET + b * 16 + p,
					load<u8>(SCRATCH + round * 16 + p));
			}
		}
		transposeIn();
		memory.copy(ROUND_KEYS_OFFSET + (round << 7), BITSLICED_STATE_OFFSET, 128);
	}

	// Step 4 — build EqInvCipher (decrypt) round keys at INV_ROUND_KEYS.
	// FIPS 197 §5.3.5: K[0] and K[Nr] stay as the forward keys; K[1..Nr-1]
	// are InvMixColumns-transformed so decrypt's per-round AddRoundKey reuses
	// the encrypt structure unchanged. We populate INV_ROUND_KEYS in parallel
	// to ROUND_KEYS so a single AES instance supports both directions.
	memory.copy(INV_ROUND_KEYS_OFFSET, ROUND_KEYS_OFFSET, (Nr + 1) * 128);
	for (let r: i32 = 1; r < Nr; r++) {
		memory.copy(BITSLICED_STATE_OFFSET, ROUND_KEYS_OFFSET + (r << 7), 128);
		invMixColumns();
		memory.copy(INV_ROUND_KEYS_OFFSET + (r << 7), BITSLICED_STATE_OFFSET, 128);
	}

	// Step 5 — persist Nr; encrypt/decrypt read this at the top of each call.
	store<u8>(NR_OFFSET, <u8>Nr);

	// Wipe the byte-level scratch and BLOCK_PT_8X (since they held key bytes).
	memory.fill(SCRATCH, 0, KEY_SCHEDULE_SCRATCH_SIZE);
	memory.fill(BLOCK_PT_8X_OFFSET, 0, 128);
	memory.fill(BITSLICED_STATE_OFFSET, 0, 128);
}

// ── Public AES encrypt + decrypt API ────────────────────────────────────────

/**
 * Validate key length and run the AES key schedule.
 *
 * Accepts 16, 24, or 32 byte keys (AES-128/192/256). The key schedule
 * produces (Nr+1) bitsliced forward round keys at ROUND_KEYS, the
 * InvMixColumns-transformed EqInvCipher schedule at INV_ROUND_KEYS, and
 * persists Nr to NR_BUFFER for the round loops to consume.
 *
 * Phase 4a addition: also derives the GCM hash subkey
 * H = AES_ENC(K, 0^128) into H_BUFFER and builds the GF(2^128) 4-bit
 * windowed multiply table. This adds one AES block encrypt + 16 GF
 * multiplies per loadKey call (≈ a few microseconds); the cost is
 * paid by every consumer of loadKey but read only by AES-GCM. CTR/CBC
 * never touch the GCM-only buffers.
 *
 * @param keyLen  16, 24, or 32
 * @returns       0 on success, nonzero on any other key length.
 */
export function loadKey(keyLen: i32): i32 {
	if (keyLen != 16 && keyLen != 24 && keyLen != 32) return 1;
	keyExpansion(keyLen);

	// Phase 4a: derive GCM hash subkey H = AES_ENC(K, 0^128) and build
	// the 4-bit windowed multiply table from H. SP 800-38D §7.1 step 1.
	store<u64>(BLOCK_PT_OFFSET,     0);
	store<u64>(BLOCK_PT_OFFSET + 8, 0);
	encryptBlock();
	store<u64>(H_OFFSET,     load<u64>(BLOCK_CT_OFFSET));
	store<u64>(H_OFFSET + 8, load<u64>(BLOCK_CT_OFFSET + 8));
	gf128InitTable();
	return 0;
}

/**
 * AES encrypt 8 parallel blocks at BLOCK_PT_8X_OFFSET, writing 8 ciphertext
 * blocks to BLOCK_CT_8X_OFFSET.
 *
 * Reference: FIPS 197 §5.1 Algorithm 1, Nr ∈ {10, 12, 14}. Bitsliced
 * layout: Käsper-Schwabe 2009 §4. Nr is read from NR_BUFFER (persisted by
 * the most recent loadKey() call).
 */
export function encryptBlock_8x(): void {
	const Nr: i32 = <i32>load<u8>(NR_OFFSET);

	transposeIn();

	// Round 0: AddRoundKey only.
	addRoundKey(0);

	// Inner rounds 1..Nr-1: SubBytes, ShiftRows, MixColumns, AddRoundKey.
	for (let round: i32 = 1; round < Nr; round++) {
		sboxBitsliced();
		shiftRows();
		mixColumns();
		addRoundKey(round);
	}

	// Final round Nr: SubBytes, ShiftRows, AddRoundKey (no MixColumns;
	// FIPS 197 §5.1 Algorithm 1 lines 10–12).
	sboxBitsliced();
	shiftRows();
	addRoundKey(Nr);

	transposeOut();
}

/**
 * AES encrypt a single block at BLOCK_PT_OFFSET, writing to BLOCK_CT_OFFSET.
 *
 * Direct single-block path: `transposeIn1` reads BLOCK_PT into the bitsliced
 * state (lane 0 populated, lanes 1..7 zero), the standard 8x round kernel
 * runs, and `transposeOut1` reconstructs block 0 from the state and writes
 * BLOCK_CT. The 7 dummy lanes still pay AES work in the kernel (it's
 * inherently 8-wide), but BLOCK_PT_8X / BLOCK_CT_8X are never touched —
 * saves the prior 144 bytes of memory ops and ~⅔ of the transpose v128
 * count per call. Hot path for AES-GCM-SIV's `sivCtrXform`.
 *
 * Reference: FIPS 197 §5.1 Algorithm 1, Nr ∈ {10, 12, 14}. Kernel layout:
 * Käsper-Schwabe 2009 §4. Nr is read from NR_BUFFER (persisted by the most
 * recent loadKey() call).
 */
export function encryptBlock(): void {
	const Nr: i32 = <i32>load<u8>(NR_OFFSET);

	transposeIn1();

	addRoundKey(0);
	for (let round: i32 = 1; round < Nr; round++) {
		sboxBitsliced();
		shiftRows();
		mixColumns();
		addRoundKey(round);
	}
	sboxBitsliced();
	shiftRows();
	addRoundKey(Nr);

	transposeOut1();
}

/**
 * AES decrypt 8 parallel blocks at BLOCK_PT_8X_OFFSET (treated as
 * ciphertext input), writing 8 plaintext blocks to BLOCK_CT_8X_OFFSET.
 *
 * Reference: FIPS 197 §5.3.5 Equivalent Inverse Cipher, Nr ∈ {10, 12, 14}.
 * Round keys 1..Nr-1 have already been pre-transformed by InvMixColumns at
 * key-schedule time; round keys 0 and Nr stay in their original form. The
 * round structure mirrors `encryptBlock_8x` with inverse subroutines.
 *
 * Buffer naming note: BLOCK_PT_8X holds the *ciphertext* input during
 * decrypt and BLOCK_CT_8X holds the *plaintext* output. The buffers are
 * named for the encrypt direction; the convention matches Serpent.
 */
export function decryptBlock_8x(): void {
	const Nr: i32 = <i32>load<u8>(NR_OFFSET);

	transposeIn();

	// EqInvCipher initial AddRoundKey with K[Nr]. INV_ROUND_KEYS[Nr] is a
	// plain copy of the forward K[Nr] (no InvMixColumns).
	addInvRoundKey(Nr);

	// Rounds Nr-1..1: InvSubBytes, InvShiftRows, InvMixColumns, AddRoundKey
	// with InvMixColumns-transformed round keys (already prepared at
	// loadKey() time in INV_ROUND_KEYS).
	for (let round: i32 = Nr - 1; round >= 1; round--) {
		invSboxBitsliced();
		invShiftRows();
		invMixColumns();
		addInvRoundKey(round);
	}

	// Final round (FIPS 197 §5.3.5): InvSubBytes, InvShiftRows, AddRoundKey
	// with K[0]. No InvMixColumns. INV_ROUND_KEYS[0] is a plain copy.
	invSboxBitsliced();
	invShiftRows();
	addInvRoundKey(0);

	transposeOut();
}

/**
 * AES decrypt a single block at BLOCK_PT_OFFSET (ciphertext input),
 * writing plaintext to BLOCK_CT_OFFSET.
 *
 * Direct single-block path mirroring `encryptBlock` — reads BLOCK_PT
 * (treated as ciphertext input here, matching the buffer-naming
 * convention where BLOCK_PT/CT are named for the encrypt direction) and
 * writes BLOCK_CT (plaintext output). Never touches BLOCK_PT_8X /
 * BLOCK_CT_8X.
 *
 * Reference: FIPS 197 §5.3.5 Equivalent Inverse Cipher.
 */
export function decryptBlock(): void {
	const Nr: i32 = <i32>load<u8>(NR_OFFSET);

	transposeIn1();

	addInvRoundKey(Nr);
	for (let round: i32 = Nr - 1; round >= 1; round--) {
		invSboxBitsliced();
		invShiftRows();
		invMixColumns();
		addInvRoundKey(round);
	}
	invSboxBitsliced();
	invShiftRows();
	addInvRoundKey(0);

	transposeOut1();
}

// ── DEBUG-ONLY exports for gate tests 1, 2, 3 ───────────────────────────────

/**
 * DEBUG-ONLY: used by aes_transpose.test.ts (Gate 1).
 * transposeIn followed by transposeOut on the BLOCK_PT_8X buffer; output
 * appears at BLOCK_CT_8X. Should be the identity for any 128-byte input.
 */
export function transposeRoundTrip(): void {
	transposeIn();
	transposeOut();
}

/**
 * DEBUG-ONLY: used by aes_sbox.test.ts to exhaustively verify the
 * Boyar-Peralta scalar S-box used by the key schedule. Direct passthrough
 * to `sboxWord`.
 */
export function sboxWordExport(w: u32): u32 {
	return sboxWord(w);
}

/**
 * DEBUG-ONLY: used by aes_sbox.test.ts (Gate 2).
 * transposeIn → sboxBitsliced → transposeOut. With single-byte input at
 * block 0 byte 0 of BLOCK_PT_8X (rest zeroed), block 0 byte 0 of BLOCK_CT_8X
 * should equal the FIPS 197 S-box of the input byte.
 */
export function sboxRoundTrip(): void {
	transposeIn();
	sboxBitsliced();
	transposeOut();
}

/**
 * DEBUG-ONLY: used by aes_round.test.ts (Gate 3).
 * Apply one full AES round at index `roundIdx` to BLOCK_PT_8X, writing
 * BLOCK_CT_8X. The round is the inner-round form (SubBytes + ShiftRows +
 * MixColumns + AddRoundKey) — appropriate for round 1 verification against
 * FIPS 197 §B Round 1.
 */
export function singleRound(roundIdx: i32): void {
	transposeIn();
	sboxBitsliced();
	shiftRows();
	mixColumns();
	addRoundKey(roundIdx);
	transposeOut();
}
