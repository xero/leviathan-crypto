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
// src/asm/chacha/chacha20_simd_4x.ts
//
// ChaCha20 4-wide inter-block SIMD — RFC 8439, May 2018
// URL: https://www.rfc-editor.org/rfc/rfc8439
//
// Each v128 register holds word[w] from 4 independent blocks (same key/nonce,
// counters ctr, ctr+1, ctr+2, ctr+3). The 4 blocks are completely independent
// so each lane's dependency chain is isolated — 4× useful work per SIMD
// instruction with no shuffle overhead (unlike intra-block SIMD).
//
// Quarter-round indices: RFC 8439 §2.1
// Double-round column + diagonal sequence: RFC 8439 §2.1.1

import {
	CHACHA_STATE_OFFSET,
	CHACHA_CTR_OFFSET,
	CHACHA_BLOCK_OFFSET,
	CHUNK_PT_OFFSET,
	CHUNK_CT_OFFSET,
	CHUNK_SIZE,
	CHACHA_SIMD_WORK_OFFSET,
} from './buffers'

// ── Scalar helpers (private, not exported) ──────────────────────────────────
// Duplicated from chacha20.ts to avoid exporting internal symbols.

@inline
function rotl32_4x(x: u32, n: u32): u32 {
	return (x << n) | (x >>> (32 - n))
}

@inline
function qr_4x(base: i32, a: i32, b: i32, c: i32, d: i32): void {
	let av = load<u32>(base + a * 4)
	let bv = load<u32>(base + b * 4)
	let cv = load<u32>(base + c * 4)
	let dv = load<u32>(base + d * 4)

	av += bv; dv ^= av; dv = rotl32_4x(dv, 16)
	cv += dv; bv ^= cv; bv = rotl32_4x(bv, 12)
	av += bv; dv ^= av; dv = rotl32_4x(dv,  8)
	cv += dv; bv ^= cv; bv = rotl32_4x(bv,  7)

	store<u32>(base + a * 4, av)
	store<u32>(base + b * 4, bv)
	store<u32>(base + c * 4, cv)
	store<u32>(base + d * 4, dv)
}

// Generate one 64-byte keystream block into CHACHA_BLOCK_OFFSET using
// current CHACHA_STATE_OFFSET (which holds the correct counter).
@inline
function computeBlock_scalar(): void {
	memory.copy(CHACHA_BLOCK_OFFSET, CHACHA_STATE_OFFSET, 64)
	// 10 double rounds — RFC 8439 §2.1.1
	for (let i = 0; i < 10; i++) {
		qr_4x(CHACHA_BLOCK_OFFSET, 0,  4,  8, 12)
		qr_4x(CHACHA_BLOCK_OFFSET, 1,  5,  9, 13)
		qr_4x(CHACHA_BLOCK_OFFSET, 2,  6, 10, 14)
		qr_4x(CHACHA_BLOCK_OFFSET, 3,  7, 11, 15)
		qr_4x(CHACHA_BLOCK_OFFSET, 0,  5, 10, 15)
		qr_4x(CHACHA_BLOCK_OFFSET, 1,  6, 11, 12)
		qr_4x(CHACHA_BLOCK_OFFSET, 2,  7,  8, 13)
		qr_4x(CHACHA_BLOCK_OFFSET, 3,  4,  9, 14)
	}
	for (let i = 0; i < 16; i++) {
		store<u32>(CHACHA_BLOCK_OFFSET + i * 4,
			load<u32>(CHACHA_BLOCK_OFFSET + i * 4) +
			load<u32>(CHACHA_STATE_OFFSET + i * 4))
	}
}

// ── 4-wide SIMD block function ──────────────────────────────────────────────
//
// Produces 256 bytes of keystream (4 × 64) stored in deinterleaved order at
// CHACHA_SIMD_WORK_OFFSET:
//   bytes   0– 63: block 0 keystream (counter = ctr)
//   bytes  64–127: block 1 keystream (counter = ctr+1)
//   bytes 128–191: block 2 keystream (counter = ctr+2)
//   bytes 192–255: block 3 keystream (counter = ctr+3)
//
// Each v128 register r[w] holds [block0_word_w, block1_word_w, block2_word_w,
// block3_word_w]. All 16 registers are local variables — locals stay in CPU
// registers; globals would compile to global.get/global.set and prevent JIT
// register allocation.
//
// After 10 double rounds, initial state is added back by reconstructing from
// CHACHA_STATE_OFFSET (no extra v128 locals needed for the initial copy).
function block4x(ctr: u32): void {
	const s = CHACHA_STATE_OFFSET

	// Load state words into v128 locals — words 0–11 and 13–15 are identical
	// across all 4 blocks (splat); word 12 (counter) differs (ctr+0..3).
	let r0:  v128 = i32x4.splat(load<i32>(s +  0))
	let r1:  v128 = i32x4.splat(load<i32>(s +  4))
	let r2:  v128 = i32x4.splat(load<i32>(s +  8))
	let r3:  v128 = i32x4.splat(load<i32>(s + 12))
	let r4:  v128 = i32x4.splat(load<i32>(s + 16))
	let r5:  v128 = i32x4.splat(load<i32>(s + 20))
	let r6:  v128 = i32x4.splat(load<i32>(s + 24))
	let r7:  v128 = i32x4.splat(load<i32>(s + 28))
	let r8:  v128 = i32x4.splat(load<i32>(s + 32))
	let r9:  v128 = i32x4.splat(load<i32>(s + 36))
	let r10: v128 = i32x4.splat(load<i32>(s + 40))
	let r11: v128 = i32x4.splat(load<i32>(s + 44))
	// Word 12: counter lanes [ctr, ctr+1, ctr+2, ctr+3]
	let r12: v128 = i32x4.replace_lane(
		i32x4.replace_lane(
			i32x4.replace_lane(i32x4.splat(ctr as i32), 1, (ctr + 1) as i32),
			2, (ctr + 2) as i32),
		3, (ctr + 3) as i32)
	let r13: v128 = i32x4.splat(load<i32>(s + 52))
	let r14: v128 = i32x4.splat(load<i32>(s + 56))
	let r15: v128 = i32x4.splat(load<i32>(s + 60))

	// 10 double rounds — RFC 8439 §2.1.1
	// Column rounds then diagonal rounds. No shuffles needed: each lane's
	// chain of dependencies is isolated within its block.
	for (let i = 0; i < 10; i++) {
		// Column round: QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)
		r0  = v128.add<i32>(r0,  r4);  r12 = v128.xor(r12, r0);  r12 = v128.or(i32x4.shl(r12, 16), i32x4.shr_u(r12, 16))
		r8  = v128.add<i32>(r8,  r12); r4  = v128.xor(r4,  r8);  r4  = v128.or(i32x4.shl(r4,  12), i32x4.shr_u(r4,  20))
		r0  = v128.add<i32>(r0,  r4);  r12 = v128.xor(r12, r0);  r12 = v128.or(i32x4.shl(r12,  8), i32x4.shr_u(r12, 24))
		r8  = v128.add<i32>(r8,  r12); r4  = v128.xor(r4,  r8);  r4  = v128.or(i32x4.shl(r4,   7), i32x4.shr_u(r4,  25))

		r1  = v128.add<i32>(r1,  r5);  r13 = v128.xor(r13, r1);  r13 = v128.or(i32x4.shl(r13, 16), i32x4.shr_u(r13, 16))
		r9  = v128.add<i32>(r9,  r13); r5  = v128.xor(r5,  r9);  r5  = v128.or(i32x4.shl(r5,  12), i32x4.shr_u(r5,  20))
		r1  = v128.add<i32>(r1,  r5);  r13 = v128.xor(r13, r1);  r13 = v128.or(i32x4.shl(r13,  8), i32x4.shr_u(r13, 24))
		r9  = v128.add<i32>(r9,  r13); r5  = v128.xor(r5,  r9);  r5  = v128.or(i32x4.shl(r5,   7), i32x4.shr_u(r5,  25))

		r2  = v128.add<i32>(r2,  r6);  r14 = v128.xor(r14, r2);  r14 = v128.or(i32x4.shl(r14, 16), i32x4.shr_u(r14, 16))
		r10 = v128.add<i32>(r10, r14); r6  = v128.xor(r6,  r10); r6  = v128.or(i32x4.shl(r6,  12), i32x4.shr_u(r6,  20))
		r2  = v128.add<i32>(r2,  r6);  r14 = v128.xor(r14, r2);  r14 = v128.or(i32x4.shl(r14,  8), i32x4.shr_u(r14, 24))
		r10 = v128.add<i32>(r10, r14); r6  = v128.xor(r6,  r10); r6  = v128.or(i32x4.shl(r6,   7), i32x4.shr_u(r6,  25))

		r3  = v128.add<i32>(r3,  r7);  r15 = v128.xor(r15, r3);  r15 = v128.or(i32x4.shl(r15, 16), i32x4.shr_u(r15, 16))
		r11 = v128.add<i32>(r11, r15); r7  = v128.xor(r7,  r11); r7  = v128.or(i32x4.shl(r7,  12), i32x4.shr_u(r7,  20))
		r3  = v128.add<i32>(r3,  r7);  r15 = v128.xor(r15, r3);  r15 = v128.or(i32x4.shl(r15,  8), i32x4.shr_u(r15, 24))
		r11 = v128.add<i32>(r11, r15); r7  = v128.xor(r7,  r11); r7  = v128.or(i32x4.shl(r7,   7), i32x4.shr_u(r7,  25))

		// Diagonal round: QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)
		r0  = v128.add<i32>(r0,  r5);  r15 = v128.xor(r15, r0);  r15 = v128.or(i32x4.shl(r15, 16), i32x4.shr_u(r15, 16))
		r10 = v128.add<i32>(r10, r15); r5  = v128.xor(r5,  r10); r5  = v128.or(i32x4.shl(r5,  12), i32x4.shr_u(r5,  20))
		r0  = v128.add<i32>(r0,  r5);  r15 = v128.xor(r15, r0);  r15 = v128.or(i32x4.shl(r15,  8), i32x4.shr_u(r15, 24))
		r10 = v128.add<i32>(r10, r15); r5  = v128.xor(r5,  r10); r5  = v128.or(i32x4.shl(r5,   7), i32x4.shr_u(r5,  25))

		r1  = v128.add<i32>(r1,  r6);  r12 = v128.xor(r12, r1);  r12 = v128.or(i32x4.shl(r12, 16), i32x4.shr_u(r12, 16))
		r11 = v128.add<i32>(r11, r12); r6  = v128.xor(r6,  r11); r6  = v128.or(i32x4.shl(r6,  12), i32x4.shr_u(r6,  20))
		r1  = v128.add<i32>(r1,  r6);  r12 = v128.xor(r12, r1);  r12 = v128.or(i32x4.shl(r12,  8), i32x4.shr_u(r12, 24))
		r11 = v128.add<i32>(r11, r12); r6  = v128.xor(r6,  r11); r6  = v128.or(i32x4.shl(r6,   7), i32x4.shr_u(r6,  25))

		r2  = v128.add<i32>(r2,  r7);  r13 = v128.xor(r13, r2);  r13 = v128.or(i32x4.shl(r13, 16), i32x4.shr_u(r13, 16))
		r8  = v128.add<i32>(r8,  r13); r7  = v128.xor(r7,  r8);  r7  = v128.or(i32x4.shl(r7,  12), i32x4.shr_u(r7,  20))
		r2  = v128.add<i32>(r2,  r7);  r13 = v128.xor(r13, r2);  r13 = v128.or(i32x4.shl(r13,  8), i32x4.shr_u(r13, 24))
		r8  = v128.add<i32>(r8,  r13); r7  = v128.xor(r7,  r8);  r7  = v128.or(i32x4.shl(r7,   7), i32x4.shr_u(r7,  25))

		r3  = v128.add<i32>(r3,  r4);  r14 = v128.xor(r14, r3);  r14 = v128.or(i32x4.shl(r14, 16), i32x4.shr_u(r14, 16))
		r9  = v128.add<i32>(r9,  r14); r4  = v128.xor(r4,  r9);  r4  = v128.or(i32x4.shl(r4,  12), i32x4.shr_u(r4,  20))
		r3  = v128.add<i32>(r3,  r4);  r14 = v128.xor(r14, r3);  r14 = v128.or(i32x4.shl(r14,  8), i32x4.shr_u(r14, 24))
		r9  = v128.add<i32>(r9,  r14); r4  = v128.xor(r4,  r9);  r4  = v128.or(i32x4.shl(r4,   7), i32x4.shr_u(r4,  25))
	}

	// Add back initial state — RFC 8439 §2.2
	// Reconstruct initial values from CHACHA_STATE_OFFSET instead of saving
	// 16 extra v128 locals (saves register pressure).
	r0  = v128.add<i32>(r0,  i32x4.splat(load<i32>(s +  0)))
	r1  = v128.add<i32>(r1,  i32x4.splat(load<i32>(s +  4)))
	r2  = v128.add<i32>(r2,  i32x4.splat(load<i32>(s +  8)))
	r3  = v128.add<i32>(r3,  i32x4.splat(load<i32>(s + 12)))
	r4  = v128.add<i32>(r4,  i32x4.splat(load<i32>(s + 16)))
	r5  = v128.add<i32>(r5,  i32x4.splat(load<i32>(s + 20)))
	r6  = v128.add<i32>(r6,  i32x4.splat(load<i32>(s + 24)))
	r7  = v128.add<i32>(r7,  i32x4.splat(load<i32>(s + 28)))
	r8  = v128.add<i32>(r8,  i32x4.splat(load<i32>(s + 32)))
	r9  = v128.add<i32>(r9,  i32x4.splat(load<i32>(s + 36)))
	r10 = v128.add<i32>(r10, i32x4.splat(load<i32>(s + 40)))
	r11 = v128.add<i32>(r11, i32x4.splat(load<i32>(s + 44)))
	// Word 12 initial value: [ctr, ctr+1, ctr+2, ctr+3]
	r12 = v128.add<i32>(r12, i32x4.replace_lane(
		i32x4.replace_lane(
			i32x4.replace_lane(i32x4.splat(ctr as i32), 1, (ctr + 1) as i32),
			2, (ctr + 2) as i32),
		3, (ctr + 3) as i32))
	r13 = v128.add<i32>(r13, i32x4.splat(load<i32>(s + 52)))
	r14 = v128.add<i32>(r14, i32x4.splat(load<i32>(s + 56)))
	r15 = v128.add<i32>(r15, i32x4.splat(load<i32>(s + 60)))

	// Deinterleave and store 256 bytes to CHACHA_SIMD_WORK_OFFSET.
	// r[w] = [blk0_word_w, blk1_word_w, blk2_word_w, blk3_word_w]
	// Extract lane b from each register to assemble block b's keystream.
	// i32x4.extract_lane requires a compile-time constant lane index.
	const w = CHACHA_SIMD_WORK_OFFSET

	// Block 0 (lane 0): bytes 0–63
	store<u32>(w +   0, i32x4.extract_lane(r0,  0)); store<u32>(w +   4, i32x4.extract_lane(r1,  0))
	store<u32>(w +   8, i32x4.extract_lane(r2,  0)); store<u32>(w +  12, i32x4.extract_lane(r3,  0))
	store<u32>(w +  16, i32x4.extract_lane(r4,  0)); store<u32>(w +  20, i32x4.extract_lane(r5,  0))
	store<u32>(w +  24, i32x4.extract_lane(r6,  0)); store<u32>(w +  28, i32x4.extract_lane(r7,  0))
	store<u32>(w +  32, i32x4.extract_lane(r8,  0)); store<u32>(w +  36, i32x4.extract_lane(r9,  0))
	store<u32>(w +  40, i32x4.extract_lane(r10, 0)); store<u32>(w +  44, i32x4.extract_lane(r11, 0))
	store<u32>(w +  48, i32x4.extract_lane(r12, 0)); store<u32>(w +  52, i32x4.extract_lane(r13, 0))
	store<u32>(w +  56, i32x4.extract_lane(r14, 0)); store<u32>(w +  60, i32x4.extract_lane(r15, 0))

	// Block 1 (lane 1): bytes 64–127
	store<u32>(w +  64, i32x4.extract_lane(r0,  1)); store<u32>(w +  68, i32x4.extract_lane(r1,  1))
	store<u32>(w +  72, i32x4.extract_lane(r2,  1)); store<u32>(w +  76, i32x4.extract_lane(r3,  1))
	store<u32>(w +  80, i32x4.extract_lane(r4,  1)); store<u32>(w +  84, i32x4.extract_lane(r5,  1))
	store<u32>(w +  88, i32x4.extract_lane(r6,  1)); store<u32>(w +  92, i32x4.extract_lane(r7,  1))
	store<u32>(w +  96, i32x4.extract_lane(r8,  1)); store<u32>(w + 100, i32x4.extract_lane(r9,  1))
	store<u32>(w + 104, i32x4.extract_lane(r10, 1)); store<u32>(w + 108, i32x4.extract_lane(r11, 1))
	store<u32>(w + 112, i32x4.extract_lane(r12, 1)); store<u32>(w + 116, i32x4.extract_lane(r13, 1))
	store<u32>(w + 120, i32x4.extract_lane(r14, 1)); store<u32>(w + 124, i32x4.extract_lane(r15, 1))

	// Block 2 (lane 2): bytes 128–191
	store<u32>(w + 128, i32x4.extract_lane(r0,  2)); store<u32>(w + 132, i32x4.extract_lane(r1,  2))
	store<u32>(w + 136, i32x4.extract_lane(r2,  2)); store<u32>(w + 140, i32x4.extract_lane(r3,  2))
	store<u32>(w + 144, i32x4.extract_lane(r4,  2)); store<u32>(w + 148, i32x4.extract_lane(r5,  2))
	store<u32>(w + 152, i32x4.extract_lane(r6,  2)); store<u32>(w + 156, i32x4.extract_lane(r7,  2))
	store<u32>(w + 160, i32x4.extract_lane(r8,  2)); store<u32>(w + 164, i32x4.extract_lane(r9,  2))
	store<u32>(w + 168, i32x4.extract_lane(r10, 2)); store<u32>(w + 172, i32x4.extract_lane(r11, 2))
	store<u32>(w + 176, i32x4.extract_lane(r12, 2)); store<u32>(w + 180, i32x4.extract_lane(r13, 2))
	store<u32>(w + 184, i32x4.extract_lane(r14, 2)); store<u32>(w + 188, i32x4.extract_lane(r15, 2))

	// Block 3 (lane 3): bytes 192–255
	store<u32>(w + 192, i32x4.extract_lane(r0,  3)); store<u32>(w + 196, i32x4.extract_lane(r1,  3))
	store<u32>(w + 200, i32x4.extract_lane(r2,  3)); store<u32>(w + 204, i32x4.extract_lane(r3,  3))
	store<u32>(w + 208, i32x4.extract_lane(r4,  3)); store<u32>(w + 212, i32x4.extract_lane(r5,  3))
	store<u32>(w + 216, i32x4.extract_lane(r6,  3)); store<u32>(w + 220, i32x4.extract_lane(r7,  3))
	store<u32>(w + 224, i32x4.extract_lane(r8,  3)); store<u32>(w + 228, i32x4.extract_lane(r9,  3))
	store<u32>(w + 232, i32x4.extract_lane(r10, 3)); store<u32>(w + 236, i32x4.extract_lane(r11, 3))
	store<u32>(w + 240, i32x4.extract_lane(r12, 3)); store<u32>(w + 244, i32x4.extract_lane(r13, 3))
	store<u32>(w + 248, i32x4.extract_lane(r14, 3)); store<u32>(w + 252, i32x4.extract_lane(r15, 3))
}

// ── Exported chunk functions ────────────────────────────────────────────────

// 4-wide inter-block SIMD encrypt: processes 256-byte groups via block4x,
// falls back to scalar for the 0–3 remaining blocks (0–192 bytes).
// Returns len on success, -1 if len is out of range.
export function chachaEncryptChunk_simd(len: i32): i32 {
	if (len <= 0 || len > CHUNK_SIZE) return -1

	let processed: i32 = 0
	let ctr: u32 = load<u32>(CHACHA_STATE_OFFSET + 48)

	// SIMD inner loop: 4 blocks (256 bytes) per iteration
	while (processed + 256 <= len) {
		block4x(ctr)

		// XOR 256 bytes of keystream from SIMD work buffer with plaintext.
		// CHUNK_PT_OFFSET (176), CHUNK_CT_OFFSET (65712), CHACHA_SIMD_WORK_OFFSET
		// (131568) are all 16-byte aligned; processed is always a multiple of 256.
		for (let i = 0; i < 16; i++) {
			const ks = v128.load(CHACHA_SIMD_WORK_OFFSET + i * 16)
			const pt = v128.load(CHUNK_PT_OFFSET + processed + i * 16)
			v128.store(CHUNK_CT_OFFSET + processed + i * 16, v128.xor(ks, pt))
		}

		ctr += 4
		store<u32>(CHACHA_STATE_OFFSET + 48, ctr)
		store<u32>(CHACHA_CTR_OFFSET, ctr)
		processed += 256
	}

	// Scalar tail: 0–3 remaining blocks (0–192 bytes)
	while (processed < len) {
		computeBlock_scalar()

		const remaining = len - processed
		const blockLen  = remaining < 64 ? remaining : 64
		for (let i = 0; i < blockLen; i++) {
			store<u8>(CHUNK_CT_OFFSET + processed + i,
				load<u8>(CHACHA_BLOCK_OFFSET + i) ^ load<u8>(CHUNK_PT_OFFSET + processed + i))
		}

		ctr++
		store<u32>(CHACHA_STATE_OFFSET + 48, ctr)
		store<u32>(CHACHA_CTR_OFFSET, ctr)
		processed += blockLen
	}

	return len
}

export function chachaDecryptChunk_simd(len: i32): i32 {
	return chachaEncryptChunk_simd(len)
}
