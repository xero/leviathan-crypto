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
// src/asm/serpent/ctr_simd.ts
//
// SIMD-accelerated Serpent CTR mode: processes 4 counter blocks per iteration.
// Falls back to inline scalar for the 0..3 block tail.

import {
	COUNTER_OFFSET,
	BLOCK_PT_OFFSET,
	BLOCK_CT_OFFSET,
	CHUNK_PT_OFFSET,
	CHUNK_CT_OFFSET,
	CHUNK_SIZE,
	SIMD_WORK_OFFSET,
} from './buffers'

import { encryptBlock_simd_4x } from './serpent_simd'
import { encryptBlock_unrolled as encryptBlock } from './serpent_unrolled'

// ── Counter helpers ─────────────────────────────────────────────────────────

/**
 * Increment the 128-bit little-endian counter in COUNTER_BUFFER by one.
 * Byte 0 is the least significant byte; carry propagates toward byte 15.
 * @internal
 */
@inline function incrementCounter(): void {
	for (let i = 0; i < 16; i++) {
		const b: i32 = i32(load<u8>(COUNTER_OFFSET + i)) + 1
		store<u8>(COUNTER_OFFSET + i, u8(b))
		if (b < 256) break
	}
}

// ── Interleave / Deinterleave ───────────────────────────────────────────────

/**
 * Load 4 consecutive counter values into SIMD working registers at SIMD_WORK_OFFSET.
 * Applies Serpent byte-reversal: r[0]=bytes[15..12], r[1]=[11..8], r[2]=[7..4], r[3]=[3..0].
 * Each v128 register w holds lane[k] = word w of block k (k = 0..3).
 * Advances the counter by 4 as a side effect.
 * @internal
 */
@inline function loadCounters4x(): void {
	// Save base counter
	const c0 = COUNTER_OFFSET

	// Helper: read 4 bytes from counter at offset o as Serpent-internal word (big-endian reversal)
	// w(o) = byte[o+3] | (byte[o+2]<<8) | (byte[o+1]<<16) | (byte[o]<<24)

	// We need 4 counter values: ctr+0, ctr+1, ctr+2, ctr+3
	// Build words for each block, interleave into v128 registers

	// Block 0: current counter
	const b0w0 = i32(load<u8>(c0 + 15)) | (i32(load<u8>(c0 + 14)) << 8) | (i32(load<u8>(c0 + 13)) << 16) | (i32(load<u8>(c0 + 12)) << 24)
	const b0w1 = i32(load<u8>(c0 + 11)) | (i32(load<u8>(c0 + 10)) << 8) | (i32(load<u8>(c0 +  9)) << 16) | (i32(load<u8>(c0 +  8)) << 24)
	const b0w2 = i32(load<u8>(c0 +  7)) | (i32(load<u8>(c0 +  6)) << 8) | (i32(load<u8>(c0 +  5)) << 16) | (i32(load<u8>(c0 +  4)) << 24)
	const b0w3 = i32(load<u8>(c0 +  3)) | (i32(load<u8>(c0 +  2)) << 8) | (i32(load<u8>(c0 +  1)) << 16) | (i32(load<u8>(c0 +  0)) << 24)

	incrementCounter()

	// Block 1
	const b1w0 = i32(load<u8>(c0 + 15)) | (i32(load<u8>(c0 + 14)) << 8) | (i32(load<u8>(c0 + 13)) << 16) | (i32(load<u8>(c0 + 12)) << 24)
	const b1w1 = i32(load<u8>(c0 + 11)) | (i32(load<u8>(c0 + 10)) << 8) | (i32(load<u8>(c0 +  9)) << 16) | (i32(load<u8>(c0 +  8)) << 24)
	const b1w2 = i32(load<u8>(c0 +  7)) | (i32(load<u8>(c0 +  6)) << 8) | (i32(load<u8>(c0 +  5)) << 16) | (i32(load<u8>(c0 +  4)) << 24)
	const b1w3 = i32(load<u8>(c0 +  3)) | (i32(load<u8>(c0 +  2)) << 8) | (i32(load<u8>(c0 +  1)) << 16) | (i32(load<u8>(c0 +  0)) << 24)

	incrementCounter()

	// Block 2
	const b2w0 = i32(load<u8>(c0 + 15)) | (i32(load<u8>(c0 + 14)) << 8) | (i32(load<u8>(c0 + 13)) << 16) | (i32(load<u8>(c0 + 12)) << 24)
	const b2w1 = i32(load<u8>(c0 + 11)) | (i32(load<u8>(c0 + 10)) << 8) | (i32(load<u8>(c0 +  9)) << 16) | (i32(load<u8>(c0 +  8)) << 24)
	const b2w2 = i32(load<u8>(c0 +  7)) | (i32(load<u8>(c0 +  6)) << 8) | (i32(load<u8>(c0 +  5)) << 16) | (i32(load<u8>(c0 +  4)) << 24)
	const b2w3 = i32(load<u8>(c0 +  3)) | (i32(load<u8>(c0 +  2)) << 8) | (i32(load<u8>(c0 +  1)) << 16) | (i32(load<u8>(c0 +  0)) << 24)

	incrementCounter()

	// Block 3
	const b3w0 = i32(load<u8>(c0 + 15)) | (i32(load<u8>(c0 + 14)) << 8) | (i32(load<u8>(c0 + 13)) << 16) | (i32(load<u8>(c0 + 12)) << 24)
	const b3w1 = i32(load<u8>(c0 + 11)) | (i32(load<u8>(c0 + 10)) << 8) | (i32(load<u8>(c0 +  9)) << 16) | (i32(load<u8>(c0 +  8)) << 24)
	const b3w2 = i32(load<u8>(c0 +  7)) | (i32(load<u8>(c0 +  6)) << 8) | (i32(load<u8>(c0 +  5)) << 16) | (i32(load<u8>(c0 +  4)) << 24)
	const b3w3 = i32(load<u8>(c0 +  3)) | (i32(load<u8>(c0 +  2)) << 8) | (i32(load<u8>(c0 +  1)) << 16) | (i32(load<u8>(c0 +  0)) << 24)

	incrementCounter()

	// Interleave into v128 registers: register w = [blk0_w, blk1_w, blk2_w, blk3_w]
	v128.store(SIMD_WORK_OFFSET + 0 * 16, i32x4.replace_lane(i32x4.replace_lane(i32x4.replace_lane(i32x4.splat(b0w0), 1, b1w0), 2, b2w0), 3, b3w0))
	v128.store(SIMD_WORK_OFFSET + 1 * 16, i32x4.replace_lane(i32x4.replace_lane(i32x4.replace_lane(i32x4.splat(b0w1), 1, b1w1), 2, b2w1), 3, b3w1))
	v128.store(SIMD_WORK_OFFSET + 2 * 16, i32x4.replace_lane(i32x4.replace_lane(i32x4.replace_lane(i32x4.splat(b0w2), 1, b1w2), 2, b2w2), 3, b3w2))
	v128.store(SIMD_WORK_OFFSET + 3 * 16, i32x4.replace_lane(i32x4.replace_lane(i32x4.replace_lane(i32x4.splat(b0w3), 1, b1w3), 2, b2w3), 3, b3w3))
}

/**
 * XOR one 16-byte keystream block (supplied as 4 × i32 words) with plaintext.
 * Applies Serpent output byte-reversal: ct[0..3] = w3 big-endian, ct[4..7] = w2, etc.
 * i32x4.extract_lane requires compile-time constant indices, so this helper is
 * called with literal lane values extracted by the caller.
 * @internal
 * @param ptBase  byte offset of the plaintext source in WASM linear memory
 * @param ctBase  byte offset of the ciphertext destination in WASM linear memory
 * @param w0      keystream word 0 (Serpent register r[0])
 * @param w1      keystream word 1 (Serpent register r[1])
 * @param w2      keystream word 2 (Serpent register r[2])
 * @param w3      keystream word 3 (Serpent register r[3])
 */
@inline function xorKeystreamBlock(ptBase: i32, ctBase: i32, w0: i32, w1: i32, w2: i32, w3: i32): void {
	store<u8>(ctBase +  0, u8(w3 >>> 24) ^ load<u8>(ptBase +  0))
	store<u8>(ctBase +  1, u8(w3 >>> 16) ^ load<u8>(ptBase +  1))
	store<u8>(ctBase +  2, u8(w3 >>>  8) ^ load<u8>(ptBase +  2))
	store<u8>(ctBase +  3, u8(w3       ) ^ load<u8>(ptBase +  3))
	store<u8>(ctBase +  4, u8(w2 >>> 24) ^ load<u8>(ptBase +  4))
	store<u8>(ctBase +  5, u8(w2 >>> 16) ^ load<u8>(ptBase +  5))
	store<u8>(ctBase +  6, u8(w2 >>>  8) ^ load<u8>(ptBase +  6))
	store<u8>(ctBase +  7, u8(w2       ) ^ load<u8>(ptBase +  7))
	store<u8>(ctBase +  8, u8(w1 >>> 24) ^ load<u8>(ptBase +  8))
	store<u8>(ctBase +  9, u8(w1 >>> 16) ^ load<u8>(ptBase +  9))
	store<u8>(ctBase + 10, u8(w1 >>>  8) ^ load<u8>(ptBase + 10))
	store<u8>(ctBase + 11, u8(w1       ) ^ load<u8>(ptBase + 11))
	store<u8>(ctBase + 12, u8(w0 >>> 24) ^ load<u8>(ptBase + 12))
	store<u8>(ctBase + 13, u8(w0 >>> 16) ^ load<u8>(ptBase + 13))
	store<u8>(ctBase + 14, u8(w0 >>>  8) ^ load<u8>(ptBase + 14))
	store<u8>(ctBase + 15, u8(w0       ) ^ load<u8>(ptBase + 15))
}

/**
 * Deinterleave and XOR 4 encrypted blocks (64 bytes) of keystream with plaintext.
 * Reads v128 registers from SIMD_WORK_OFFSET and extracts each lane to call
 * `xorKeystreamBlock` for each of the 4 blocks.
 * @internal
 * @param ptOff  byte offset of the plaintext source (start of 4-block group)
 * @param ctOff  byte offset of the ciphertext destination (start of 4-block group)
 */
@inline function xorKeystream4x(ptOff: i32, ctOff: i32): void {
	const r0 = v128.load(SIMD_WORK_OFFSET + 0 * 16)
	const r1 = v128.load(SIMD_WORK_OFFSET + 1 * 16)
	const r2 = v128.load(SIMD_WORK_OFFSET + 2 * 16)
	const r3 = v128.load(SIMD_WORK_OFFSET + 3 * 16)

	// Block 0 — lane 0
	xorKeystreamBlock(ptOff, ctOff,
		i32x4.extract_lane(r0, 0), i32x4.extract_lane(r1, 0),
		i32x4.extract_lane(r2, 0), i32x4.extract_lane(r3, 0))
	// Block 1 — lane 1
	xorKeystreamBlock(ptOff + 16, ctOff + 16,
		i32x4.extract_lane(r0, 1), i32x4.extract_lane(r1, 1),
		i32x4.extract_lane(r2, 1), i32x4.extract_lane(r3, 1))
	// Block 2 — lane 2
	xorKeystreamBlock(ptOff + 32, ctOff + 32,
		i32x4.extract_lane(r0, 2), i32x4.extract_lane(r1, 2),
		i32x4.extract_lane(r2, 2), i32x4.extract_lane(r3, 2))
	// Block 3 — lane 3
	xorKeystreamBlock(ptOff + 48, ctOff + 48,
		i32x4.extract_lane(r0, 3), i32x4.extract_lane(r1, 3),
		i32x4.extract_lane(r2, 3), i32x4.extract_lane(r3, 3))
}

// ── Inline scalar tail ──────────────────────────────────────────────────────

/**
 * Encrypt one counter block (scalar path) and XOR with plaintext.
 * Used for the 0..3 block tail after the SIMD inner loop.
 * Inlined here rather than calling `encryptChunk` from ctr.ts to avoid circular imports.
 * @internal
 * @param ptOffset  byte offset of the plaintext source in WASM linear memory
 * @param ctOffset  byte offset of the ciphertext destination in WASM linear memory
 * @param len       number of bytes to process (1..16)
 */
@inline function processBlockScalar(ptOffset: i32, ctOffset: i32, len: i32): void {
	memory.copy(BLOCK_PT_OFFSET, COUNTER_OFFSET, 16)
	encryptBlock()
	for (let i = 0; i < len; i++) {
		const ks = load<u8>(BLOCK_CT_OFFSET + i)
		const pt = load<u8>(ptOffset + i)
		store<u8>(ctOffset + i, ks ^ pt)
	}
	incrementCounter()
}

// ── Exported CTR encrypt/decrypt ────────────────────────────────────────────

/**
 * Encrypt chunkLen bytes using SIMD-accelerated Serpent CTR mode.
 * Processes 4 blocks (64 bytes) per SIMD iteration; scalar tail handles remainder.
 * CTR mode is symmetric — encryption and decryption are identical operations.
 * Counter must be initialised before calling.
 * @param chunkLen  number of bytes to encrypt (1..CHUNK_SIZE)
 * @returns         chunkLen on success, -1 if chunkLen is out of range
 */
export function encryptChunk_simd(chunkLen: i32): i32 {
	if (chunkLen <= 0 || chunkLen > CHUNK_SIZE) return -1

	let processed: i32 = 0

	// SIMD inner loop: 4 blocks (64 bytes) per iteration
	while (processed + 64 <= chunkLen) {
		loadCounters4x()
		encryptBlock_simd_4x()
		xorKeystream4x(CHUNK_PT_OFFSET + processed, CHUNK_CT_OFFSET + processed)
		processed += 64
	}

	// Scalar tail: 0..3 remaining blocks
	while (processed < chunkLen) {
		const remaining = chunkLen - processed
		const blockLen = remaining < 16 ? remaining : 16
		processBlockScalar(
			CHUNK_PT_OFFSET + processed,
			CHUNK_CT_OFFSET + processed,
			blockLen,
		)
		processed += blockLen
	}

	return chunkLen
}

/**
 * Decrypt chunkLen bytes using SIMD-accelerated Serpent CTR mode.
 * Identical to `encryptChunk_simd` — CTR mode is symmetric.
 * @param chunkLen  number of bytes to decrypt (1..CHUNK_SIZE)
 * @returns         chunkLen on success, -1 if chunkLen is out of range
 */
export function decryptChunk_simd(chunkLen: i32): i32 {
	return encryptChunk_simd(chunkLen)
}
