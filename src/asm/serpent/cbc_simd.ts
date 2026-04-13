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
// src/asm/serpent/cbc_simd.ts
//
// SIMD-accelerated Serpent CBC decrypt: 4 blocks decrypted simultaneously.
// CBC encrypt stays scalar (sequential dependency — not parallelizable).
//
// After decryptBlock_simd_4x(), output registers are [4,1,3,2]:
//   r[4] → bytes 0..3, r[1] → bytes 4..7, r[3] → bytes 8..11, r[2] → bytes 12..15

import {
	CBC_IV_OFFSET,
	BLOCK_CT_OFFSET,
	BLOCK_PT_OFFSET,
	CHUNK_CT_OFFSET,
	CHUNK_PT_OFFSET,
	CHUNK_SIZE,
	SIMD_WORK_OFFSET,
} from './buffers'

import { decryptBlock_simd_4x } from './serpent_simd'
import { decryptBlock_unrolled as decryptBlock } from './serpent_unrolled'

// ── Byte-reversal word load ─────────────────────────────────────────────────
// Serpent internal format: r[0]=bytes[15..12], r[1]=[11..8], r[2]=[7..4], r[3]=[3..0]

/**
 * Read Serpent working-register word 0 from a 16-byte block at `base`.
 * Applies Serpent byte-reversal: bytes[15..12] assembled as big-endian i32.
 * @internal
 * @param base  byte offset of the 16-byte block in WASM linear memory
 * @returns     word 0 in Serpent internal format
 */
@inline function w0(base: i32): i32 {
	return i32(load<u8>(base + 15)) | (i32(load<u8>(base + 14)) << 8) | (i32(load<u8>(base + 13)) << 16) | (i32(load<u8>(base + 12)) << 24)
}

/**
 * Read Serpent working-register word 1 from a 16-byte block at `base`.
 * Applies Serpent byte-reversal: bytes[11..8] assembled as big-endian i32.
 * @internal
 * @param base  byte offset of the 16-byte block in WASM linear memory
 * @returns     word 1 in Serpent internal format
 */
@inline function w1(base: i32): i32 {
	return i32(load<u8>(base + 11)) | (i32(load<u8>(base + 10)) << 8) | (i32(load<u8>(base +  9)) << 16) | (i32(load<u8>(base +  8)) << 24)
}

/**
 * Read Serpent working-register word 2 from a 16-byte block at `base`.
 * Applies Serpent byte-reversal: bytes[7..4] assembled as big-endian i32.
 * @internal
 * @param base  byte offset of the 16-byte block in WASM linear memory
 * @returns     word 2 in Serpent internal format
 */
@inline function w2(base: i32): i32 {
	return i32(load<u8>(base +  7)) | (i32(load<u8>(base +  6)) << 8) | (i32(load<u8>(base +  5)) << 16) | (i32(load<u8>(base +  4)) << 24)
}

/**
 * Read Serpent working-register word 3 from a 16-byte block at `base`.
 * Applies Serpent byte-reversal: bytes[3..0] assembled as big-endian i32.
 * @internal
 * @param base  byte offset of the 16-byte block in WASM linear memory
 * @returns     word 3 in Serpent internal format
 */
@inline function w3(base: i32): i32 {
	return i32(load<u8>(base +  3)) | (i32(load<u8>(base +  2)) << 8) | (i32(load<u8>(base +  1)) << 16) | (i32(load<u8>(base +  0)) << 24)
}

// ── Load 4 ciphertext blocks into SIMD working registers ────────────────────

/**
 * Interleave 4 consecutive ciphertext blocks into v128 SIMD working registers.
 * Each v128 register w holds: lane[k] = word w of block k (k = 0..3).
 * Reads 64 bytes starting at ctBase.
 * @internal
 * @param ctBase  byte offset of the first of 4 ciphertext blocks in WASM linear memory
 */
@inline function loadCiphertext4x(ctBase: i32): void {
	const b0 = ctBase
	const b1 = ctBase + 16
	const b2 = ctBase + 32
	const b3 = ctBase + 48

	v128.store(SIMD_WORK_OFFSET +  0, i32x4.replace_lane(i32x4.replace_lane(i32x4.replace_lane(i32x4.splat(w0(b0)), 1, w0(b1)), 2, w0(b2)), 3, w0(b3)))
	v128.store(SIMD_WORK_OFFSET + 16, i32x4.replace_lane(i32x4.replace_lane(i32x4.replace_lane(i32x4.splat(w1(b0)), 1, w1(b1)), 2, w1(b2)), 3, w1(b3)))
	v128.store(SIMD_WORK_OFFSET + 32, i32x4.replace_lane(i32x4.replace_lane(i32x4.replace_lane(i32x4.splat(w2(b0)), 1, w2(b1)), 2, w2(b2)), 3, w2(b3)))
	v128.store(SIMD_WORK_OFFSET + 48, i32x4.replace_lane(i32x4.replace_lane(i32x4.replace_lane(i32x4.splat(w3(b0)), 1, w3(b1)), 2, w3(b2)), 3, w3(b3)))
}

// ── Deinterleave one decrypted block and XOR with chaining value ────────────

/**
 * Write one decrypted CBC block to plaintext memory, XORing with the chaining block.
 * Decryption output slot layout: r[4]→bytes[0..3], r[1]→[4..7], r[3]→[8..11], r[2]→[12..15].
 * @internal
 * @param ptBase    byte offset of the plaintext destination in WASM linear memory
 * @param chainBase byte offset of the 16-byte chaining block (IV or previous ciphertext)
 * @param rw4       decrypted word from register slot 4 (bytes 0..3)
 * @param rw1       decrypted word from register slot 1 (bytes 4..7)
 * @param rw3       decrypted word from register slot 3 (bytes 8..11)
 * @param rw2       decrypted word from register slot 2 (bytes 12..15)
 */
@inline function writeDecryptedBlock(ptBase: i32, chainBase: i32, rw4: i32, rw1: i32, rw3: i32, rw2: i32): void {
	store<u8>(ptBase +  0, u8(rw4 >>> 24) ^ load<u8>(chainBase +  0))
	store<u8>(ptBase +  1, u8(rw4 >>> 16) ^ load<u8>(chainBase +  1))
	store<u8>(ptBase +  2, u8(rw4 >>>  8) ^ load<u8>(chainBase +  2))
	store<u8>(ptBase +  3, u8(rw4       ) ^ load<u8>(chainBase +  3))
	store<u8>(ptBase +  4, u8(rw1 >>> 24) ^ load<u8>(chainBase +  4))
	store<u8>(ptBase +  5, u8(rw1 >>> 16) ^ load<u8>(chainBase +  5))
	store<u8>(ptBase +  6, u8(rw1 >>>  8) ^ load<u8>(chainBase +  6))
	store<u8>(ptBase +  7, u8(rw1       ) ^ load<u8>(chainBase +  7))
	store<u8>(ptBase +  8, u8(rw3 >>> 24) ^ load<u8>(chainBase +  8))
	store<u8>(ptBase +  9, u8(rw3 >>> 16) ^ load<u8>(chainBase +  9))
	store<u8>(ptBase + 10, u8(rw3 >>>  8) ^ load<u8>(chainBase + 10))
	store<u8>(ptBase + 11, u8(rw3       ) ^ load<u8>(chainBase + 11))
	store<u8>(ptBase + 12, u8(rw2 >>> 24) ^ load<u8>(chainBase + 12))
	store<u8>(ptBase + 13, u8(rw2 >>> 16) ^ load<u8>(chainBase + 13))
	store<u8>(ptBase + 14, u8(rw2 >>>  8) ^ load<u8>(chainBase + 14))
	store<u8>(ptBase + 15, u8(rw2       ) ^ load<u8>(chainBase + 15))
}

// ── Deinterleave 4 decrypted blocks with CBC chaining XOR ───────────────────

/**
 * Deinterleave 4 decrypted blocks from SIMD registers and apply CBC chaining XOR.
 * Chaining: block 0 XORs with CBC_IV_BUFFER; blocks 1-3 XOR with CT[n], CT[n+1], CT[n+2].
 * Updates CBC_IV_BUFFER to CT[n+3] after writing all 4 plaintext blocks.
 * Unrolled because i32x4.extract_lane requires compile-time constant lane indices.
 * @internal
 * @param processed  byte offset into the current chunk (marks start of this 4-block group)
 */
@inline function deinterleaveDecrypt4x(processed: i32): void {
	const r4 = v128.load(SIMD_WORK_OFFSET + 4 * 16)
	const r1 = v128.load(SIMD_WORK_OFFSET + 1 * 16)
	const r3 = v128.load(SIMD_WORK_OFFSET + 3 * 16)
	const r2 = v128.load(SIMD_WORK_OFFSET + 2 * 16)

	const ptBase = CHUNK_PT_OFFSET + processed
	const ctBase = CHUNK_CT_OFFSET + processed

	// Block 0: chain = CBC_IV_OFFSET
	writeDecryptedBlock(ptBase, CBC_IV_OFFSET,
		i32x4.extract_lane(r4, 0), i32x4.extract_lane(r1, 0),
		i32x4.extract_lane(r3, 0), i32x4.extract_lane(r2, 0))

	// Block 1: chain = CT[n+0]
	writeDecryptedBlock(ptBase + 16, ctBase,
		i32x4.extract_lane(r4, 1), i32x4.extract_lane(r1, 1),
		i32x4.extract_lane(r3, 1), i32x4.extract_lane(r2, 1))

	// Block 2: chain = CT[n+1]
	writeDecryptedBlock(ptBase + 32, ctBase + 16,
		i32x4.extract_lane(r4, 2), i32x4.extract_lane(r1, 2),
		i32x4.extract_lane(r3, 2), i32x4.extract_lane(r2, 2))

	// Block 3: chain = CT[n+2]
	writeDecryptedBlock(ptBase + 48, ctBase + 32,
		i32x4.extract_lane(r4, 3), i32x4.extract_lane(r1, 3),
		i32x4.extract_lane(r3, 3), i32x4.extract_lane(r2, 3))

	// Update chaining block to CT[n+3] — the last ciphertext in this group
	memory.copy(CBC_IV_OFFSET, ctBase + 48, 16)
}

// ── Inline scalar tail ──────────────────────────────────────────────────────

/**
 * Decrypt one 16-byte CBC block using the scalar path.
 * Used for the 0..3 block tail after the SIMD inner loop.
 * Copies CT to BLOCK_CT_BUFFER, decrypts, XORs with CBC_IV_BUFFER, updates chaining block.
 * @internal
 * @param ctOff  byte offset of the ciphertext block in WASM linear memory
 * @param ptOff  byte offset of the plaintext destination in WASM linear memory
 */
@inline function decryptBlockScalar(ctOff: i32, ptOff: i32): void {
	// Copy CT to BLOCK_CT_BUFFER, decrypt, XOR with chaining, update chain
	for (let j: i32 = 0; j < 16; j++)
		store<u8>(BLOCK_CT_OFFSET + j, load<u8>(ctOff + j))
	decryptBlock()
	for (let j: i32 = 0; j < 16; j++) {
		store<u8>(ptOff + j, load<u8>(BLOCK_PT_OFFSET + j) ^ load<u8>(CBC_IV_OFFSET + j))
		store<u8>(CBC_IV_OFFSET + j, load<u8>(ctOff + j))
	}
}

// ── Exported CBC SIMD decrypt ───────────────────────────────────────────────

/**
 * Decrypt chunkLen bytes from CHUNK_CT_BUFFER to CHUNK_PT_BUFFER using SIMD-accelerated
 * Serpent CBC mode. Processes 4 blocks (64 bytes) per SIMD iteration; scalar tail handles
 * any remainder. CBC encrypt stays scalar (sequential dependency — not parallelizable).
 * PKCS7 unpadding must be performed by the caller after this function returns.
 * @param chunkLen  number of bytes to decrypt; must be a positive multiple of 16
 * @returns         chunkLen on success, -1 if chunkLen is invalid
 */
export function cbcDecryptChunk_simd(chunkLen: i32): i32 {
	if (chunkLen <= 0 || chunkLen > CHUNK_SIZE || chunkLen % 16 !== 0) return -1

	let processed: i32 = 0

	// SIMD inner loop: 4 blocks (64 bytes) per iteration
	while (processed + 64 <= chunkLen) {
		loadCiphertext4x(CHUNK_CT_OFFSET + processed)
		decryptBlock_simd_4x()
		deinterleaveDecrypt4x(processed)
		processed += 64
	}

	// Scalar tail: 0..3 remaining blocks
	while (processed < chunkLen) {
		decryptBlockScalar(
			CHUNK_CT_OFFSET + processed,
			CHUNK_PT_OFFSET + processed,
		)
		processed += 16
	}

	return chunkLen
}
