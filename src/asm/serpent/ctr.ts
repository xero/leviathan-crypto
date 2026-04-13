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
// src/asm/serpent/ctr.ts
//
// Serpent CTR mode streaming encryption/decryption.
//
// Counter format: 128-bit little-endian stored in COUNTER_BUFFER.
// Byte 0 is least-significant; increment propagates carry from byte 0 upward.
// This matches leviathan blockmode.ts (ctr[0]++ with LE carry propagation).
//
// resetCounter() COPIES NONCE_BUFFER → COUNTER_BUFFER (nonce IS the initial
// counter value, matching leviathan CTR class: this.ctr.set(iv)).

import {
	NONCE_OFFSET,
	COUNTER_OFFSET,
	BLOCK_PT_OFFSET,
	BLOCK_CT_OFFSET,
	CHUNK_PT_OFFSET,
	CHUNK_CT_OFFSET,
	CHUNK_SIZE,
} from './buffers'

import { encryptBlock_unrolled as encryptBlock } from './serpent_unrolled'

// ── Counter management ──────────────────────────────────────────────────────

/**
 * Reset the CTR counter to the current nonce value.
 * Copies 16 bytes from NONCE_BUFFER to COUNTER_BUFFER, establishing
 * the nonce as the initial 128-bit little-endian counter value.
 */
export function resetCounter(): void {
	memory.copy(COUNTER_OFFSET, NONCE_OFFSET, 16)
}

/**
 * Increment the 128-bit little-endian counter in COUNTER_BUFFER by one.
 * Byte 0 is the least significant byte; carry propagates toward byte 15.
 * @internal
 */
@inline function incrementCounter(): void {
	for (let i = 0; i < 16; i++) {
		const b: i32 = i32(load<u8>(COUNTER_OFFSET + i)) + 1
		store<u8>(COUNTER_OFFSET + i, u8(b))
		if (b < 256) break  // no carry
		// carry: byte wrapped to 0, continue to next byte
	}
}

// ── CTR block processing ────────────────────────────────────────────────────

/**
 * Encrypt one counter block and XOR with plaintext bytes at the given offsets.
 * Advances the counter by one after writing the keystream.
 * @internal
 * @param ptOffset  byte offset of the plaintext source in WASM linear memory
 * @param ctOffset  byte offset of the ciphertext destination in WASM linear memory
 * @param len       number of bytes to process (1..16); supports partial final block
 */
@inline function processBlock(ptOffset: i32, ctOffset: i32, len: i32): void {
	// Copy current counter to BLOCK_PT_BUFFER, then encrypt it
	memory.copy(BLOCK_PT_OFFSET, COUNTER_OFFSET, 16)
	encryptBlock()
	// result (keystream block) is now in BLOCK_CT_BUFFER
	// XOR keystream with plaintext, write to ciphertext buffer
	for (let i = 0; i < len; i++) {
		const ks = load<u8>(BLOCK_CT_OFFSET + i)
		const pt = load<u8>(ptOffset + i)
		store<u8>(ctOffset + i, ks ^ pt)
	}
	incrementCounter()
}

// ── Exported CTR encrypt/decrypt ────────────────────────────────────────────

/**
 * Encrypt chunkLen bytes from CHUNK_PT_BUFFER to CHUNK_CT_BUFFER using Serpent CTR mode.
 * CTR mode is symmetric — encryption and decryption are identical operations.
 * Counter must be initialised via `resetCounter()` or `setCounter()` before calling.
 * @param chunkLen  number of bytes to encrypt (1..CHUNK_SIZE)
 * @returns         chunkLen on success, -1 if chunkLen is out of range
 */
export function encryptChunk(chunkLen: i32): i32 {
	if (chunkLen <= 0 || chunkLen > CHUNK_SIZE) return -1
	let processed: i32 = 0
	while (processed < chunkLen) {
		const remaining = chunkLen - processed
		const blockLen = remaining < 16 ? remaining : 16
		processBlock(
			CHUNK_PT_OFFSET + processed,
			CHUNK_CT_OFFSET + processed,
			blockLen,
		)
		processed += blockLen
	}
	return chunkLen
}

/**
 * Decrypt chunkLen bytes from CHUNK_CT_BUFFER to CHUNK_PT_BUFFER using Serpent CTR mode.
 * Identical to `encryptChunk` — CTR mode is symmetric.
 * @param chunkLen  number of bytes to decrypt (1..CHUNK_SIZE)
 * @returns         chunkLen on success, -1 if chunkLen is out of range
 */
export function decryptChunk(chunkLen: i32): i32 {
	return encryptChunk(chunkLen)
}

// ── Absolute counter positioning (worker pool) ──────────────────────────────

/**
 * Set the 128-bit CTR counter to an absolute block position.
 * Used by the worker pool so each worker can start at the correct counter value
 * without calling `resetCounter()`. Each worker operates on a non-overlapping range.
 * @param lo  low 64 bits of the counter (bytes 0-7 of COUNTER_BUFFER, little-endian)
 * @param hi  high 64 bits of the counter (bytes 8-15 of COUNTER_BUFFER, little-endian)
 */
export function setCounter(lo: i64, hi: i64): void {
	store<i64>(COUNTER_OFFSET, lo)
	store<i64>(COUNTER_OFFSET + 8, hi)
}
