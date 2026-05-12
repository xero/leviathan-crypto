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
// src/asm/aes/ctr.ts
//
// AES-128/192/256 CTR mode streaming encryption/decryption.
// Reference: NIST SP 800-38A §6.5 (mode), Appendix B.1 (Standard
// Incrementing Function), Appendix F.5 (worked example vectors).
//
// Counter format: 128-bit big-endian stored in COUNTER_BUFFER. Byte 15 is
// the least-significant byte; increment propagates carry from byte 15
// downward toward byte 0.
//
// This is the canonical AES CTR convention. SP 800-38A §F.5 worked
// examples validate against big-endian incrementing, the §F.5.1 transition
// from IC = `f0f1...feff` to IC+1 = `f0f1...ff00` (byte 15 wraps, byte 14
// increments) confirms it. The Serpent module in this repo uses 128-bit
// little-endian by historical choice; AES matches the NIST AES convention.
//
// `resetCounter()` copies NONCE_BUFFER → COUNTER_BUFFER, the nonce IS
// the initial counter block, parallel to the Serpent CTR shape but with
// the increment direction flipped.

import {
	NONCE_OFFSET,
	COUNTER_OFFSET,
	BLOCK_PT_OFFSET,
	BLOCK_CT_OFFSET,
	CHUNK_PT_OFFSET,
	CHUNK_CT_OFFSET,
	CHUNK_SIZE,
} from './buffers';

import { encryptBlock } from './aes';

// ── Counter management ──────────────────────────────────────────────────────

/**
 * Reset the CTR counter to the current nonce value.
 * Copies 16 bytes from NONCE_BUFFER to COUNTER_BUFFER, establishing the
 * nonce as the initial 128-bit big-endian counter block.
 */
export function resetCounter(): void {
	memory.copy(COUNTER_OFFSET, NONCE_OFFSET, 16);
}

/**
 * Increment the 128-bit big-endian counter in COUNTER_BUFFER by one.
 * Byte 15 is the least significant byte; carry propagates toward byte 0.
 * @internal
 */
@inline function incrementCounter(): void {
	for (let i = 15; i >= 0; i--) {
		const b: i32 = i32(load<u8>(COUNTER_OFFSET + i)) + 1;
		store<u8>(COUNTER_OFFSET + i, u8(b));
		if (b < 256) break;
	}
}

/**
 * Set the 128-bit CTR counter to an absolute big-endian value.
 * Used by future worker-pool flows so each worker can start at the correct
 * counter block without calling `resetCounter()`.
 * @param hi  high 64 bits of the counter (bytes 0-7 of COUNTER_BUFFER, big-endian)
 * @param lo  low 64 bits of the counter (bytes 8-15 of COUNTER_BUFFER, big-endian)
 */
export function setCounter(hi: i64, lo: i64): void {
	// store<i64> writes little-endian; bswap to land big-endian bytes.
	store<i64>(COUNTER_OFFSET,     bswap<i64>(hi));
	store<i64>(COUNTER_OFFSET + 8, bswap<i64>(lo));
}

// ── CTR block processing ────────────────────────────────────────────────────

/**
 * Encrypt one counter block and XOR the keystream with `len` plaintext bytes
 * at the given offsets. Advances the counter by one after writing.
 * @internal
 * @param ptOffset  byte offset of the plaintext source
 * @param ctOffset  byte offset of the ciphertext destination
 * @param len       number of bytes to process (1..16); supports partial final block
 */
@inline function processBlock(ptOffset: i32, ctOffset: i32, len: i32): void {
	memory.copy(BLOCK_PT_OFFSET, COUNTER_OFFSET, 16);
	encryptBlock();
	for (let i = 0; i < len; i++) {
		const ks = load<u8>(BLOCK_CT_OFFSET + i);
		const pt = load<u8>(ptOffset + i);
		store<u8>(ctOffset + i, ks ^ pt);
	}
	incrementCounter();
}

// ── Exported CTR encrypt/decrypt ────────────────────────────────────────────

/**
 * Encrypt chunkLen bytes from CHUNK_PT_BUFFER to CHUNK_CT_BUFFER using AES CTR mode.
 * CTR is symmetric, encryption and decryption are identical operations.
 * Counter must be initialised via `resetCounter()` or `setCounter()` before calling.
 * @param chunkLen  number of bytes to encrypt (1..CHUNK_SIZE)
 * @returns         chunkLen on success, -1 if chunkLen is out of range
 */
export function encryptChunk(chunkLen: i32): i32 {
	if (chunkLen <= 0 || chunkLen > CHUNK_SIZE) return -1;
	let processed: i32 = 0;
	while (processed < chunkLen) {
		const remaining = chunkLen - processed;
		const blockLen = remaining < 16 ? remaining : 16;
		processBlock(
			CHUNK_PT_OFFSET + processed,
			CHUNK_CT_OFFSET + processed,
			blockLen,
		);
		processed += blockLen;
	}
	return chunkLen;
}

/**
 * Decrypt chunkLen bytes from CHUNK_CT_BUFFER to CHUNK_PT_BUFFER using AES CTR mode.
 * Identical to `encryptChunk`, CTR mode is symmetric.
 * @param chunkLen  number of bytes to decrypt (1..CHUNK_SIZE)
 * @returns         chunkLen on success, -1 if chunkLen is out of range
 */
export function decryptChunk(chunkLen: i32): i32 {
	return encryptChunk(chunkLen);
}
