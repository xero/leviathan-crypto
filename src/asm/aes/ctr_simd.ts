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
//                           ▀█████▀▀▀
//
// src/asm/aes/ctr_simd.ts
//
// SIMD-accelerated AES CTR mode: processes 8 counter blocks per
// iteration via the bitsliced `encryptBlock_8x` kernel. The 8-block
// batch is the natural width of the AES bitsliced kernel
// (Käsper-Schwabe §4); SIMD here means "use the kernel as-is" rather
// than additional v128 work in the mode loop itself.
//
// Counter direction: 128-bit big-endian (matches SP 800-38A Appendix
// B.1 / §F.5 worked examples). See ctr.ts for the rationale.
//
// Algorithm: build 8 sequential counter blocks at BLOCK_PT_8X (offsets
// 0, 16, 32, ..., 112), call `encryptBlock_8x()` to produce 8 keystream
// blocks at BLOCK_CT_8X, then XOR with 128 bytes of plaintext. The
// 0..127-byte tail falls back to the scalar `processBlock` path.

import {
	COUNTER_OFFSET,
	BLOCK_PT_OFFSET,
	BLOCK_CT_OFFSET,
	BLOCK_PT_8X_OFFSET,
	BLOCK_CT_8X_OFFSET,
	CHUNK_PT_OFFSET,
	CHUNK_CT_OFFSET,
	CHUNK_SIZE,
} from './buffers';

import { encryptBlock, encryptBlock_8x } from './aes';

// ── Counter helpers ─────────────────────────────────────────────────────────

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
 * Encrypt one counter block (scalar tail) and XOR with `len` plaintext bytes.
 * Mirrors the equivalent helper in ctr.ts; inlined here to avoid a circular
 * import on the scalar `processBlock`.
 * @internal
 */
@inline function processBlockScalar(ptOffset: i32, ctOffset: i32, len: i32): void {
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
 * Encrypt chunkLen bytes using the 8-block bitsliced AES kernel for CTR mode.
 * Processes 128 bytes (8 blocks) per kernel call; remaining 0..127 bytes
 * use the scalar `processBlockScalar` path. CTR is symmetric — encrypt and
 * decrypt are identical operations.
 * Counter must be initialised before calling.
 * @param chunkLen  number of bytes to encrypt (1..CHUNK_SIZE)
 * @returns         chunkLen on success, -1 if chunkLen is out of range
 */
export function encryptChunk_simd(chunkLen: i32): i32 {
	if (chunkLen <= 0 || chunkLen > CHUNK_SIZE) return -1;

	let processed: i32 = 0;

	// 8-block inner loop: 128 bytes per kernel call.
	while (processed + 128 <= chunkLen) {
		// Lay 8 sequential counter blocks into BLOCK_PT_8X[0..128].
		for (let b: i32 = 0; b < 8; b++) {
			memory.copy(BLOCK_PT_8X_OFFSET + (b << 4), COUNTER_OFFSET, 16);
			incrementCounter();
		}
		// Run the bitsliced kernel: 8 keystream blocks → BLOCK_CT_8X.
		encryptBlock_8x();
		// XOR keystream with 128 plaintext bytes → ciphertext.
		// v128 chunks where alignment permits (16-byte stride).
		const ptBase = CHUNK_PT_OFFSET + processed;
		const ctBase = CHUNK_CT_OFFSET + processed;
		for (let off: i32 = 0; off < 128; off += 16) {
			const ks = v128.load(BLOCK_CT_8X_OFFSET + off);
			const pt = v128.load(ptBase + off);
			v128.store(ctBase + off, v128.xor(ks, pt));
		}
		processed += 128;
	}

	// Scalar tail: 0..127 remaining bytes (0..7 blocks plus partial).
	while (processed < chunkLen) {
		const remaining = chunkLen - processed;
		const blockLen = remaining < 16 ? remaining : 16;
		processBlockScalar(
			CHUNK_PT_OFFSET + processed,
			CHUNK_CT_OFFSET + processed,
			blockLen,
		);
		processed += blockLen;
	}

	return chunkLen;
}

/**
 * Decrypt chunkLen bytes using SIMD-accelerated AES CTR mode.
 * Identical to `encryptChunk_simd` — CTR mode is symmetric.
 * @param chunkLen  number of bytes to decrypt (1..CHUNK_SIZE)
 * @returns         chunkLen on success, -1 if chunkLen is out of range
 */
export function decryptChunk_simd(chunkLen: i32): i32 {
	return encryptChunk_simd(chunkLen);
}
