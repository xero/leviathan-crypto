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
// src/asm/aes/cbc_simd.ts
//
// SIMD-accelerated AES CBC decrypt: 8 blocks per `decryptBlock_8x` call.
// CBC encrypt remains scalar (in cbc.ts) — the chaining
// `C[i] = E_K(P[i] XOR C[i-1])` is sequential by definition and cannot
// be parallelised. CBC decrypt is parallelisable: every plaintext
// `P[i] = D_K(C[i]) XOR C[i-1]` depends only on already-known
// ciphertext blocks, so all D_K calls can fire simultaneously and the
// XOR chaining is a post-pass.
//
// Algorithm:
//   while remaining >= 128:
//     copy CHUNK_CT[processed..processed+128] → BLOCK_PT_8X (input is CT
//       under aes.ts decryptBlock_8x's encrypt-named buffer convention)
//     decryptBlock_8x()  // 8 plaintexts → BLOCK_CT_8X
//     XOR block 0 with CBC_IV; XOR block i (1..7) with CHUNK_CT[(i-1)*16..]
//     CBC_IV ← CHUNK_CT[processed + 112 .. processed + 128] (last CT)
//     processed += 128
//   scalar fallback (cbcDecryptChunk in cbc.ts) handles the 0..127 tail
//
// Reference: NIST SP 800-38A §6.2 ("In CBC decryption, however, the
// input blocks for the inverse cipher function … are immediately
// available, so that multiple inverse cipher operations can be
// performed in parallel.")

import {
	CBC_IV_OFFSET,
	BLOCK_PT_OFFSET,
	BLOCK_CT_OFFSET,
	BLOCK_PT_8X_OFFSET,
	BLOCK_CT_8X_OFFSET,
	CHUNK_PT_OFFSET,
	CHUNK_CT_OFFSET,
	CHUNK_SIZE,
} from './buffers';

import { decryptBlock, decryptBlock_8x } from './aes';

/**
 * Decrypt one CBC ciphertext block with the chaining block from CBC_IV
 * via the scalar `decryptBlock` path. Used for the 0..127-byte tail of
 * `cbcDecryptChunk_simd`.
 * @internal
 */
@inline function processBlockScalar(ctOffset: i32, ptOffset: i32): void {
	// Copy CT into BLOCK_PT (decryptBlock reads CT from BLOCK_PT, writes
	// PT to BLOCK_CT — see aes.ts decryptBlock buffer-naming note).
	for (let j: i32 = 0; j < 16; j++)
		store<u8>(BLOCK_PT_OFFSET + j, load<u8>(ctOffset + j));

	decryptBlock();

	// XOR with chaining block; advance CBC_IV to current CT.
	for (let j: i32 = 0; j < 16; j++) {
		store<u8>(ptOffset + j,
			load<u8>(BLOCK_CT_OFFSET + j) ^ load<u8>(CBC_IV_OFFSET + j));
		store<u8>(CBC_IV_OFFSET + j, load<u8>(ctOffset + j));
	}
}

/**
 * Decrypt len bytes from CHUNK_CT_BUFFER to CHUNK_PT_BUFFER using AES
 * CBC decrypt with the 8-block bitsliced kernel. Reads chaining from
 * CBC_IV_BUFFER, advances CBC_IV to the last CT block of the chunk.
 * Falls back to the scalar `processBlockScalar` for any 0..127-byte
 * tail.
 * PKCS7 unpadding must be performed by the caller after this returns.
 * @param len  number of bytes to decrypt; must be a positive multiple of 16
 * @returns    len on success, -1 if len is invalid
 */
export function cbcDecryptChunk_simd(len: i32): i32 {
	if (len <= 0 || len > CHUNK_SIZE || len % 16 !== 0) return -1;

	let processed: i32 = 0;

	// 8-block batched inner loop.
	while (processed + 128 <= len) {
		const ctBase = CHUNK_CT_OFFSET + processed;
		const ptBase = CHUNK_PT_OFFSET + processed;

		// Load 8 ciphertext blocks → BLOCK_PT_8X (kernel input buffer).
		memory.copy(BLOCK_PT_8X_OFFSET, ctBase, 128);

		// Decrypt 8 blocks in parallel → 8 plaintext blocks at BLOCK_CT_8X.
		decryptBlock_8x();

		// Block 0: chaining input is the current CBC_IV.
		{
			const pt = v128.load(BLOCK_CT_8X_OFFSET);
			const ch = v128.load(CBC_IV_OFFSET);
			v128.store(ptBase, v128.xor(pt, ch));
		}
		// Blocks 1..7: chaining input is the previous block's ciphertext,
		// taken from the original CHUNK_CT_BUFFER (still intact — the
		// kernel wrote plaintexts into BLOCK_CT_8X, not CHUNK_CT).
		for (let b: i32 = 1; b < 8; b++) {
			const pt = v128.load(BLOCK_CT_8X_OFFSET + (b << 4));
			const ch = v128.load(ctBase + ((b - 1) << 4));
			v128.store(ptBase + (b << 4), v128.xor(pt, ch));
		}

		// New chaining block = the last CT block of this batch.
		memory.copy(CBC_IV_OFFSET, ctBase + 112, 16);

		processed += 128;
	}

	// Scalar tail: 0..127 bytes (0..7 full blocks since len is %16).
	while (processed < len) {
		processBlockScalar(
			CHUNK_CT_OFFSET + processed,
			CHUNK_PT_OFFSET + processed,
		);
		processed += 16;
	}

	return len;
}
