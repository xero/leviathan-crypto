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
// src/asm/serpent/cbc.ts
//
// Serpent-256 CBC mode streaming encryption/decryption.
//
// Encryption: C[i] = Encrypt(P[i] XOR C[i-1]),  C[-1] = IV
// Decryption: P[i] = Decrypt(C[i]) XOR C[i-1],  C[-1] = IV
//
// CBC_IV_OFFSET holds the chaining block (IV on first call,
// last ciphertext block thereafter). Updated in-place after each chunk.
//
// Caller sets up:
//   KEY_BUFFER[0..32]        — key (via existing loadKey export)
//   CHUNK_PT_OFFSET[0..len]  — plaintext (for cbcEncryptChunk)
//   CHUNK_CT_OFFSET[0..len]  — ciphertext (for cbcDecryptChunk)
//   CBC_IV_OFFSET[0..16]     — IV (caller writes before first chunk)
//
// PKCS7 padding is applied by the TypeScript wrapper — not here.
// Both functions require len to be a positive multiple of 16.

import {
	CBC_IV_OFFSET,
	BLOCK_PT_OFFSET,
	BLOCK_CT_OFFSET,
	CHUNK_PT_OFFSET,
	CHUNK_CT_OFFSET,
	CHUNK_SIZE,
} from './buffers';

import { encryptBlock_unrolled as encryptBlock } from './serpent_unrolled';
import { decryptBlock_unrolled as decryptBlock } from './serpent_unrolled';

// Encrypt len bytes from CHUNK_PT_OFFSET → CHUNK_CT_OFFSET.
// len must be a positive multiple of 16 (PKCS7 padding is the caller's job).
// Updates CBC_IV_OFFSET to the last ciphertext block on return.
// Returns len on success, -1 on invalid len.
export function cbcEncryptChunk(len: i32): i32 {
	if (len <= 0 || len > CHUNK_SIZE || len % 16 !== 0) return -1;

	for (let i: i32 = 0; i < len; i += 16) {
		// XOR plaintext block with chaining block (IV or previous CT) → BLOCK_PT_OFFSET
		for (let j: i32 = 0; j < 16; j++) {
			store<u8>(BLOCK_PT_OFFSET + j,
				load<u8>(CHUNK_PT_OFFSET + i + j) ^ load<u8>(CBC_IV_OFFSET + j));
		}

		// Encrypt → result in BLOCK_CT_OFFSET
		encryptBlock();

		// Write ciphertext output and update chaining block
		for (let j: i32 = 0; j < 16; j++) {
			const ct: u8 = load<u8>(BLOCK_CT_OFFSET + j);
			store<u8>(CHUNK_CT_OFFSET + i + j, ct);
			store<u8>(CBC_IV_OFFSET + j, ct);
		}
	}
	return len;
}

// Decrypt len bytes from CHUNK_CT_OFFSET → CHUNK_PT_OFFSET.
// len must be a positive multiple of 16.
// Updates CBC_IV_OFFSET to the last ciphertext block on return.
// Returns len on success, -1 on invalid len.
export function cbcDecryptChunk(len: i32): i32 {
	if (len <= 0 || len > CHUNK_SIZE || len % 16 !== 0) return -1;

	for (let i: i32 = 0; i < len; i += 16) {
		// Copy ciphertext block to BLOCK_CT_OFFSET for decryptBlock
		for (let j: i32 = 0; j < 16; j++)
			store<u8>(BLOCK_CT_OFFSET + j, load<u8>(CHUNK_CT_OFFSET + i + j));

		// Decrypt → result in BLOCK_PT_OFFSET
		decryptBlock();

		// XOR with chaining block to get plaintext; update chaining block from CHUNK_CT_OFFSET
		// (CHUNK_CT_OFFSET[i..] is still the original CT — decryptBlock does not touch it)
		for (let j: i32 = 0; j < 16; j++) {
			store<u8>(CHUNK_PT_OFFSET + i + j,
				load<u8>(BLOCK_PT_OFFSET + j) ^ load<u8>(CBC_IV_OFFSET + j));
			store<u8>(CBC_IV_OFFSET + j, load<u8>(CHUNK_CT_OFFSET + i + j));
		}
	}
	return len;
}
