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
// src/asm/chacha/wipe.ts
//
// Zeroes all ChaCha20/Poly1305/XChaCha20 buffers.
// Key material, state, and intermediate values must not persist after dispose().

import {
	KEY_OFFSET, CHUNK_SIZE,
	CHACHA_NONCE_OFFSET, CHACHA_CTR_OFFSET,
	CHACHA_BLOCK_OFFSET, CHACHA_STATE_OFFSET,
	CHUNK_PT_OFFSET, CHUNK_CT_OFFSET,
	POLY_KEY_OFFSET, POLY_MSG_OFFSET,
	POLY_BUF_OFFSET, POLY_BUF_LEN_OFFSET,
	POLY_TAG_OFFSET,
	POLY_H_OFFSET, POLY_R_OFFSET, POLY_RS_OFFSET, POLY_S_OFFSET,
	XCHACHA_NONCE_OFFSET, XCHACHA_SUBKEY_OFFSET,
} from './buffers';

export function wipeBuffers(): void {
	// ChaCha20 key and state
	memory.fill(KEY_OFFSET,           0, 32);    // 256-bit key
	memory.fill(CHACHA_NONCE_OFFSET,  0, 12);    // 96-bit nonce
	memory.fill(CHACHA_CTR_OFFSET,    0,  4);    // counter
	memory.fill(CHACHA_BLOCK_OFFSET,  0, 64);    // keystream block
	memory.fill(CHACHA_STATE_OFFSET,  0, 64);    // contains key copy (words 4–11)

	// Chunk buffers
	memory.fill(CHUNK_PT_OFFSET,      0, CHUNK_SIZE);
	memory.fill(CHUNK_CT_OFFSET,      0, CHUNK_SIZE);

	// Poly1305 state and key material
	memory.fill(POLY_KEY_OFFSET,      0, 32);    // one-time key r||s
	memory.fill(POLY_MSG_OFFSET,      0, 64);    // message staging
	memory.fill(POLY_BUF_OFFSET,      0, 16);    // partial block accumulator
	memory.fill(POLY_BUF_LEN_OFFSET,  0,  4);    // partial block length
	memory.fill(POLY_TAG_OFFSET,      0, 16);    // output tag
	memory.fill(POLY_H_OFFSET,        0, 40);    // accumulator h
	memory.fill(POLY_R_OFFSET,        0, 40);    // clamped r
	memory.fill(POLY_RS_OFFSET,       0, 32);    // precomputed 5×r[1..4]
	memory.fill(POLY_S_OFFSET,        0, 16);    // s pad

	// XChaCha20 nonce and subkey (key-derived material)
	memory.fill(XCHACHA_NONCE_OFFSET,  0, 24);   // full 24-byte nonce
	memory.fill(XCHACHA_SUBKEY_OFFSET, 0, 32);   // HChaCha20 subkey
}
