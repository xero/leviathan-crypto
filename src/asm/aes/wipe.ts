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
// src/asm/aes/wipe.ts
//
// Buffer-zeroing on dispose. Every buffer declared in buffers.ts is wiped
// here; key material in particular must not persist after dispose().

import {
	KEY_OFFSET,
	BLOCK_PT_OFFSET, BLOCK_CT_OFFSET,
	BLOCK_PT_8X_OFFSET, BLOCK_CT_8X_OFFSET,
	ROUND_KEYS_OFFSET, ROUND_KEYS_SIZE,
	BITSLICED_STATE_OFFSET, BITSLICED_STATE_SIZE,
	CANRIGHT_SCRATCH_OFFSET, CANRIGHT_SCRATCH_SIZE,
	KEY_SCHEDULE_SCRATCH_OFFSET, KEY_SCHEDULE_SCRATCH_SIZE,
	INV_ROUND_KEYS_OFFSET, INV_ROUND_KEYS_SIZE,
	CHUNK_PT_OFFSET, CHUNK_CT_OFFSET,
	CHUNK_SIZE,
	NR_OFFSET, NR_SIZE,
	NONCE_OFFSET, NONCE_SIZE,
	COUNTER_OFFSET, COUNTER_SIZE,
	CBC_IV_OFFSET, CBC_IV_SIZE,
} from './buffers'

/**
 * Zero every buffer declared in buffers.ts. Called by AES.dispose() in the
 * TS wrapper to ensure key material does not persist in WASM memory.
 */
export function wipeBuffers(): void {
	memory.fill(KEY_OFFSET,                  0, 32);
	memory.fill(BLOCK_PT_OFFSET,             0, 16);
	memory.fill(BLOCK_CT_OFFSET,             0, 16);
	memory.fill(BLOCK_PT_8X_OFFSET,          0, 128);
	memory.fill(BLOCK_CT_8X_OFFSET,          0, 128);
	memory.fill(ROUND_KEYS_OFFSET,           0, ROUND_KEYS_SIZE);
	memory.fill(BITSLICED_STATE_OFFSET,      0, BITSLICED_STATE_SIZE);
	memory.fill(CANRIGHT_SCRATCH_OFFSET,     0, CANRIGHT_SCRATCH_SIZE);
	memory.fill(KEY_SCHEDULE_SCRATCH_OFFSET, 0, KEY_SCHEDULE_SCRATCH_SIZE);
	memory.fill(INV_ROUND_KEYS_OFFSET,       0, INV_ROUND_KEYS_SIZE);
	memory.fill(CHUNK_PT_OFFSET,             0, CHUNK_SIZE);
	memory.fill(CHUNK_CT_OFFSET,             0, CHUNK_SIZE);
	memory.fill(NR_OFFSET,                   0, NR_SIZE);
	memory.fill(NONCE_OFFSET,                0, NONCE_SIZE);
	memory.fill(COUNTER_OFFSET,              0, COUNTER_SIZE);
	memory.fill(CBC_IV_OFFSET,               0, CBC_IV_SIZE);
}
