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
// src/asm/serpent/buffers.ts
//
// Serpent module — static buffer layout.
// Independent linear memory starting at offset 0.
//
// Total: 131732 bytes < 3 × 64KB = 196608 (64876 bytes spare).
//
// Offset   Size     Name
// 0        32       KEY_BUFFER (pad to 32 for all key sizes)
// 32       16       BLOCK_PT_BUFFER
// 48       16       BLOCK_CT_BUFFER
// 64       16       NONCE_BUFFER (CTR mode)
// 80       16       COUNTER_BUFFER (128-bit LE)
// 96       528      SUBKEY_BUFFER (33 rounds × 4 words × 4 bytes)
// 624      65536    CHUNK_PT_BUFFER
// 66160    65536    CHUNK_CT_BUFFER
// 131696   20       WORK_BUFFER (5 × i32 working registers)
// 131716   16       CBC_IV_BUFFER
// 131732            END (< 196608 = 3 × 64KB ✓)

export const CHUNK_SIZE:       i32 = 65536;

export const KEY_OFFSET:       i32 = 0;
export const BLOCK_PT_OFFSET:  i32 = 32;
export const BLOCK_CT_OFFSET:  i32 = 48;
export const NONCE_OFFSET:     i32 = 64;
export const COUNTER_OFFSET:   i32 = 80;
export const SUBKEY_OFFSET:    i32 = 96;
export const CHUNK_PT_OFFSET:  i32 = 624;
export const CHUNK_CT_OFFSET:  i32 = 66160;
export const WORK_OFFSET:      i32 = 131696;
export const CBC_IV_OFFSET:    i32 = 131716;
// END = 131732 < 196608 ✓

export function getModuleId():      i32 {
	return 0;
}
export function getKeyOffset():     i32 {
	return KEY_OFFSET;
}
export function getBlockPtOffset(): i32 {
	return BLOCK_PT_OFFSET;
}
export function getBlockCtOffset(): i32 {
	return BLOCK_CT_OFFSET;
}
export function getNonceOffset():   i32 {
	return NONCE_OFFSET;
}
export function getCounterOffset(): i32 {
	return COUNTER_OFFSET;
}
export function getSubkeyOffset():  i32 {
	return SUBKEY_OFFSET;
}
export function getChunkPtOffset(): i32 {
	return CHUNK_PT_OFFSET;
}
export function getChunkCtOffset(): i32 {
	return CHUNK_CT_OFFSET;
}
export function getWorkOffset():    i32 {
	return WORK_OFFSET;
}
export function getCbcIvOffset():   i32 {
	return CBC_IV_OFFSET;
}
export function getChunkSize():     i32 {
	return CHUNK_SIZE;
}
export function getMemoryPages():   i32 {
	return memory.size();
}
