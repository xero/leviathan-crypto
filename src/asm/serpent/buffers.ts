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
// Total: 131856 bytes < 3 × 64KB = 196608 (64752 bytes spare).
//
// Offset   Size     Name
// 0        32       KEY_BUFFER (pad to 32 for all key sizes)
// 32       16       BLOCK_PT_BUFFER
// 48       16       BLOCK_CT_BUFFER
// 64       16       NONCE_BUFFER (CTR mode)
// 80       16       COUNTER_BUFFER (128-bit LE)
// 96       528      SUBKEY_BUFFER (33 rounds × 4 words × 4 bytes)
// 624      65552    CHUNK_PT_BUFFER   (+16 from 65536; accommodates PKCS7 max overhead)
// 66176    65552    CHUNK_CT_BUFFER   (+16, start shifts +16)
// 131728   20       WORK_BUFFER       (start shifts +32)
// 131748   16       CBC_IV_BUFFER     (start shifts +32)
// 131764   12       (alignment pad)
// 131776   80       SIMD_WORK_BUFFER  (start shifts +32)
// 131856            END               (< 196608 = 3 pages ✓)

export const CHUNK_SIZE:       i32 = 65552;   // 65536 + 16 (PKCS7 max overhead)

export const KEY_OFFSET:       i32 = 0;
export const BLOCK_PT_OFFSET:  i32 = 32;
export const BLOCK_CT_OFFSET:  i32 = 48;
export const NONCE_OFFSET:     i32 = 64;
export const COUNTER_OFFSET:   i32 = 80;
export const SUBKEY_OFFSET:    i32 = 96;
export const CHUNK_PT_OFFSET:  i32 = 624;
export const CHUNK_CT_OFFSET:  i32 = 66176;   // 624 + 65552
export const WORK_OFFSET:      i32 = 131728;  // 66176 + 65552
export const CBC_IV_OFFSET:    i32 = 131748;  // 131728 + 20
// 12 bytes padding for 16-byte alignment (131748+16=131764, 131764+12=131776)
export const SIMD_WORK_OFFSET: i32 = 131776;  // 5 × v128 = 80 bytes
// END = 131856 < 196608 ✓

// ── Buffer offset getters ───────────────────────────────────────────────────

/** Returns the module identifier (always 0 for serpent). */
export function getModuleId():      i32 {
	return 0;
}
/** Returns the byte offset of KEY_BUFFER in WASM linear memory. */
export function getKeyOffset():     i32 {
	return KEY_OFFSET;
}
/** Returns the byte offset of BLOCK_PT_BUFFER in WASM linear memory. */
export function getBlockPtOffset(): i32 {
	return BLOCK_PT_OFFSET;
}
/** Returns the byte offset of BLOCK_CT_BUFFER in WASM linear memory. */
export function getBlockCtOffset(): i32 {
	return BLOCK_CT_OFFSET;
}
/** Returns the byte offset of NONCE_BUFFER (CTR mode) in WASM linear memory. */
export function getNonceOffset():   i32 {
	return NONCE_OFFSET;
}
/** Returns the byte offset of COUNTER_BUFFER (128-bit LE) in WASM linear memory. */
export function getCounterOffset(): i32 {
	return COUNTER_OFFSET;
}
/** Returns the byte offset of SUBKEY_BUFFER (33 × 4 round subkeys) in WASM linear memory. */
export function getSubkeyOffset():  i32 {
	return SUBKEY_OFFSET;
}
/** Returns the byte offset of CHUNK_PT_BUFFER in WASM linear memory. */
export function getChunkPtOffset(): i32 {
	return CHUNK_PT_OFFSET;
}
/** Returns the byte offset of CHUNK_CT_BUFFER in WASM linear memory. */
export function getChunkCtOffset(): i32 {
	return CHUNK_CT_OFFSET;
}
/** Returns the byte offset of WORK_BUFFER (5 × i32 working registers) in WASM linear memory. */
export function getWorkOffset():    i32 {
	return WORK_OFFSET;
}
/** Returns the byte offset of CBC_IV_BUFFER in WASM linear memory. */
export function getCbcIvOffset():   i32 {
	return CBC_IV_OFFSET;
}
/** Returns the byte offset of SIMD_WORK_BUFFER (5 × v128 registers) in WASM linear memory. */
export function getSimdWorkOffset(): i32 {
	return SIMD_WORK_OFFSET;
}
/** Returns the chunk buffer size in bytes (65536 + 16 for PKCS7 max overhead). */
export function getChunkSize():     i32 {
	return CHUNK_SIZE;
}
/** Returns the number of WASM memory pages currently allocated (each page is 64 KB). */
export function getMemoryPages():   i32 {
	return memory.size();
}
