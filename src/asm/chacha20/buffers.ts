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
// src/asm/chacha/buffers.ts
//
// ChaCha20 module — static buffer layout.
// Independent linear memory starting at offset 0.
//
// Total: 131824 bytes < 3 × 64KB = 196608 (64784 bytes spare).
//
// Offset   Size     Name
// 0        32       KEY_BUFFER (ChaCha20 256-bit key)
// 32       12       CHACHA_NONCE_BUFFER (96-bit nonce, 3 × u32, LE)
// 44       4        CHACHA_CTR_BUFFER (u32 block counter)
// 48       64       CHACHA_BLOCK_BUFFER (64-byte keystream block output)
// 112      64       CHACHA_STATE_BUFFER (16 × u32 initial state)
// 176      65536    CHUNK_PT_BUFFER (streaming plaintext)
// 65712    65536    CHUNK_CT_BUFFER (streaming ciphertext)
// 131248   32       POLY_KEY_BUFFER (one-time key r||s)
// 131280   64       POLY_MSG_BUFFER (message staging, ≤ 64 bytes per polyUpdate)
// 131344   16       POLY_BUF_BUFFER (partial block accumulator)
// 131360   4        POLY_BUF_LEN_BUFFER (u32 bytes in partial block)
// 131364   16       POLY_TAG_BUFFER (16-byte output MAC tag)
// 131380   40       POLY_H_BUFFER (accumulator h: 5 × u64)
// 131420   40       POLY_R_BUFFER (clamped r: 5 × u64)
// 131460   32       POLY_RS_BUFFER (precomputed 5×r[1..4]: 4 × u64)
// 131492   16       POLY_S_BUFFER (s pad: 4 × u32)
// 131508   24       XCHACHA_NONCE_BUFFER (full 24-byte XChaCha20 nonce)
// 131532   32       XCHACHA_SUBKEY_BUFFER (HChaCha20 output, key material)
// 131564   4        (padding for 16-byte SIMD alignment)
// 131568   256      CHACHA_SIMD_WORK_BUFFER (4-wide inter-block keystream: 4 × 64 bytes)
// 131824            END (< 196608 = 3 × 64KB ✓)

export const CHUNK_SIZE:           i32 = 65536;

export const KEY_OFFSET:           i32 = 0;
export const CHACHA_NONCE_OFFSET:  i32 = 32;
export const CHACHA_CTR_OFFSET:    i32 = 44;
export const CHACHA_BLOCK_OFFSET:  i32 = 48;
export const CHACHA_STATE_OFFSET:  i32 = 112;
export const CHUNK_PT_OFFSET:      i32 = 176;
export const CHUNK_CT_OFFSET:      i32 = 65712;
export const POLY_KEY_OFFSET:      i32 = 131248;
export const POLY_MSG_OFFSET:      i32 = 131280;
export const POLY_BUF_OFFSET:      i32 = 131344;
export const POLY_BUF_LEN_OFFSET:  i32 = 131360;
export const POLY_TAG_OFFSET:      i32 = 131364;
export const POLY_H_OFFSET:        i32 = 131380;
export const POLY_R_OFFSET:        i32 = 131420;
export const POLY_RS_OFFSET:       i32 = 131460;
export const POLY_S_OFFSET:        i32 = 131492;
export const XCHACHA_NONCE_OFFSET:      i32 = 131508;
export const XCHACHA_SUBKEY_OFFSET:     i32 = 131532;
// 4 bytes padding for 16-byte SIMD alignment (131564 % 16 = 12 → +4)
export const CHACHA_SIMD_WORK_OFFSET:   i32 = 131568;  // 16 × v128 = 256 bytes
// END = 131824 < 196608 ✓

export function getModuleId():           i32 {
	return 1;
}
export function getKeyOffset():          i32 {
	return KEY_OFFSET;
}
export function getChachaNonceOffset():  i32 {
	return CHACHA_NONCE_OFFSET;
}
export function getChachaCtrOffset():    i32 {
	return CHACHA_CTR_OFFSET;
}
export function getChachaBlockOffset():  i32 {
	return CHACHA_BLOCK_OFFSET;
}
export function getChachaStateOffset():  i32 {
	return CHACHA_STATE_OFFSET;
}
export function getChunkPtOffset():      i32 {
	return CHUNK_PT_OFFSET;
}
export function getChunkCtOffset():      i32 {
	return CHUNK_CT_OFFSET;
}
export function getChunkSize():          i32 {
	return CHUNK_SIZE;
}
export function getPolyKeyOffset():      i32 {
	return POLY_KEY_OFFSET;
}
export function getPolyMsgOffset():      i32 {
	return POLY_MSG_OFFSET;
}
export function getPolyBufOffset():      i32 {
	return POLY_BUF_OFFSET;
}
export function getPolyBufLenOffset():   i32 {
	return POLY_BUF_LEN_OFFSET;
}
export function getPolyTagOffset():      i32 {
	return POLY_TAG_OFFSET;
}
export function getPolyHOffset():        i32 {
	return POLY_H_OFFSET;
}
export function getPolyROffset():        i32 {
	return POLY_R_OFFSET;
}
export function getPolyRsOffset():       i32 {
	return POLY_RS_OFFSET;
}
export function getPolySOffset():        i32 {
	return POLY_S_OFFSET;
}
export function getXChaChaNonceOffset():   i32 {
	return XCHACHA_NONCE_OFFSET;
}
export function getXChaChaSubkeyOffset():  i32 {
	return XCHACHA_SUBKEY_OFFSET;
}
export function getChachaSimdWorkOffset(): i32 {
	return CHACHA_SIMD_WORK_OFFSET;
}
export function getMemoryPages():          i32 {
	return memory.size();
}
