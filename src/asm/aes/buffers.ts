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
// src/asm/aes/buffers.ts
//
// AES module — static buffer layout.
// Independent linear memory starting at offset 0.
//
// Supports AES-128/192/256 encrypt + decrypt; the round-count slot
// (NR_BUFFER) is written by `keyExpansion` and read by encrypt/decrypt at
// the top of each call.
//
// Total: 136641 bytes < 3 × 64KB = 196608 (59967 bytes spare).
//
// Offset    Size      Name
// 0         32        KEY_BUFFER (sized for AES-256)
// 32        16        BLOCK_PT_BUFFER  (atomic 1-block input)
// 48        16        BLOCK_CT_BUFFER  (atomic 1-block output)
// 64        128       BLOCK_PT_8X_BUFFER  (8 parallel plaintext blocks)
// 192       128       BLOCK_CT_8X_BUFFER  (8 parallel ciphertext blocks)
// 320       1920      ROUND_KEYS_BUFFER   (15 × 8 × 16, bitsliced; AES-128
//                                          uses 11 × 128 = 1408, AES-192
//                                          uses 13 × 128 = 1664, AES-256
//                                          uses 15 × 128 = 1920) — forward
//                                          (encrypt) round keys.
// 2240      128       BITSLICED_STATE_BUFFER  (8 × v128 = AES state in K-S layout)
// 2368      1024      CANRIGHT_SCRATCH_BUFFER (≈64 v128 scratch slots for the
//                                              tower-field S-box)
// 3392      256       KEY_SCHEDULE_SCRATCH_BUFFER  (byte-level round-key scratch
//                                              during keyExpansion; sized for
//                                              AES-256: 15 × 16 = 240, padded
//                                              to 256 for v128 alignment)
// 3648      1920      INV_ROUND_KEYS_BUFFER  (15 × 8 × 16, EqInvCipher form for
//                                              decrypt; rounds 0 and Nr are
//                                              copies of forward keys, rounds
//                                              1..Nr-1 are InvMixColumns(K[r]))
// 5568      65536     CHUNK_PT_BUFFER     (CTR/GCM stream input — phase 3+)
// 71104     65536     CHUNK_CT_BUFFER     (CTR/GCM stream output — phase 3+)
// 136640    1         NR_BUFFER           (u8 — round count: 10/12/14, written
//                                          by keyExpansion, read by encrypt/
//                                          decrypt round loops)
// 136641              END                 (< 196608 = 3 pages ✓)
//
// Why bitsliced round keys are 128 bytes/round (not 16): per Käsper-Schwabe §4.5,
// each AES round key is pre-transposed to bitsliced form so that AddRoundKey is
// 8 plain v128 XORs. The 16 round-key bytes duplicate across the 8 "parallel
// blocks" (since all 8 blocks share one key schedule), then transpose — yielding
// 8 × v128 = 128 bytes per bitsliced round key.
//
// Why a dedicated KEY_SCHEDULE_SCRATCH_BUFFER: prior layout placed the byte-level
// scratch at ROUND_KEYS_OFFSET + 1408 (the gap above the AES-128 round keys).
// For AES-256 (15 × 128 = 1920 bytes of bitsliced round keys) that gap vanishes
// and the scratch collides with rounds 11–13. Carving out a dedicated 256-byte
// region eliminates the collision and keeps the round-key buffer purely about
// round keys.
//
// Why a parallel INV_ROUND_KEYS_BUFFER: FIPS 197 §5.3.5 Equivalent Inverse
// Cipher requires round keys 1..Nr-1 to be InvMixColumns-transformed for
// decrypt, while encrypt needs the untransformed forward round keys. Storing
// both sets in parallel buffers means a single AES instance supports both
// directions without per-call key-schedule work; total cost is one
// InvMixColumns per round key, paid once at loadKey() time.

export const CHUNK_SIZE: i32 = 65536;

export const KEY_OFFSET:                  i32 = 0;
export const BLOCK_PT_OFFSET:             i32 = 32;
export const BLOCK_CT_OFFSET:             i32 = 48;
export const BLOCK_PT_8X_OFFSET:          i32 = 64;
export const BLOCK_CT_8X_OFFSET:          i32 = 192;
export const ROUND_KEYS_OFFSET:           i32 = 320;
export const BITSLICED_STATE_OFFSET:      i32 = 2240;
export const CANRIGHT_SCRATCH_OFFSET:     i32 = 2368;
export const KEY_SCHEDULE_SCRATCH_OFFSET: i32 = 3392;
export const INV_ROUND_KEYS_OFFSET:       i32 = 3648;
export const CHUNK_PT_OFFSET:             i32 = 5568;
export const CHUNK_CT_OFFSET:             i32 = 71104;
export const NR_OFFSET:                   i32 = 136640;
// END = 136641 < 196608 ✓

// Sizes referenced from wipe.ts and aes.ts.
export const ROUND_KEYS_SIZE:           i32 = 1920;   // 15 round keys × 8 v128 (AES-256 future)
export const BITSLICED_STATE_SIZE:      i32 = 128;    // 8 v128 = state for 8 parallel blocks
export const CANRIGHT_SCRATCH_SIZE:     i32 = 1024;   // 64 v128 scratch slots
export const KEY_SCHEDULE_SCRATCH_SIZE: i32 = 256;    // 240 B used by AES-256, padded to 256
export const INV_ROUND_KEYS_SIZE:       i32 = 1920;   // parallel to ROUND_KEYS_SIZE
export const NR_SIZE:                   i32 = 1;      // u8 — Nr ∈ {10, 12, 14}

// ── Buffer offset getters ───────────────────────────────────────────────────

/** Returns the module identifier (1 for AES; 0 = serpent). */
export function getModuleId(): i32 {
	return 1;
}
/** Returns the byte offset of KEY_BUFFER in WASM linear memory. */
export function getKeyOffset(): i32 {
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
/** Returns the byte offset of BLOCK_PT_8X_BUFFER (8 parallel input blocks). */
export function getBlockPt8xOffset(): i32 {
	return BLOCK_PT_8X_OFFSET;
}
/** Returns the byte offset of BLOCK_CT_8X_BUFFER (8 parallel output blocks). */
export function getBlockCt8xOffset(): i32 {
	return BLOCK_CT_8X_OFFSET;
}
/** Returns the byte offset of ROUND_KEYS_BUFFER (bitsliced round keys). */
export function getRoundKeysOffset(): i32 {
	return ROUND_KEYS_OFFSET;
}
/** Returns the byte offset of BITSLICED_STATE_BUFFER (8 × v128 AES state). */
export function getBitslicedStateOffset(): i32 {
	return BITSLICED_STATE_OFFSET;
}
/** Returns the byte offset of CANRIGHT_SCRATCH_BUFFER (S-box scratch v128 slots). */
export function getCanrightScratchOffset(): i32 {
	return CANRIGHT_SCRATCH_OFFSET;
}
/** Returns the byte offset of KEY_SCHEDULE_SCRATCH_BUFFER (byte-level keyExpansion scratch). */
export function getKeyScheduleScratchOffset(): i32 {
	return KEY_SCHEDULE_SCRATCH_OFFSET;
}
/** Returns the byte offset of INV_ROUND_KEYS_BUFFER (EqInvCipher decrypt round keys). */
export function getInvRoundKeysOffset(): i32 {
	return INV_ROUND_KEYS_OFFSET;
}
/** Returns the byte offset of CHUNK_PT_BUFFER in WASM linear memory. */
export function getChunkPtOffset(): i32 {
	return CHUNK_PT_OFFSET;
}
/** Returns the byte offset of CHUNK_CT_BUFFER in WASM linear memory. */
export function getChunkCtOffset(): i32 {
	return CHUNK_CT_OFFSET;
}
/** Returns the byte offset of NR_BUFFER (u8 round count: 10/12/14). */
export function getNrOffset(): i32 {
	return NR_OFFSET;
}
/** Returns the chunk buffer size in bytes (65536). */
export function getChunkSize(): i32 {
	return CHUNK_SIZE;
}
/** Returns the number of WASM memory pages currently allocated (each page is 64 KB). */
export function getMemoryPages(): i32 {
	return memory.size();
}
