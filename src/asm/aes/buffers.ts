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
// AES module, static buffer layout.
// Independent linear memory starting at offset 0.
//
// Supports AES-128/192/256 encrypt + decrypt; the round-count slot
// (NR_BUFFER) is written by `keyExpansion` and read by encrypt/decrypt at
// the top of each call.
//
// Total: 202688 bytes < 4 × 64KB = 262144 (59456 bytes spare). The 4-page
// budget covers the 64 KiB AAD_BUFFER for AES-GCM authenticated additional
// data plus 64 bytes of AES-GCM-SIV state (POLYVAL auth/enc keys + initial
// counter) after AAD.
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
//                                          uses 15 × 128 = 1920), forward
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
// 5568      65536     CHUNK_PT_BUFFER     (CTR/CBC stream input)
// 71104     65536     CHUNK_CT_BUFFER     (CTR/CBC stream output)
// 136640    1         NR_BUFFER           (u8, round count: 10/12/14, written
//                                          by keyExpansion, read by encrypt/
//                                          decrypt round loops)
// 136656    16        NONCE_BUFFER        (CTR initial counter value)
// 136672    16        COUNTER_BUFFER      (CTR working counter, 128-bit LE)
// 136688    16        CBC_IV_BUFFER       (CBC chaining block, IV on first
//                                          chunk, last ciphertext block on
//                                          subsequent chunks)
// 136704    16        H_BUFFER            (GCM hash subkey H = AES_ENC(K, 0^128),
//                                          derived once per loadKey)
// 136720    16        J0_BUFFER           (GCM pre-counter block, set per
//                                          seal/open call)
// 136736    16        GHASH_ACC_BUFFER    (GHASH running accumulator, evolved
//                                          across AAD and CT blocks)
// 136752    16        TAG_BUFFER          (computed-tag scratch on seal,
//                                          comparison target on open)
// 136768    16        J0E_BUFFER          (E(K, J0) pad, derived in gcmStart
//                                          and XORed with S to form the tag)
// 136784    16        GCM_LENS_BUFFER     (running GCM seal/open state:
//                                          bytes [0..7]  = AAD bit-length (u64 BE),
//                                          bytes [8..15] = PT/CT bit-length so far (u64 BE))
// 136800    16        GCM_SCRATCH_BUFFER  (zero-padded partial block scratch
//                                          for GHASH absorption tail; reused
//                                          between AAD-tail, CT-tail, lengths)
// 136816    16        GCM_CB_BUFFER       (GCTR working counter, high 96 bits
//                                          fixed from J0, low 32 bits 32-bit
//                                          BE incrementing per block)
// 136832    256       GF128_TABLE_BUFFER  (16 entries × 16 bytes, 4-bit
//                                          windowed multiply table, computed
//                                          from H once per loadKey)
// 137088    65536     AAD_BUFFER          (GCM additional authenticated data;
//                                          single-shot caller writes AAD here
//                                          before gcmStart)
// ── AES-GCM-SIV ────────────────────────────────────────────────────────
// 202624    16        POLYVAL_AUTH_KEY_BUFFER  (per-message authentication
//                                          key derived from KGK by
//                                          sivDeriveKeys, RFC 8452 §4)
// 202640    32        POLYVAL_ENC_KEY_BUFFER   (per-message encryption key
//                                          derived from KGK; sized for
//                                          AES-256, AES-128 uses bytes
//                                          [0..16] only)
// 202672    16        SIV_IC_BUFFER            (SIV initial counter, tag
//                                          with bit 7 of byte 15 set;
//                                          first 4 bytes hold the 32-bit
//                                          little-endian CTR counter)
// 202688              END                 (< 262144 = 4 pages ✓; 59456 spare)
//
// GHASH_ACC_BUFFER also serves as the POLYVAL accumulator during AES-GCM-SIV
// operations. GHASH and POLYVAL are mutually exclusive at runtime
// (atomic AEAD pattern); the alias is safe and saves 16 bytes of layout.
//
// Why bitsliced round keys are 128 bytes/round (not 16): per Käsper-Schwabe §4.5,
// each AES round key is pre-transposed to bitsliced form so that AddRoundKey is
// 8 plain v128 XORs. The 16 round-key bytes duplicate across the 8 "parallel
// blocks" (since all 8 blocks share one key schedule), then transpose, yielding
// 8 × v128 = 128 bytes per bitsliced round key.
//
// Why a dedicated KEY_SCHEDULE_SCRATCH_BUFFER: prior layout placed the byte-level
// scratch at ROUND_KEYS_OFFSET + 1408 (the gap above the AES-128 round keys).
// For AES-256 (15 × 128 = 1920 bytes of bitsliced round keys) that gap vanishes
// and the scratch collides with rounds 11-13. Carving out a dedicated 256-byte
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
// NR_BUFFER is u8 at 136640; pad to 16-byte boundary before mode-state buffers.
export const NONCE_OFFSET:                i32 = 136656;
export const COUNTER_OFFSET:              i32 = 136672;
export const CBC_IV_OFFSET:               i32 = 136688;
// ── GCM buffers ────────────────────────────────────────────────────────────
export const H_OFFSET:                    i32 = 136704;
export const J0_OFFSET:                   i32 = 136720;
export const GHASH_ACC_OFFSET:            i32 = 136736;
export const TAG_OFFSET:                  i32 = 136752;
export const J0E_OFFSET:                  i32 = 136768;
export const GCM_LENS_OFFSET:             i32 = 136784;
export const GCM_SCRATCH_OFFSET:          i32 = 136800;
export const GCM_CB_OFFSET:               i32 = 136816;
export const GF128_TABLE_OFFSET:          i32 = 136832;
export const AAD_OFFSET:                  i32 = 137088;
// ── AES-GCM-SIV buffers ────────────────────────────────────────────────────
// GHASH_ACC_OFFSET aliases as the POLYVAL accumulator (mutually exclusive
// at runtime, atomic AEAD pattern), so no new offset is added for it.
export const POLYVAL_AUTH_KEY_OFFSET:      i32 = 202624;
export const POLYVAL_ENC_KEY_OFFSET:       i32 = 202640;
export const SIV_IC_OFFSET:                i32 = 202672;
// END = 202672 + 16 = 202688 < 262144 = 4 pages ✓

// Sizes referenced from wipe.ts and aes.ts.
export const ROUND_KEYS_SIZE:           i32 = 1920;   // 15 round keys × 8 v128 (AES-256 future)
export const BITSLICED_STATE_SIZE:      i32 = 128;    // 8 v128 = state for 8 parallel blocks
export const CANRIGHT_SCRATCH_SIZE:     i32 = 1024;   // 64 v128 scratch slots
export const KEY_SCHEDULE_SCRATCH_SIZE: i32 = 256;    // 240 B used by AES-256, padded to 256
export const INV_ROUND_KEYS_SIZE:       i32 = 1920;   // parallel to ROUND_KEYS_SIZE
export const NR_SIZE:                   i32 = 1;      // u8, Nr ∈ {10, 12, 14}
export const NONCE_SIZE:                i32 = 16;     // CTR initial counter value
export const COUNTER_SIZE:              i32 = 16;     // CTR working counter (128-bit LE)
export const CBC_IV_SIZE:               i32 = 16;     // CBC chaining block
export const H_SIZE:                    i32 = 16;     // GCM hash subkey
export const J0_SIZE:                   i32 = 16;     // GCM pre-counter block
export const GHASH_ACC_SIZE:            i32 = 16;     // GHASH running accumulator
export const TAG_SIZE:                  i32 = 16;     // GCM authentication tag (always 128-bit)
export const J0E_SIZE:                  i32 = 16;     // E(K, J0) pad
export const GCM_LENS_SIZE:             i32 = 16;     // [aadBits 64BE | ptBits 64BE]
export const GCM_SCRATCH_SIZE:          i32 = 16;     // partial-block tail scratch
export const GCM_CB_SIZE:               i32 = 16;     // GCTR working counter
export const GF128_TABLE_SIZE:          i32 = 256;    // 16 entries × 16 bytes
export const AAD_BUFFER_SIZE:           i32 = 65536;  // 64 KiB max single-shot AAD
export const POLYVAL_AUTH_KEY_SIZE:     i32 = 16;     // RFC 8452 §4, 128-bit auth key
export const POLYVAL_ENC_KEY_SIZE:      i32 = 32;     // sized for AES-256 (AES-128 uses 16)
export const SIV_IC_SIZE:               i32 = 16;     // SIV initial counter

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
/** Returns the byte offset of NONCE_BUFFER (CTR initial counter, 16 bytes). */
export function getNonceOffset(): i32 {
	return NONCE_OFFSET;
}
/** Returns the byte offset of COUNTER_BUFFER (CTR working counter, 128-bit LE, 16 bytes). */
export function getCounterOffset(): i32 {
	return COUNTER_OFFSET;
}
/** Returns the byte offset of CBC_IV_BUFFER (CBC chaining block, 16 bytes). */
export function getCbcIvOffset(): i32 {
	return CBC_IV_OFFSET;
}
/** Returns the byte offset of H_BUFFER (GCM hash subkey, 16 bytes). */
export function getHOffset(): i32 {
	return H_OFFSET;
}
/** Returns the byte offset of J0_BUFFER (GCM pre-counter block, 16 bytes). */
export function getJ0Offset(): i32 {
	return J0_OFFSET;
}
/** Returns the byte offset of GHASH_ACC_BUFFER (running GHASH accumulator, 16 bytes). */
export function getGhashAccOffset(): i32 {
	return GHASH_ACC_OFFSET;
}
/** Returns the byte offset of TAG_BUFFER (GCM authentication tag, 16 bytes). */
export function getTagOffset(): i32 {
	return TAG_OFFSET;
}
/** Returns the byte offset of GF128_TABLE_BUFFER (4-bit windowed multiply table, 256 bytes). */
export function getGf128TableOffset(): i32 {
	return GF128_TABLE_OFFSET;
}
/** Returns the byte offset of AAD_BUFFER (GCM additional authenticated data, 65536 bytes). */
export function getAadOffset(): i32 {
	return AAD_OFFSET;
}
/** Returns the maximum AAD buffer size in bytes (65536). */
export function getAadBufferSize(): i32 {
	return AAD_BUFFER_SIZE;
}
/** Returns the byte offset of POLYVAL_AUTH_KEY_BUFFER (16 bytes; SIV per-message auth key). */
export function getPolyvalAuthKeyOffset(): i32 {
	return POLYVAL_AUTH_KEY_OFFSET;
}
/** Returns the byte offset of POLYVAL_ENC_KEY_BUFFER (32 bytes; SIV per-message encryption key). */
export function getPolyvalEncKeyOffset(): i32 {
	return POLYVAL_ENC_KEY_OFFSET;
}
/** Returns the byte offset of SIV_IC_BUFFER (16 bytes; SIV initial counter / scratch for provided tag). */
export function getSivIcOffset(): i32 {
	return SIV_IC_OFFSET;
}
/** Returns the chunk buffer size in bytes (65536). */
export function getChunkSize(): i32 {
	return CHUNK_SIZE;
}
/** Returns the number of WASM memory pages currently allocated (each page is 64 KB). */
export function getMemoryPages(): i32 {
	return memory.size();
}
