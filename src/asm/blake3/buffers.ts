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
// src/asm/blake3/buffers.ts
//
// BLAKE3 module, static linear-memory buffer layout.
// Independent linear memory starting at offset 0 (no shared memory with
// other modules per repo §Architecture Constraints).
//
// Layout sized for the entire phase, not just compress: INPUT staging for
// 4-way compress4 batching, OUTPUT staging for XOF reads, the working
// compression slots (CV / MSG / counter / block_len / flags), key slots
// for KEYED_HASH and DERIVE_KEY modes, the §2.5 tree-mode queue-per-level
// region (LEVEL_QUEUES / LEVEL_COUNTS) sized for the BLAKE3 §5.1.2
// 54-level depth bound, compress4 staging for the v128-external SIMD
// kernel, chunk-state slots for the §2.4 chunk machine, and the §2.6
// root-compress snapshot for XOF squeezes.
//
// The AS runtime places SIGMA tables and other StaticArray<i32> in the
// data segment at low memory. The first 4096 bytes are reserved for that
// data segment so `wipeBuffers()` will not clobber it. Mutable buffers
// start at MUTABLE_START.
//
// Region map (byte offsets, sizes in bytes):
//
//   Offset    Size     Region
//   0         4096     (reserved for AS data segment / SIGMA tables)
//   4096      4096     INPUT_STAGING    (4 chunks × 1024 bytes, kept vestigial)
//   8192      1024     OUTPUT_STAGING   (XOF reader, 16 root compressions)
//   9216        32     CV               (working 8-word chaining value)
//   9248        64     MSG              (16-word message block input)
//   9312         8     COUNTER          (u64 chunk index, lo at +0 hi at +4)
//   9320         4     BLOCK_LEN        (u32 bytes in current block)
//   9324         4     FLAGS            (u32 domain-separation bitfield)
//   9328        64     COMPRESS_OUT     (full 64-byte output; first 32 = next CV)
//   9392        32     KEYED_KEY        (KEYED_HASH 32-byte key, §2.3)
//   9424        32     DERIVE_CV        (DERIVE_KEY context CV stage, §2.3)
//   9456     15552     LEVEL_QUEUES     (54 × 9 × 32, §2.5 queue-per-level)
//   25008      216     LEVEL_COUNTS     (54 × 4, one i32 count per level)
//   25224      128     COMPRESS4_CV_IN  (4 × 32)
//   25352      256     COMPRESS4_MSG_IN (4 × 64)
//   25608       32     COMPRESS4_CTR_IN (4 × 8)
//   25640      256     COMPRESS4_OUT    (4 × 64)
//   25896       16     COMPRESS4_BLEN_IN  (4 × 4, BLAKE3 §2.2 b)
//   25912        4     COMPRESS4_FLAGS_IN (1 × 4, shared across lanes)
//   25916       32     MODE_CV          (chunkInit start CV / parent compress key)
//   25948        8     CHUNK_INDEX      (u64 §2.4 chunk counter)
//   25956        4     CHUNK_BLOCKS     (i32 blocks compressed in current chunk)
//   25960        4     CHUNK_PENDING_LEN (i32 1-block lookahead length)
//   25964       64     CHUNK_PENDING_BLOCK (1-block lookahead buffer)
//   26028       64     TREE_PARENT_BLOCK (left || right concat for parent compress)
//   26092       32     CHUNK_CV_SCRATCH (32-byte chunk CV between finalize / push)
//   26124       64     ROOT_OUT_SCRATCH (64-byte root compress output staging)
//   26188        4     MODE_FLAGS       (mode-flag bits OR'd onto every compress, §2.3)
//   26192       32     CONTEXT_CV       (derive_key pass-1 output CV, §2.3)
//   26224       32     ROOT_STATE_CV    (XOF: snapshot of root-compress input CV)
//   26256       64     ROOT_STATE_MSG   (XOF: snapshot of root-compress message block)
//   26320        4     ROOT_STATE_BLEN  (XOF: snapshot of root-compress block_len)
//   26324        4     ROOT_STATE_FLAGS (XOF: snapshot of root-compress flag bits)
//   BUFFER_END = 26328 (< 65536 = 1 page; module sized at 2 pages for slack)
//
// Each level L holds a small queue of pending CVs at offset
// `LEVEL_QUEUES_OFFSET + L * LEVEL_QUEUE_STRIDE` (stride 288 = 9 × 32);
// pending count is i32 at `LEVEL_COUNTS_OFFSET + L * 4`. 9-entry width
// covers the transient peak of 8 (BLAKE3 §2.5); 54 levels is the §5.1.2
// depth bound for the maximum 2^64-byte input.
//
// ROOT_STATE_* captures the root-compress input the moment before the root
// compress fires (single-chunk §2.4 path in chunkFinalize, multi-chunk
// §2.5 path in treeFinalizeRoot). Subsequent §2.6 XOF squeezes re-fire
// the root compress from this snapshot with an incremented counter, which
// is the contract `squeezeXofBlock` (index.ts) exposes to the TS layer.

// ── Reserved region for AS data segment ─────────────────────────────────────

export const MUTABLE_START:           i32 = 4096

// ── Region offsets ──────────────────────────────────────────────────────────

export const INPUT_STAGING_OFFSET:    i32 = 4096
export const INPUT_STAGING_SIZE:      i32 = 4096

export const OUTPUT_STAGING_OFFSET:   i32 = 8192
export const OUTPUT_STAGING_SIZE:     i32 = 1024

export const CV_OFFSET:               i32 = 9216
export const MSG_OFFSET:              i32 = 9248
export const COUNTER_OFFSET:          i32 = 9312
export const BLOCK_LEN_OFFSET:        i32 = 9320
export const FLAGS_OFFSET:            i32 = 9324
export const COMPRESS_OUT_OFFSET:     i32 = 9328

export const KEYED_KEY_OFFSET:        i32 = 9392
export const DERIVE_CV_OFFSET:        i32 = 9424

// ── §2.5 tree-mode queue-per-level region ──────────────────────────────────
//
// Each of the 54 BLAKE3 §5.1.2 levels gets a queue of up to 9 32-byte CVs
// at LEVEL_QUEUES_OFFSET + L * LEVEL_QUEUE_STRIDE, with the i32 count at
// LEVEL_COUNTS_OFFSET + L * 4. The 9-entry width covers the transient
// peak of 8 entries (post-push 4 plus 4 finalize-time emissions, see
// tree.ts) plus 1 slot of headroom for alignment and future tightening.

export const MAX_LEVEL:               i32 = 54
export const LEVEL_QUEUE_ENTRIES:     i32 = 9
export const LEVEL_QUEUE_STRIDE:      i32 = 288  // 9 × 32 bytes

export const LEVEL_QUEUES_OFFSET:     i32 = 9456
export const LEVEL_QUEUES_SIZE:       i32 = 15552  // 54 × 288
export const LEVEL_COUNTS_OFFSET:     i32 = 25008
export const LEVEL_COUNTS_SIZE:       i32 = 216    // 54 × 4

export const COMPRESS4_CV_IN_OFFSET:  i32 = 25224
export const COMPRESS4_MSG_IN_OFFSET: i32 = 25352
export const COMPRESS4_CTR_IN_OFFSET: i32 = 25608
export const COMPRESS4_OUT_OFFSET:    i32 = 25640

export const COMPRESS4_BLEN_IN_OFFSET:  i32 = 25896
export const COMPRESS4_FLAGS_IN_OFFSET: i32 = 25912

export const MODE_CV_OFFSET:               i32 = 25916
export const CHUNK_INDEX_OFFSET:           i32 = 25948
export const CHUNK_BLOCKS_OFFSET:          i32 = 25956
export const CHUNK_PENDING_LEN_OFFSET:     i32 = 25960
export const CHUNK_PENDING_BLOCK_OFFSET:   i32 = 25964

export const TREE_PARENT_BLOCK_OFFSET:     i32 = 26028

export const CHUNK_CV_SCRATCH_OFFSET:      i32 = 26092
export const ROOT_OUT_SCRATCH_OFFSET:      i32 = 26124

// Mode-flag bits OR'd onto every compress for the current invocation
// (BLAKE3 §2.3 KEYED_HASH, DERIVE_KEY_CONTEXT / DERIVE_KEY_MATERIAL).
// Hash mode leaves this zero. Set by the top-level entry points before
// any chunk / tree work; read at every compress site.
export const MODE_FLAGS_OFFSET:            i32 = 26188

// derive_key pass-1 output CV (BLAKE3 §2.3). Pass 1 hashes the context
// string with DERIVE_KEY_CONTEXT and writes 32 bytes here; pass 2 reads
// this slot as its starting CV. Wiped after pass 2 in addition to the
// dispose-time wipeBuffers() sweep.
export const CONTEXT_CV_OFFSET:            i32 = 26192

// Root-compress input snapshot (BLAKE3 §2.6 XOF). chunkFinalize (single
// chunk, §2.4) and treeFinalizeRoot (multi-chunk, §2.5) write CV / MSG
// / BLEN / FLAGS here immediately before the root compress fires. The
// `squeezeXofBlock` export re-fires the root compress from this snapshot
// with an incremented counter so the TS layer can squeeze arbitrary
// 64-byte XOF blocks past the first one.
export const ROOT_STATE_CV_OFFSET:         i32 = 26224
export const ROOT_STATE_MSG_OFFSET:        i32 = 26256
export const ROOT_STATE_BLEN_OFFSET:       i32 = 26320
export const ROOT_STATE_FLAGS_OFFSET:      i32 = 26324

/**
 * End of the BLAKE3 module buffer region (exclusive upper bound).
 * Used by `wipeBuffers()` in `index.ts` to clear mutable state without
 * touching the AS data segment that holds the SIGMA permutation table.
 */
export const BUFFER_END:              i32 = 26328

// ── Module identity ─────────────────────────────────────────────────────────

export function getModuleId():    i32 { return 4             }
export function getMemoryPages(): i32 { return memory.size() }

// ── Offset getter functions ─────────────────────────────────────────────────

export function getInputStagingOffset():     i32 { return INPUT_STAGING_OFFSET      }
export function getOutputStagingOffset():    i32 { return OUTPUT_STAGING_OFFSET     }
export function getCvOffset():               i32 { return CV_OFFSET                 }
export function getMsgOffset():              i32 { return MSG_OFFSET                }
export function getCounterOffset():          i32 { return COUNTER_OFFSET            }
export function getBlockLenOffset():         i32 { return BLOCK_LEN_OFFSET          }
export function getFlagsOffset():            i32 { return FLAGS_OFFSET              }
export function getCompressOutOffset():      i32 { return COMPRESS_OUT_OFFSET       }
export function getKeyedKeyOffset():         i32 { return KEYED_KEY_OFFSET          }
export function getDeriveCvOffset():         i32 { return DERIVE_CV_OFFSET          }
export function getCompress4CvInOffset():    i32 { return COMPRESS4_CV_IN_OFFSET    }
export function getCompress4MsgInOffset():   i32 { return COMPRESS4_MSG_IN_OFFSET   }
export function getCompress4CtrInOffset():   i32 { return COMPRESS4_CTR_IN_OFFSET   }
export function getCompress4OutOffset():     i32 { return COMPRESS4_OUT_OFFSET      }
export function getCompress4BlenInOffset():  i32 { return COMPRESS4_BLEN_IN_OFFSET  }
export function getCompress4FlagsInOffset(): i32 { return COMPRESS4_FLAGS_IN_OFFSET }
export function getModeCvOffset():           i32 { return MODE_CV_OFFSET            }
