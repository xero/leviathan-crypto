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
// src/asm/curve25519/buffers.ts
//
// curve25519 module, static linear-memory buffer layout.
// Independent linear memory starting at offset 0 (no shared memory with
// other modules per repo §Architecture Constraints).
//
// Module 8 in the AsmModule registry (after blake3); 11th WASM binary.
// 2 memory pages = 131072 bytes; the substrate's mutable buffer usage
// is far smaller (a few KB), pages were rounded up to match the blake3 /
// slhdsa precedent and leave headroom for TASK-C / TASK-D additions.
//
// Field element = 40 bytes (5 × 8-byte i64 limbs, radix 2^51 per RFC 8032
// §5.1 + TASK-B field-representation lock). Edwards point in extended
// coords (X:Y:Z:T) = 160 bytes. Scalar = 32 bytes LE.
//
// Region map (byte offsets, sizes in bytes):
//
//   Offset    Size     Region
//   0         4096     (reserved for AS data segment)
//   4096      640      FIELD_TMP        (16 × 40, scratch field elements
//                                       for compress/decompress, scalar
//                                       reductions, and field-level
//                                       intermediates)
//   4736      640      POINT_TMP        (4 × 160, scratch Edwards points
//                                       for edPointMul loop state R, Q,
//                                       and one-shot helpers)
//   5376      480      LADDER_TMP       (12 × 40, X25519 Montgomery
//                                       ladder state x2, z2, x3, z3 plus
//                                       step temporaries a, aa, b, bb, e,
//                                       c, d, da+cb)
//   BUFFER_END = 5856 (< 65536 = 1 page; module sized at 2 pages)
//
// Constants (basepoint B, curve constants d, 2d, a24 = 121665, curve
// order L) are NOT stored in mutable linear memory; they live as
// `@inline const` u64 limb values in `field.ts` / `montgomery.ts` /
// `scalar.ts` and are materialized into caller-provided offsets via
// loader helpers (e.g. `edPointBasepoint(out)` writes the 160 bytes of
// the basepoint into the caller's `out` slot).
//
// Per AGENTS.md "Wipe discipline", `wipeBuffers()` in index.ts zeros
// every byte from MUTABLE_START to BUFFER_END after each public-API
// operation finalises; secret scalar limbs and intermediate point
// coordinates do not persist.

// ── Reserved region for AS data segment ─────────────────────────────────────

export const MUTABLE_START:        i32 = 4096

// ── Region offsets ──────────────────────────────────────────────────────────

// Scratch field elements (40 bytes each, 16 slots). Used by:
//  - compress.ts: u, v, sqrt candidate, x sign, on-curve check
//  - scalar.ts: reduce64 intermediate widening
//  - field.ts: feInv intermediate squarings
export const FIELD_TMP_OFFSET:     i32 = 4096
export const FIELD_TMP_SIZE:       i32 = 640
export const FIELD_TMP_STRIDE:     i32 = 40

// Scratch Edwards points (160 bytes each, 4 slots). Used by:
//  - edwards.ts edPointMul / edPointMulBase: R (accumulator), Q (R+P)
//    held across the 255-iteration loop; 2 additional slots for the
//    constant-time conditional-select staging
//  - compress.ts: decompression intermediate point
export const POINT_TMP_OFFSET:     i32 = 4736
export const POINT_TMP_SIZE:       i32 = 640
export const POINT_TMP_STRIDE:     i32 = 160

// Scratch field elements for the Montgomery ladder (40 bytes × 12 slots).
// Per RFC 7748 §5 the ladder maintains two projective points (x2:z2),
// (x3:z3); the ladder-step requires a handful of additional temporaries
// (a, aa, b, bb, e, c, d, da, cb). Held separately from FIELD_TMP so
// X25519 and Edwards substrates can run sequentially without aliasing.
export const LADDER_TMP_OFFSET:    i32 = 5376
export const LADDER_TMP_SIZE:      i32 = 480
export const LADDER_TMP_STRIDE:    i32 = 40

// Column accumulators for radix-2^51 multiplication, 5 × (u64 lo, u64 hi).
// Each output limb of feMul / feSqr collects up to 5 cross products of
// up-to-2^57-bit values, requiring 128-bit accumulation. AssemblyScript
// lacks a native u128 type; this region is the back-store for the
// (lo, hi) pair per output column. Sized 80 bytes (5 × 16) and reused
// per call: the field-arithmetic functions clear it on entry.
export const ACC_OFFSET:           i32 = 5856
export const ACC_SIZE:             i32 = 80

/**
 * End of the curve25519 module buffer region (exclusive upper bound).
 * Used by `wipeBuffers()` in `index.ts` to clear mutable state without
 * touching the AS data segment.
 */
export const BUFFER_END:           i32 = 5936

// ── Module identity ─────────────────────────────────────────────────────────

// Module ID 8: ct=0, serpent=0, chacha20=1, aes=1, sha2=2, sha3=3,
// blake3=4, kyber=5, mldsa=6, slhdsa=7. (The cipher modules collide on
// the low IDs; the values are informational, not used as a unique key.)
export function getModuleId():           i32 { return 8                  }
export function getMemoryPages():        i32 { return memory.size()      }

// ── Offset getter functions ─────────────────────────────────────────────────

export function getFieldTmpOffset():     i32 { return FIELD_TMP_OFFSET   }
export function getFieldTmpStride():     i32 { return FIELD_TMP_STRIDE   }
export function getPointTmpOffset():     i32 { return POINT_TMP_OFFSET   }
export function getPointTmpStride():     i32 { return POINT_TMP_STRIDE   }
export function getLadderTmpOffset():    i32 { return LADDER_TMP_OFFSET  }
export function getLadderTmpStride():    i32 { return LADDER_TMP_STRIDE  }
