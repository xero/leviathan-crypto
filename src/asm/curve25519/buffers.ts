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
// 4 memory pages = 262144 bytes; the substrate's mutable buffer usage
// is far smaller (a few KB), pages were rounded up to match the blake3 /
// slhdsa precedent and leave headroom for the SHA-512, Ed25519, and
// X25519 scratch regions appended below.
//
// Field element = 40 bytes (5 × 8-byte i64 limbs, radix 2^51 per RFC 8032
// §5.1). Edwards point in extended coords (X:Y:Z:T) = 160 bytes. Scalar
// = 32 bytes LE.
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
//   BUFFER_END = 7836 (< 65536 = 1 page; module sized at 4 pages)
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

// ── Embedded SHA-512 + Ed25519 scratch ─────────────────────────────────────

// SHA-512 buffer offsets (verbatim names from sha2/buffers.ts)
export const SHA512_H_OFFSET:       i32 = 5936
export const SHA512_BLOCK_OFFSET:   i32 = 6000   // 5936 + 64
export const SHA512_W_OFFSET:       i32 = 6128   // 6000 + 128
export const SHA512_OUT_OFFSET:     i32 = 6768   // 6128 + 640
export const SHA512_INPUT_OFFSET:   i32 = 6832   // 6768 + 64
export const SHA512_PARTIAL_OFFSET: i32 = 6960   // 6832 + 128
export const SHA512_TOTAL_OFFSET:   i32 = 6964   // 6960 + 4

// Ed25519 scratch buffers. Persistent across substrate calls.
export const ED25519_SCALAR_A:      i32 = 6972   // 32 bytes (clamped scalar a)
export const ED25519_PREFIX:        i32 = 7004   // 32 bytes (h[32..64])
export const ED25519_R_SCALAR:      i32 = 7036   // 32 bytes (r mod L)
export const ED25519_K_SCALAR:      i32 = 7068   // 32 bytes (k mod L)
export const ED25519_PK_CHECK:      i32 = 7100   // 32 bytes (derived pk for compare)
export const ED25519_POINT_A:       i32 = 7132   // 160 bytes (A = [a]B / decompressed pk)
export const ED25519_POINT_R:       i32 = 7292   // 160 bytes (R_point = [r]B / decompressed R)
export const ED25519_POINT_TMP1:    i32 = 7452   // 160 bytes
export const ED25519_POINT_TMP2:    i32 = 7612   // 160 bytes

// ── X25519 high-level scratch ──────────────────────────────────────────────

export const X25519_SCALAR_CLAMP:   i32 = 7772   // 32 bytes (clamped scalar)
export const BASEPOINT_U:           i32 = 7804   // 32 bytes (basepoint u-coord, RFC 7748 §4.1)

/**
 * End of the curve25519 module buffer region (exclusive upper bound).
 * Used by `wipeBuffers()` in `index.ts` to clear mutable state without
 * touching the AS data segment.
 */
export const BUFFER_END:           i32 = 7836

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

// ── Ed25519ph dom2 ASCII prefix (RFC 8032 §5.1) ────────────────────────────

// ── Curve25519 basepoint u-coordinate (RFC 7748 §4.1) ──────────────────────

@inline
export function loadBasepointU(dst: i32): void {
	store<u64>(dst +  0, 9)   // byte 0 = 0x09, bytes 1..7 = 0
	store<u64>(dst +  8, 0)
	store<u64>(dst + 16, 0)
	store<u64>(dst + 24, 0)
}

@inline
export function loadDom2Prefix(dst: i32): void {
	store<u8>(dst +  0, 0x53)  // 'S'
	store<u8>(dst +  1, 0x69)  // 'i'
	store<u8>(dst +  2, 0x67)  // 'g'
	store<u8>(dst +  3, 0x45)  // 'E'
	store<u8>(dst +  4, 0x64)  // 'd'
	store<u8>(dst +  5, 0x32)  // '2'
	store<u8>(dst +  6, 0x35)  // '5'
	store<u8>(dst +  7, 0x35)  // '5'
	store<u8>(dst +  8, 0x31)  // '1'
	store<u8>(dst +  9, 0x39)  // '9'
	store<u8>(dst + 10, 0x20)  // ' '
	store<u8>(dst + 11, 0x6E)  // 'n'
	store<u8>(dst + 12, 0x6F)  // 'o'
	store<u8>(dst + 13, 0x20)  // ' '
	store<u8>(dst + 14, 0x45)  // 'E'
	store<u8>(dst + 15, 0x64)  // 'd'
	store<u8>(dst + 16, 0x32)  // '2'
	store<u8>(dst + 17, 0x35)  // '5'
	store<u8>(dst + 18, 0x35)  // '5'
	store<u8>(dst + 19, 0x31)  // '1'
	store<u8>(dst + 20, 0x39)  // '9'
	store<u8>(dst + 21, 0x20)  // ' '
	store<u8>(dst + 22, 0x63)  // 'c'
	store<u8>(dst + 23, 0x6F)  // 'o'
	store<u8>(dst + 24, 0x6C)  // 'l'
	store<u8>(dst + 25, 0x6C)  // 'l'
	store<u8>(dst + 26, 0x69)  // 'i'
	store<u8>(dst + 27, 0x73)  // 's'
	store<u8>(dst + 28, 0x69)  // 'i'
	store<u8>(dst + 29, 0x6F)  // 'o'
	store<u8>(dst + 30, 0x6E)  // 'n'
	store<u8>(dst + 31, 0x73)  // 's'
}
