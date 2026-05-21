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
//                           ▀█████▀▀▀
//
// src/asm/p256/buffers.ts
//
// p256 module, static linear-memory buffer layout.
// Independent linear memory starting at offset 0 (no shared memory with
// other modules per repo §Architecture Constraints).
//
// Module 9 in the AsmModule registry (after curve25519); 12th WASM
// binary. 3 memory pages = 196608 bytes; the substrate's mutable
// buffer usage is far smaller (~6 KB), pages sized for headroom and
// matching the per-call I/O staging idiom.
//
// Multiplication intermediate: 16 × u32 limbs (64 bytes). feMul writes
// an 8×8 schoolbook sum into MUL_INT, then runs feReduce in place.
//
// Projective point representation: (X : Y : Z) at offsets +0, +32, +64.
// 96 bytes per point. Renes-Costello-Batina 2016 complete addition
// formulas (eprint 2015/1060, algorithm 4 for unified add).
//
// Scalar representation: 32 bytes big-endian per FIPS 186-5 §6 (the
// natural P-256 byte order). All scalar operations consume / produce
// 32 BE bytes; the byte-level reduction loop in scalar.ts mirrors the
// curve25519 byte-level reduction with the curve order n substituted
// for L.
//
// Region map (byte offsets, sizes in bytes):
//
//   Offset    Size     Region
//   0         4096     (reserved for AS data segment)
//   4096      32       MUL_INT_LO       (low half of mul intermediate)
//   4128      32       MUL_INT_HI       (high half)
//   4160      1024     FIELD_TMP        (32 × 32, scratch field elements;
//                                       slots 0..15 reserved for field.ts
//                                       internals (feMul / feReduce /
//                                       feInv / feSqrt), slots 16..31
//                                       available for point.ts and other
//                                       callers that need FE scratch
//                                       across feMul calls)
//   5184      768      POINT_TMP        (8 × 96, scratch projective points
//                                       for scalar-mult ladder state,
//                                       fixed-window conditional-select)
//   5952      256      SCALAR_TMP       (8 × 32, scratch scalars: k, kInv,
//                                       r, s, d, e, u1, u2)
//   6208      32       HMAC_DRBG_K      (RFC 6979 §3.2 / SP 800-90A K state)
//   6240      32       HMAC_DRBG_V      (RFC 6979 §3.2 / SP 800-90A V state)
//   6336      33       ECDSA_PK_CHECK   (compressed-pk fault-check scratch)
//   6369      33       ECDSA_PK_INPUT   (caller-supplied compressed-pk copy)
//   6402      32       ECDSA_MSG_HASH   (caller-supplied SHA-256(M))
//
// Embedded SHA-256 + HMAC-SHA-256 region (verbatim names from
// sha2/buffers.ts, offsets local to p256). RFC 6979 calls HMAC many
// times per sign so the buffers are sized for repeated use without
// re-allocation.
//
//   6434      32       SHA256_H_OFFSET       (H0..H7 state)
//   6466      64       SHA256_BLOCK_OFFSET   (block accumulator)
//   6530      256      SHA256_W_OFFSET       (W[0..63] message schedule)
//   6786      32       SHA256_OUT_OFFSET     (32-byte digest output)
//   6818      64       SHA256_INPUT_OFFSET   (caller input staging, 1 block)
//   6882      4        SHA256_PARTIAL_OFFSET (u32 partial-block length)
//   6886      8        SHA256_TOTAL_OFFSET   (u64 total bytes hashed)
//   6894      64       HMAC256_IPAD_OFFSET   (K' XOR 0x36)
//   6958      64       HMAC256_OPAD_OFFSET   (K' XOR 0x5C)
//   7022      32       HMAC256_INNER_OFFSET  (inner hash saved by hmacFinal)
//
//   BUFFER_END = 7054
//
// Constants live as inline u32 in field.ts / scalar.ts / point.ts; AS
// data-segment volatility makes layout-anchored constants brittle.
//
// Per AGENTS.md "Wipe discipline", `wipeBuffers()` in index.ts zeros
// every byte from MUTABLE_START to BUFFER_END after each public-API
// operation finalises; secret scalar bytes, intermediate point
// coordinates, HMAC_DRBG K / V state, and the embedded SHA-256
// streaming state do not persist.

// ── Reserved region for AS data segment ─────────────────────────────────────

export const MUTABLE_START:        i32 = 4096

// ── Field-arithmetic regions ───────────────────────────────────────────────

// feMul writes the 8x8 schoolbook sum into MUL_INT_LO (low 8) +
// MUL_INT_HI (high 8); LO/HI split lets Solinas index high limbs 0..7
// as HMV §2.27 h0..h7.
export const MUL_INT_LO:           i32 = 4096
export const MUL_INT_HI:           i32 = 4128

// Scratch field elements (32 bytes each, 32 slots). Used by:
//   - field.ts feInv: 256-bit binary scan + ct-select, uses slots 4..15
//   - field.ts feSqrt: same scan over (p+1)/4, uses slots 4..15
//   - field.ts feMul/feReduce: uses slots 0..15 (s1..s9 + acc + scratch)
//   - point.ts: Renes-Costello-Batina algorithm 4 / 6 intermediates;
//     uses slots 16..31 so the inner feMul calls retain their slot 0..15
//     working set across calls.
export const FIELD_TMP:            i32 = 4160
export const FIELD_TMP_STRIDE:     i32 = 32

// Scratch projective points (96 bytes each, 8 slots). Used by:
//   - scalar_mult.ts pointMul / pointMulBase: accumulator R, addend Q,
//     plus 6 slots for fixed-window conditional-select staging
//   - point.ts pointAdd / pointDouble result staging when caller aliases
//     out with one of the inputs
//   - ecdsa.ts verify: u1*G + u2*Q intermediate, single-affinify result
export const POINT_TMP:            i32 = 5184
export const POINT_TMP_STRIDE:     i32 = 96

// Scratch scalars (32 bytes each, 8 slots).
//   slot 0: k             (per-call nonce)
//   slot 1: kInv          (k^-1 mod n)
//   slot 2: r             (signature r)
//   slot 3: s             (signature s)
//   slot 4: d             (private scalar, copied from skOff for arithmetic)
//   slot 5: e             (message digest mapped into Z_n)
//   slot 6: u1            (verify: e * w mod n)
//   slot 7: u2            (verify: r * w mod n)
export const SCALAR_TMP:           i32 = 5952
export const SCALAR_TMP_STRIDE:    i32 = 32

// ── RFC 6979 / SP 800-90A HMAC_DRBG state ──────────────────────────────────
//
// K and V are the per-derivation DRBG state; RFC 6979 §3.2 step b sets
// V = 0x01..01, K = 0x00..00, then loops HMAC(K, ...) to refresh both
// until a candidate k is produced. Persist across the rejection-sampling
// loop and are wiped at the end of the sign call.
export const HMAC_DRBG_K:          i32 = 6208
export const HMAC_DRBG_V:          i32 = 6240

// ── ECDSA per-call scratch ─────────────────────────────────────────────────

// Compressed-pk fault-check scratch. After signing, ecdsa.ts re-derives
// pk by pointMulBase(d) and compresses to this slot, then compares
// byte-for-byte against ECDSA_PK_INPUT (the caller-supplied pk). The
// fault-injection trap mirrors Ed25519's defence.
export const ECDSA_PK_CHECK:       i32 = 6336

// Caller-supplied compressed pk (33 bytes). Copied into mutable memory
// up front so the caller's source buffer can be freely reused; the
// fault-check at the end of sign compares ECDSA_PK_CHECK to this slot.
export const ECDSA_PK_INPUT:       i32 = 6369

// Caller-supplied SHA-256(M) (32 bytes). Mirrored to mutable memory so
// the per-call e = msg_hash mod n reduction can use it as input without
// aliasing caller-owned memory.
export const ECDSA_MSG_HASH:       i32 = 6402

// ── Embedded SHA-256 + HMAC-SHA-256 region ─────────────────────────────────
//
// Buffer NAMES mirror sha2/buffers.ts so the verbatim sha256 / hmac
// port compiles unchanged after only a buffer-import path rewrite;
// OFFSETS are local to the p256 module's linear memory layout.

export const SHA256_H_OFFSET:       i32 = 6434
export const SHA256_BLOCK_OFFSET:   i32 = 6466   // 6434 + 32
export const SHA256_W_OFFSET:       i32 = 6530   // 6466 + 64
export const SHA256_OUT_OFFSET:     i32 = 6786   // 6530 + 256
export const SHA256_INPUT_OFFSET:   i32 = 6818   // 6786 + 32
export const SHA256_PARTIAL_OFFSET: i32 = 6882   // 6818 + 64
export const SHA256_TOTAL_OFFSET:   i32 = 6886   // 6882 + 4
export const HMAC256_IPAD_OFFSET:   i32 = 6894   // 6886 + 8
export const HMAC256_OPAD_OFFSET:   i32 = 6958   // 6894 + 64
export const HMAC256_INNER_OFFSET:  i32 = 7022   // 6958 + 64

/**
 * End of the p256 module buffer region (exclusive upper bound).
 * Used by `wipeBuffers()` in `index.ts` to clear mutable state without
 * touching the AS data segment.
 */
export const BUFFER_END:           i32 = 7054   // 7022 + 32

// ── Module identity ─────────────────────────────────────────────────────────

// Module ID 9: ct=0, serpent=0, chacha20=1, aes=1, sha2=2, sha3=3,
// blake3=4, kyber=5, mldsa=6, slhdsa=7, curve25519=8. (The cipher
// modules collide on the low IDs; the values are informational, not
// used as a unique key.)
export function getModuleId():           i32 { return 9                  }
export function getMemoryPages():        i32 { return memory.size()      }

// ── Offset getter functions ─────────────────────────────────────────────────

export function getFieldTmpOffset():     i32 { return FIELD_TMP          }
export function getFieldTmpStride():     i32 { return FIELD_TMP_STRIDE   }
export function getPointTmpOffset():     i32 { return POINT_TMP          }
export function getPointTmpStride():     i32 { return POINT_TMP_STRIDE   }
export function getScalarTmpOffset():    i32 { return SCALAR_TMP         }
export function getScalarTmpStride():    i32 { return SCALAR_TMP_STRIDE  }
export function getMulIntOffset():       i32 { return MUL_INT_LO         }
