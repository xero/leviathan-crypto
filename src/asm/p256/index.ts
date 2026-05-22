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
// src/asm/p256/index.ts
//
// p256 WASM module, public export surface.
// FIPS 186-5 §6 (ECDSA) and SP 800-186 §3.2.1.3 (P-256 parameters).
//
// Substrate: field arithmetic over GF(p256) with the
// Hankerson-Menezes-Vanstone §2.4.1 Algorithm 2.27 Solinas reduction,
// short-Weierstrass projective-coords point operations via the
// Renes-Costello-Batina 2016 complete addition formulas (eprint
// 2015/1060, algorithm 4 for unified add, algorithm 7 for doubling),
// scalar arithmetic mod n (curve order), constant-time fixed-window
// scalar multiplication (variable-base and fixed-base over a
// precomputed-G table). Composed on top: RFC 6979 §3.2 deterministic /
// hedged K derivation against an embedded HMAC-SHA-256 chain, and
// FIPS 186-5 §6.4 / §6.5 ECDSA sign / verify entry points.
//
// Module ID 9 (the 12th WASM binary; 3 memory pages). The 3-page
// sizing is comfortable for the substrate's mutable buffer footprint
// (a few KB; see ./buffers.ts) and the per-call message-hash staging
// (the TS wrapper computes SHA-256(M) before crossing the WASM
// boundary, so only the 32-byte digest is passed in).
//
// Scalar (no v128); the 256-bit Solinas reduction lane-packs poorly.
// Non-Montgomery domain (locked): natural field domain, feFromBytes /
// feToBytes are radix conversions. See
// docs/asm_p256.md#simd-posture and
// docs/asm_p256.md#representation-choice for the
// AS extmul evaluation and the RustCrypto-Montgomery comparison.

import {BUFFER_END, MUTABLE_START} from './buffers'

// ── Buffer layout + module identity ─────────────────────────────────────────

export {
	getModuleId, getMemoryPages,
	getFieldTmpOffset, getFieldTmpStride,
	getPointTmpOffset, getPointTmpStride,
	getScalarTmpOffset, getScalarTmpStride,
	getMulIntOffset,
} from './buffers'

// ── Field arithmetic ────────────────────────────────────────────────────────

export {
	feAdd, feSub, feNeg, feMul, feSqr, feInv, feSqrt,
	feFromBytes, feToBytes,
	feIsZero, feIsEqual, feIsOdd, feIsCanonical, feCondSwap, feCondNeg,
} from './field'

// ── Scalar arithmetic (mod n, curve order) ──────────────────────────────────

export {
	scalarFromBytes, scalarToBytes,
	scalarIsCanonical, scalarIsZero, scalarIsHighS,
	scalarReduce, scalarReduce64,
	scalarAdd, scalarSub, scalarMul, scalarNegate, scalarInv,
} from './scalar'

// ── Projective points + complete addition + doubling ───────────────────────

export {
	pointZero, pointBasepoint, pointAdd, pointDouble, pointSub,
	pointNegate, pointEqual, pointOnCurve, pointAffinify,
	pointCompress, pointDecompress,
} from './point'

// ── Scalar multiplication ───────────────────────────────────────────────────

export {
	pointMul, pointMulBase, pointMulDoubleVerify,
} from './scalar_mult'

// ── RFC 6979 K derivation (deterministic + hedged) ──────────────────────────

export {
	deriveKDeterministic, deriveKHedged,
} from './rfc6979'

// ── ECDSA high-level operations ─────────────────────────────────────────────
//
// FIPS 186-5 §6.4 sign, §6.5 verify, §A.4 keygen. The substrate
// exposes both the public-pk-fault-check sign entry (`ecdsaSign`) for
// direct callers and the suite-only entry (`ecdsaSignInternalPk`) for
// the higher-level signature suites, mirroring the
// curve25519 `ed25519Sign` / `ed25519SignInternalPk` pair.

export {
	ecdsaKeygen,
	ecdsaSign,
	ecdsaSignInternalPk,
	ecdsaVerify,
} from './ecdsa'

// ── Test-only field hooks (substrate gate; not part of the consumer ABI)

export {
	_testFeReduce, _testGetMulIntOffset,
} from './field'

// ── Buffer wipe ─────────────────────────────────────────────────────────────

/**
 * Zero the p256 module's mutable buffer region.
 * Skips the data segment at offsets 0..MUTABLE_START-1.
 * Called by the TypeScript wrapper's dispose() so secret scalars,
 * intermediate point coordinates, the HMAC_DRBG K / V state, and the
 * embedded SHA-256 streaming state do not persist in WASM memory.
 */
export function wipeBuffers(): void {
	memory.fill(MUTABLE_START, 0, BUFFER_END - MUTABLE_START)
}
