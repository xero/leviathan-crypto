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
// src/asm/curve25519/index.ts
//
// curve25519 WASM module, public export surface.
// RFC 7748 (Curve25519 / X25519) and RFC 8032 (edwards25519 / Ed25519).
//
// TASK-B substrate: field arithmetic over GF(2^255-19), Edwards point
// operations on edwards25519 (extended coords), Montgomery ladder for
// X25519, scalar arithmetic mod L, and point encoding / decoding.
// TASK-C will compose Ed25519 high-level keygen / sign / verify on this
// substrate; TASK-D will compose X25519 keygen / DH.
//
// Module ID 8 (the 11th WASM binary; 2 memory pages).
// SIMD required: v128-internal field arithmetic and 2-way paired
// Edwards-addition. No scalar fallback.

import { BUFFER_END, MUTABLE_START } from './buffers'

// ── Buffer layout + module identity ─────────────────────────────────────────

export {
	getModuleId, getMemoryPages,
	getFieldTmpOffset, getFieldTmpStride,
	getPointTmpOffset, getPointTmpStride,
	getLadderTmpOffset, getLadderTmpStride,
} from './buffers'

// ── Field arithmetic ────────────────────────────────────────────────────────

export {
	feAdd, feSub, feNeg, feMul, feSqr, feInv,
	feMul121666, feFromBytes, feToBytes,
	feIsZero, feIsNegative, feCondSwap, feCondNeg,
} from './field'

// ── Edwards points (TASK-B step 7 / 9 for full impls) ───────────────────────

export {
	edPointZero, edPointBasepoint, edPointDouble, edPointAdd, edPointSub,
	edPointEqual, edPointMul, edPointMulBase, edPointOnCurve,
} from './edwards'

// ── Point compression (TASK-B step 7 for full impls) ────────────────────────

export {
	edPointCompress, edPointDecompress,
} from './compress'

// ── X25519 Montgomery ladder ────────────────────────────────────────────────

export { x25519Ladder } from './montgomery'

// ── Scalar arithmetic (mod L) ───────────────────────────────────────────────

export {
	scalarClamp, scalarReduce, scalarReduce64,
	scalarAdd, scalarMulAdd, scalarIsCanonical,
} from './scalar'

// ── Buffer wipe ─────────────────────────────────────────────────────────────

/**
 * Zero the curve25519 module's mutable buffer region.
 * Skips the data segment at offsets 0..MUTABLE_START-1.
 * Called by the TypeScript wrapper's dispose() so secret scalars,
 * intermediate point coordinates, and ladder state do not persist in
 * WASM memory.
 */
export function wipeBuffers(): void {
	memory.fill(MUTABLE_START, 0, BUFFER_END - MUTABLE_START)
}
