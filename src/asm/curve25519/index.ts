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
// Module ID 8 (the 11th WASM binary; 4 memory pages). The 4-page sizing
// gives the TS layer's pure-mode message-staging region enough headroom
// to handle realistic in-memory pure-Ed25519 messages (cap ~248 KB).
// Prehash-mode signatures (`Ed25519PreHashSuite` + `SignStream`) never
// stage the message in WASM at all - the digest is computed at the TS
// layer and only 64 bytes cross the WASM boundary.
//
// Scalar (no v128). The dalek-cryptography parallel-formulas approach
// (eprint 2018/098) pairs the eight independent field multiplications
// of the Hisil-Wong-Carter-Dawson §3.1 extended-coords Edwards
// addition onto 2-way SIMD lanes. That approach materially helps only
// with a native paired 64x64→128 multiply. AssemblyScript's v128
// instruction set does not expose one; the closest primitive is
// i64x2.extmul_low_i32x4 / extmul_high_i32x4 (paired 32x32→64), and
// synthesising paired 64x64→128 from it requires a 4-piece split plus
// carry-tracking via XOR-flip + signed compare (no i64x2 unsigned
// compare). Empirically that emulated path is not measurably faster
// than two sequential scalar feMul calls: extmul throughput is not
// better than i64-mul plus 4-piece split, and the pack / unpack
// overhead consumes the marginal vector win.
//
// Per the SIMD-only-where-it-helps lib posture, curve25519 ships
// scalar, in the same bucket as sha2 / sha3 / slhdsa.

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

// ── Ed25519 high-level operations (TASK-C) ──────────────────────────────────
//
// RFC 8032 §5.1.5 (keygen), §5.1.6 (pure sign), §5.1.7 strict (pure
// verify and prehash variants). The embedded SHA-512 in ./sha512.ts is
// the only hash primitive consumed; its module-internal exports
// (sha512Init / sha512Update / sha512Final / sha512UpdateBytes) are
// deliberately NOT re-exported here. The curve25519.wasm ABI does not
// surface a sha512* function. See the head of ./sha512.ts for the
// embed-not-orchestrate rationale.

export {
	ed25519Keygen,
	ed25519Sign,
	ed25519Verify,
	ed25519SignPrehashed,
	ed25519VerifyPrehashed,
	ed25519SignInternalPk,
	ed25519SignPrehashedInternalPk,
} from './ed25519'

// ── X25519 high-level operations (TASK-D) ──────────────────────────────────
//
// RFC 7748 §6: keygen against the Curve25519 basepoint and Diffie-Hellman
// against a peer's u-coord public key. Both clamp the caller's 32-byte
// secret on every call per RFC 7748 §5; the all-zero shared-secret
// rejection (contributory behaviour) is performed at the TypeScript layer
// in TASK-E, not here. See the head of ./x25519.ts for the full posture.

export {
	x25519Keygen,
	x25519DH,
} from './x25519'

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
