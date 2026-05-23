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
// Substrate: field arithmetic over GF(2^255-19), Edwards point operations
// on edwards25519 (extended coords), Montgomery ladder for X25519,
// scalar arithmetic mod L, and point encoding / decoding. Composed on
// top: Ed25519 high-level keygen / sign / verify in `./ed25519.ts`, and
// X25519 keygen / DH in `./x25519.ts`.
//
// Module ID 8 (the 11th WASM binary; 4 memory pages). The 4-page sizing
// gives the TS layer's pure-mode message-staging region enough headroom
// to handle realistic in-memory pure-Ed25519 messages (cap ~248 KB).
// Prehash-mode signatures (`Ed25519PreHashSuite` + `SignStream`) never
// stage the message in WASM at all - the digest is computed at the TS
// layer and only 64 bytes cross the WASM boundary.
//
// Scalar (no v128). AssemblyScript's v128 instruction set does not
// expose a paired 64x64→128 multiply, and the emulated path is not
// measurably faster than sequential scalar feMul. See
// docs/asm_curve25519.md#simd-posture for the eprint 2018/098
// dalek-parallel evaluation.

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

// ── Edwards points ──────────────────────────────────────────────────────────

export {
	edPointZero, edPointBasepoint, edPointDouble, edPointAdd, edPointSub,
	edPointEqual, edPointMul, edPointMulBase, edPointMulDoubleVerify,
	edPointOnCurve,
} from './edwards'

// ── Point compression ───────────────────────────────────────────────────────

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

// ── Ed25519 high-level operations ───────────────────────────────────────────
//
// RFC 8032 §5.1.5 (keygen), §5.1.6 (pure sign), §5.1.7 strict (pure
// verify and prehash variants). Embedded SHA-512 is module-internal; the
// curve25519.wasm ABI does not surface sha512*. See ./sha512.ts head.

export {
	ed25519Keygen,
	ed25519Sign,
	ed25519Verify,
	ed25519SignPrehashed,
	ed25519VerifyPrehashed,
	ed25519SignInternalPk,
	ed25519SignPrehashedInternalPk,
} from './ed25519'

// ── X25519 high-level operations ────────────────────────────────────────────
//
// RFC 7748 §6: keygen against the Curve25519 basepoint and Diffie-Hellman
// against a peer's u-coord public key. Both clamp the caller's 32-byte
// secret on every call per RFC 7748 §5; the all-zero shared-secret
// rejection (contributory behaviour) is performed at the TypeScript layer,
// not here. See the head of ./x25519.ts for the full posture.

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
