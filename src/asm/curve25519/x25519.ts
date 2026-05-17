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
// src/asm/curve25519/x25519.ts
//
// X25519 high-level operations (RFC 7748 §6): keygen against the
// Curve25519 basepoint and Diffie-Hellman against a peer's u-coord public
// key. Thin wrappers around the substrate `x25519Ladder`: both
// exports clamp the caller's 32-byte secret on every call per RFC 7748
// §5, then drive the constant-time Montgomery ladder.
//
// Locked posture:
//
//   1. Clamping happens internally on every call. The skOff buffer holds
//      "opaque 32 random bytes" per RFC 7748 §5; the WASM API does NOT
//      surface "clamped sk" as a separate type. scalarClamp's copy-and-
//      clamp form (out != src) preserves skOff byte-for-byte.
//   2. All-zero shared-secret rejection is NOT performed at this layer.
//      x25519DH returns void; sharedOff is written unconditionally. The
//      TypeScript `X25519` class performs the constant-time
//      all-zero scan and rejects degenerate outputs per RFC 7748 §7 /
//      the contributory-behaviour interpretation. This matches x25519-
//      dalek's posture and preserves WASM-vs-oracle byte agreement on
//      any future test record that exercises a small-order peer pk.
//   3. No fault-injection cross-check. Unlike ed25519Sign which re-
//      derives pk from seed and aborts on caller-supplied pk mismatch,
//      x25519Keygen has no caller-supplied pk to cross-check and
//      x25519DH's peerPk is genuinely external (the other party's
//      actual choice).
//   4. peerPk is NOT masked at this layer. The substrate's `feFromBytes`
//      masks bit 255 of the encoded u-coord internally per RFC 7748 §5
//      (montgomery.ts:102-103); callers pass the encoded u-coord
//      byte-for-byte.
//
// Wipe discipline: each export ends with wipeX25519(), which zeroes
// X25519_SCALAR_CLAMP (the only secret intermediate, the clamped
// scalar). The caller-provided buffers (skOff, peerPkOff, pkOff,
// sharedOff) are NOT touched by wipeX25519; the TS layer manages their
// lifetimes. The module-level `wipeBuffers()` (index.ts)
// covers this slot too via the MUTABLE_START..BUFFER_END fill.

import {
	X25519_SCALAR_CLAMP,
	BASEPOINT_U,
	loadBasepointU,
} from './buffers'

import { x25519Ladder } from './montgomery'
import { scalarClamp } from './scalar'

// ── Internal wipe ──────────────────────────────────────────────────────────

/**
 * Zero the only secret intermediate this module owns. Called at the end
 * of every public export as defence-in-depth: the per-call wipe runs
 * before wipeBuffers() is invoked by the TS layer's dispose() (which
 * would clear this region anyway), so a caller that keeps the WASM
 * instance alive across multiple x25519 calls does not leave a stale
 * clamped scalar in memory between operations.
 *
 * NOT re-exported from index.ts; module-internal only.
 */
@inline
function wipeX25519(): void {
	memory.fill(X25519_SCALAR_CLAMP, 0, 32)
}

// ── x25519Keygen (RFC 7748 §6, basepoint variant) ──────────────────────────

/**
 * Derive the X25519 public key from a 32-byte secret per RFC 7748 §6:
 *   pk = X25519(clamp(sk), 9)
 *
 *   skOff: read 32 bytes (any 32 random bytes; the function clamps
 *          internally per RFC 7748 §5).
 *   pkOff: write 32 bytes (the derived public u-coord). pkOff is public
 *          and is left intact by the per-call wipe.
 *
 * BASEPOINT_U is the 32-byte LE encoding of u = 9 (RFC 7748 §4.1); it is
 * composed in linear memory by `loadBasepointU` and consumed in place by
 * the substrate.
 */
export function x25519Keygen(skOff: i32, pkOff: i32): void {
	scalarClamp(X25519_SCALAR_CLAMP, skOff)
	loadBasepointU(BASEPOINT_U)
	x25519Ladder(pkOff, X25519_SCALAR_CLAMP, BASEPOINT_U)
	wipeX25519()
}

// ── x25519DH (RFC 7748 §6, peer-pk variant) ────────────────────────────────

/**
 * Compute the X25519 shared secret per RFC 7748 §6:
 *   shared = X25519(clamp(sk), peerPk)
 *
 *   skOff:     read 32 bytes (any 32 random bytes; clamped internally).
 *   peerPkOff: read 32 bytes (the peer's encoded u-coord public key).
 *              NOT masked at this layer; the substrate's feFromBytes
 *              masks bit 255 internally per RFC 7748 §5.
 *   sharedOff: write 32 bytes (the shared u-coord). NOT checked for
 *              all-zero at the WASM level; the TypeScript `X25519` class
 *              performs the contributory-behaviour check.
 *
 * Returns void: there is no failure mode at the WASM level. A degenerate
 * output (e.g. from a small-order peerPk) is still WRITTEN to sharedOff;
 * the TS layer is responsible for rejecting it before returning the
 * value to the caller.
 */
export function x25519DH(skOff: i32, peerPkOff: i32, sharedOff: i32): void {
	scalarClamp(X25519_SCALAR_CLAMP, skOff)
	x25519Ladder(sharedOff, X25519_SCALAR_CLAMP, peerPkOff)
	wipeX25519()
}
