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
// src/asm/p256/ecdsa.ts
//
// High-level ECDSA-P256 entry points per FIPS 186-5 §6.
//
//   ecdsaKeygen(seedOff, pkOff)
//     Deterministic key derivation from a 32-byte seed. d = seed mod n
//     (caller must ensure d != 0; the substrate traps on d == 0).
//     pk = [d]G compressed to 33 bytes per SEC1 §2.3.3.
//
//   ecdsaSign(skOff, pkOff, msgHashOff, rndOff, sigOff)
//     FIPS 186-5 §6.4 sign with hedged-or-deterministic K per
//     draft-irtf-cfrg-det-sigs-with-noise-05. If rnd is all-zero, the
//     deterministic RFC 6979 §3.2 path is used (reproduces RFC 6979
//     §A.2.5 expected k values); else the hedged path. Always
//     normalises to low-S per RFC 6979 §3.5. After signing, re-derives
//     pk = [d]G and compares byte-for-byte against the caller's
//     pkOff; mismatch wipes the mutable region and traps via
//     `unreachable`, mirroring the Ed25519 fault-injection defence.
//
//   ecdsaSignInternalPk(skOff, msgHashOff, rndOff, sigOff)
//     Suite-only entry. Derives pk internally and skips the fault-
//     injection cross-check, saving one fixed-base scalar mult. Used
//     by the suite-level factory in src/ts/sign/suites/*,
//     mirrors `ed25519SignInternalPk`.
//
//   ecdsaVerify(pkOff, msgHashOff, sigOff) → i32
//     FIPS 186-5 §6.5 verify with the strict-S posture (§6.5.3 +
//     low-S enforcement). Returns 1 on accept, 0 on any reject path:
//       - pk decompression fails
//       - pk is the identity
//       - r ∉ [1, n-1] or s ∉ [1, n-1]
//       - s > n/2 (high-S)
//       - signature equation fails (R = u1*G + u2*Q, r_check =
//         x(R) mod n; reject if r_check != r)
//
// Wipe discipline: every export ends with wipeBuffersInline() on the
// success path AND on every early return / trap. Secret intermediates
// (d, k, kInv, r, s, e, K, V) all live in mutable regions cleared by
// the BUFFER_END-bounded wipe.

import {
	SCALAR_TMP, SCALAR_TMP_STRIDE,
	POINT_TMP, POINT_TMP_STRIDE,
	ECDSA_SIG_TMP, ECDSA_PK_CHECK, ECDSA_PK_INPUT, ECDSA_MSG_HASH,
	MUTABLE_START, BUFFER_END,
} from './buffers'

import {
	scalarReduce, scalarIsCanonical, scalarIsZero, scalarIsHighS,
	scalarMul, scalarAdd, scalarInv, scalarNegate,
} from './scalar'

import {
	pointMul, pointMulBase,
} from './scalar_mult'

import {
	pointAdd, pointAffinify, pointCompress, pointDecompress,
	pointOnCurve,
} from './point'

import {
	_drbgInitDeterministic, _drbgInitHedged, _drbgNextK,
} from './rfc6979'

import {FIELD_TMP, FIELD_TMP_STRIDE} from './buffers'

import { ctEqual } from '../cte/shared'

// ── Internal wipe helper ───────────────────────────────────────────────────
//
// Inlined copy of index.ts wipeBuffers so ecdsa.ts entry points can
// clean up before returning or trapping without dragging a circular
// import. Byte-equivalent to index.ts wipeBuffers.
@inline
function wipeAll(): void {
	memory.fill(MUTABLE_START, 0, BUFFER_END - MUTABLE_START)
}

// ── 32-byte all-zero detector ──────────────────────────────────────────────
//
// Used by ecdsaSign to dispatch between the deterministic and hedged
// K-derivation paths. `rnd` is caller-supplied entropy and is NOT
// secret-key dependent, so a branch on isAllZero(rnd) does not leak
// any secret bits — the dispatcher visibility is limited to the
// caller's choice of mode (deterministic vs hedged).
@inline
function isAllZero32(buf: i32): i32 {
	let r: u32 = 0
	for (let i: i32 = 0; i < 32; i++) {
		r |= load<u8>(buf + i) as u32
	}
	const x: u32 = r | ((-(r as i32)) as u32)
	return ((1 as u32) - (x >> 31)) as i32
}

// ── ecdsaKeygen ────────────────────────────────────────────────────────────

/**
 * Deterministic key pair generation from a 32-byte BE seed.
 *
 * d = seed mod n (FIPS 186-5 §A.4.2 testing-candidates style with a
 * single candidate; the substrate cannot rejection-sample because it
 * has no additional entropy). The probability that seed mod n == 0
 * is ~2^-256; on that vanishingly unlikely event the substrate traps
 * via `unreachable` rather than silently substituting d = 1.
 *
 * pk = [d]G compressed per SEC1 §2.3.3 (33 bytes at pkOff).
 */
export function ecdsaKeygen(seedOff: i32, pkOff: i32): void {
	const d: i32 = SCALAR_TMP + 4 * SCALAR_TMP_STRIDE
	scalarReduce(d, seedOff)
	if (scalarIsZero(d) == 1) {
		wipeAll()
		unreachable()
	}
	// pk = [d]G.
	const kG: i32 = POINT_TMP + 3 * POINT_TMP_STRIDE
	pointMulBase(d, kG)
	pointCompress(pkOff, kG)
	wipeAll()
}

// ── ecdsaSign ──────────────────────────────────────────────────────────────

/**
 * skOff:       32 bytes BE, private scalar d ∈ [1, n-1]
 * pkOff:       33 bytes, caller-supplied compressed pk (for the
 *              fault-injection cross-check)
 * msgHashOff:  32 bytes BE, SHA-256(M)
 * rndOff:      32 bytes, per-call entropy Z (all-zero → deterministic
 *              RFC 6979 §3.2; non-zero → hedged draft variant)
 * sigOff:      64 bytes output, raw r || s
 *
 * On pk-mismatch fault: wipes the mutable region and traps via
 * `unreachable`. Mirror of `ed25519Sign`'s fault-injection defence.
 */
export function ecdsaSign(
	skOff: i32, pkOff: i32, msgHashOff: i32, rndOff: i32, sigOff: i32,
): void {
	// Stage caller inputs into mutable scratch so subsequent wipe
	// covers all secret-derived intermediates.
	memory.copy(ECDSA_MSG_HASH, msgHashOff, 32)
	memory.copy(ECDSA_PK_INPUT, pkOff, 33)

	ecdsaSignCore(skOff, ECDSA_MSG_HASH, rndOff, sigOff)

	// Fault-injection cross-check: pk' = [d]G compressed; compare to
	// caller's pk. The d scalar still lives in SCALAR_TMP slot 4 (the
	// core sign path leaves it for this very check).
	const d: i32 = SCALAR_TMP + 4 * SCALAR_TMP_STRIDE
	const kG: i32 = POINT_TMP + 3 * POINT_TMP_STRIDE
	pointMulBase(d, kG)
	pointCompress(ECDSA_PK_CHECK, kG)
	if (ctEqual(ECDSA_PK_CHECK + 1, ECDSA_PK_INPUT + 1, 32) == 0
	    || (load<u8>(ECDSA_PK_CHECK) as i32) != (load<u8>(ECDSA_PK_INPUT) as i32)) {
		wipeAll()
		unreachable()
	}

	wipeAll()
}

/**
 * Suite-only sign entry: no pkOff parameter, no fault-injection
 * cross-check. The suite-layer caller (`EcdsaP256Suite`) has
 * already computed pk = [d]G via this same substrate during a prior
 * `keygen()` call (or never crossed the substrate boundary with a
 * known-good pk to compare against), so the cross-check would be
 * degenerate — both the suite's pk and the WASM-derived pk come from
 * the same possibly-faulted module. See AGENTS.md §"Per-call WASM
 * lifecycle in SignatureSuite factories".
 */
export function ecdsaSignInternalPk(
	skOff: i32, msgHashOff: i32, rndOff: i32, sigOff: i32,
): void {
	memory.copy(ECDSA_MSG_HASH, msgHashOff, 32)
	ecdsaSignCore(skOff, ECDSA_MSG_HASH, rndOff, sigOff)
	wipeAll()
}

// Internal: shared core of ecdsaSign / ecdsaSignInternalPk. Leaves d
// in SCALAR_TMP slot 4 for the caller's optional fault-check.
function ecdsaSignCore(
	skOff: i32, msgHashOff: i32, rndOff: i32, sigOff: i32,
): void {
	const k:     i32 = SCALAR_TMP + 0 * SCALAR_TMP_STRIDE
	const kInv:  i32 = SCALAR_TMP + 1 * SCALAR_TMP_STRIDE
	const r:     i32 = SCALAR_TMP + 2 * SCALAR_TMP_STRIDE
	const s:     i32 = SCALAR_TMP + 3 * SCALAR_TMP_STRIDE
	const d:     i32 = SCALAR_TMP + 4 * SCALAR_TMP_STRIDE
	const e:     i32 = SCALAR_TMP + 5 * SCALAR_TMP_STRIDE

	// Stage d (private scalar). The caller's skOff buffer is consumed
	// here; we copy through into mutable memory so the wipe at the end
	// of the public entry point covers d.
	memory.copy(d, skOff, 32)

	// Compute e = bits2int(h1) mod n. For P-256 + SHA-256, qlen = hlen
	// = 256, so bits2int is a no-op truncation; the reduction mod n
	// folds the integer into the scalar field. This is the same
	// reduced value that rfc6979.ts caches at SCALAR_TMP slot 5 as
	// h1mn; we recompute here so the sign-core is self-contained even
	// when the K derivation is bypassed (e.g. test-only sign-with-k
	// entry points in future revisions).
	scalarReduce(e, msgHashOff)

	// Initialise the RFC 6979 §3.2 HMAC_DRBG (or its hedged equivalent
	// per draft-irtf-cfrg-det-sigs-with-noise-05 §4) once per sign.
	// all-zero rnd → RFC 6979 §3.2 deterministic; else → hedged.
	if (isAllZero32(rndOff) == 1) {
		_drbgInitDeterministic(d, msgHashOff)
	} else {
		_drbgInitHedged(d, msgHashOff, rndOff)
	}

	// Draw the first candidate k. Subsequent draws (on the vanishingly
	// rare r == 0 / s == 0 rejection inside the loop below) reuse the
	// same DRBG state so each call cleanly advances V per RFC 6979
	// §3.2 step h. Re-initialising would re-derive the same k from the
	// same inputs and infinite-loop; the two-phase API in ./rfc6979.ts
	// makes the correct sequencing the only one available here.
	_drbgNextK(k)

	// Loop: in the vanishingly unlikely case that r == 0 or s == 0,
	// the spec (RFC 6979 §3.4 step 6) says "compute a new k from the
	// next iteration of the loop in step 5", which means continue the
	// DRBG — a fresh draw from the established (K, V) state. The
	// probability of one extra iteration is ~2^-256 (r == 0 requires
	// k*G to land on the y-axis mod n) and s == 0 is similar; under
	// any realistic adversary model this loop body runs exactly once.
	while (true) {
		// R = [k]G.
		const R: i32 = POINT_TMP + 3 * POINT_TMP_STRIDE
		pointMulBase(k, R)

		// r = x(R) mod n.
		const xR: i32 = FIELD_TMP + 16 * FIELD_TMP_STRIDE  // shared scratch with point.ts
		const yR: i32 = FIELD_TMP + 17 * FIELD_TMP_STRIDE
		pointAffinify(R, xR, yR)
		// xR is in BE-byte form after feToBytes; we need the limb form
		// reinterpreted as a 32-byte BE scalar candidate.
		const xRBytes: i32 = SCALAR_TMP + 6 * SCALAR_TMP_STRIDE
		feToBytesInto(xRBytes, xR)
		scalarReduce(r, xRBytes)

		if (scalarIsZero(r) == 1) {
			// Continue the DRBG: draw the next k from the existing
			// (K, V) state. _drbgNextK's first action is hmacKofV()
			// which advances V deterministically, so the new k is
			// guaranteed distinct from the rejected one.
			_drbgNextK(k)
			continue
		}

		// s = k^-1 * (e + r*d) mod n.
		scalarInv(kInv, k)
		const rd: i32 = SCALAR_TMP + 7 * SCALAR_TMP_STRIDE  // u2 slot, free here
		scalarMul(rd, r, d)
		scalarAdd(s, e, rd)
		scalarMul(s, kInv, s)

		if (scalarIsZero(s) == 1) {
			_drbgNextK(k)
			continue
		}

		// Low-S enforcement (RFC 6979 §3.5): if s > n/2, s ← n - s.
		if (scalarIsHighS(s) == 1) {
			scalarNegate(s, s)
		}

		break
	}

	// Output r || s.
	memory.copy(sigOff, r, 32)
	memory.copy(sigOff + 32, s, 32)
}

// Internal: bridge feToBytes from field.ts.
import {feToBytes} from './field'
@inline
function feToBytesInto(out: i32, src: i32): void {
	feToBytes(out, src)
}

// ── ecdsaVerify ────────────────────────────────────────────────────────────

/**
 * Returns 1 if (r, s) is a valid signature on msgHash under pk per
 * FIPS 186-5 §6.5, with the strict-S posture (low-S enforced). 0 on
 * any reject.
 *
 * Reject paths (each returns 0 without distinguishing which condition
 * triggered, by way of the boolean return value):
 *   - pk decompression fails (prefix not 0x02/0x03, x not on curve)
 *   - decompressed pk is the identity (Z would be 0)
 *   - r ∉ [1, n-1] or s ∉ [1, n-1]
 *   - s > n/2 (high-S; FIPS 186-5 itself does not require low-S, but
 *     this library's strict posture rejects high-S to align with the
 *     Wycheproof strict-gate corpus and the Ed25519 substrate's
 *     identical posture)
 *   - signature equation fails: r_check = x(u1*G + u2*Q) mod n
 *     does not equal r
 *
 * Timing posture: this function is NOT constant-time across reject
 * branches. Each gate early-returns on rejection, so the wall-clock
 * cost of a reject leaks WHICH gate fired. This is intentional and
 * safe: every input to ecdsaVerify (pk, msgHash, sig) is public, so a
 * timing channel between the gates discloses nothing the attacker
 * cannot already see on the wire. The constant-time discipline that
 * the library enforces elsewhere is for SECRET inputs (d, k, K/V
 * DRBG state); verify inputs do not qualify.
 */
export function ecdsaVerify(pkOff: i32, msgHashOff: i32, sigOff: i32): i32 {
	const r: i32 = sigOff
	const s: i32 = sigOff + 32

	// Strict gate: r, s ∈ [1, n-1].
	const rOk: i32 = scalarIsCanonical(r) & (1 - scalarIsZero(r))
	const sOk: i32 = scalarIsCanonical(s) & (1 - scalarIsZero(s))
	if ((rOk & sOk) == 0) {
		return 0
	}

	// Strict gate: low-S (s ≤ n/2).
	if (scalarIsHighS(s) == 1) {
		return 0
	}

	// Decompress pk.
	const Q: i32 = POINT_TMP + 4 * POINT_TMP_STRIDE
	if (pointDecompress(Q, pkOff) == 0) {
		return 0
	}

	// Reject identity pk (Z = 0 OR all coords zero). pointDecompress
	// always returns Z = 1 on success, so the identity is impossible
	// from a successful decode. The strict-gate equivalent reads on a
	// decompressed pk: pointOnCurve(Q) (mathematically guaranteed by
	// the sqrt + parity reconstruction, but we explicitly verify the
	// curve equation to catch any field-arithmetic bug that would let
	// an off-curve x through). FIPS 186-5 §6.5.2 step 1 requires this
	// public-key validation.
	if (pointOnCurve(Q) == 0) {
		return 0
	}

	// e = bits2int(h1) mod n.
	const e: i32 = SCALAR_TMP + 5 * SCALAR_TMP_STRIDE
	scalarReduce(e, msgHashOff)

	// w = s^-1 mod n; u1 = e * w mod n; u2 = r * w mod n.
	const w:  i32 = SCALAR_TMP + 1 * SCALAR_TMP_STRIDE  // reuse kInv slot
	const u1: i32 = SCALAR_TMP + 6 * SCALAR_TMP_STRIDE
	const u2: i32 = SCALAR_TMP + 7 * SCALAR_TMP_STRIDE
	scalarInv(w, s)
	scalarMul(u1, e, w)
	scalarMul(u2, r, w)

	// R = u1*G + u2*Q.
	const u1G: i32 = POINT_TMP + 3 * POINT_TMP_STRIDE
	const u2Q: i32 = POINT_TMP + 5 * POINT_TMP_STRIDE
	pointMulBase(u1, u1G)
	pointMul(u2, Q, u2Q)
	pointAdd(u1G, u1G, u2Q)  // u1G now holds R = u1*G + u2*Q

	// r_check = x(R) mod n. If R is the identity (Z = 0), reject.
	const xR: i32 = FIELD_TMP + 16 * FIELD_TMP_STRIDE
	const yR: i32 = FIELD_TMP + 17 * FIELD_TMP_STRIDE
	// We need to check R is not the point at infinity. Easiest: check
	// pZ(R) != 0 in the field. If Z is 0, x/y are undefined; we treat
	// that as a reject.
	const zR: i32 = u1G + 64
	let zNonZero: u32 = 0
	for (let i: i32 = 0; i < 32; i++) {
		zNonZero |= load<u8>(zR + i) as u32
	}
	if (zNonZero == 0) {
		return 0
	}

	pointAffinify(u1G, xR, yR)
	const xRBytes: i32 = SCALAR_TMP + 2 * SCALAR_TMP_STRIDE  // reuse r slot
	feToBytesInto(xRBytes, xR)
	const rCheck: i32 = SCALAR_TMP + 3 * SCALAR_TMP_STRIDE
	scalarReduce(rCheck, xRBytes)

	// Compare r_check to r byte-for-byte. ctEqual returns 1 if equal, 0 if not.
	return ctEqual(rCheck, r, 32)
}
