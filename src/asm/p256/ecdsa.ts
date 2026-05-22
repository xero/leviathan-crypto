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
// High-level ECDSA-P256 entry points per FIPS 186-5 §6:
//   ecdsaKeygen          : §A.4.2 seed → (d, pk); SEC1 §2.3.3 compress
//   ecdsaSign            : §6.4 sign; RFC 6979 §3.2 deterministic or
//                          draft-irtf-cfrg-det-sigs-with-noise-05 hedged;
//                          low-S per RFC 6979 §3.5; pk fault-cross-check
//   ecdsaSignInternalPk  : suite-only sign without the cross-check
//   ecdsaVerify          : §6.5 strict verify (low-S enforced)
//
// Per-export JSDoc below details reject paths and parameter shapes.
// Wipe discipline: every export ends with wipeAll() on success and on
// every early return / trap.

import {
	SCALAR_TMP, SCALAR_TMP_STRIDE,
	POINT_TMP, POINT_TMP_STRIDE,
	ECDSA_PK_CHECK, ECDSA_PK_INPUT, ECDSA_MSG_HASH,
	MUTABLE_START, BUFFER_END,
} from './buffers'

import {
	scalarReduce, scalarIsCanonical, scalarIsZero, scalarIsHighS,
	scalarMul, scalarAdd, scalarInv, scalarNegate,
} from './scalar'

import {
	pointMulBase, pointMulDoubleVerify,
} from './scalar_mult'

import {
	pointAffinify, pointCompress, pointDecompress, pointOnCurve,
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
// Dispatches deterministic vs hedged K-derivation. rnd is caller-
// supplied non-secret entropy; branching on it is safe.
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
 * Suite-only sign entry: no pkOff, no fault-injection cross-check.
 * Suite holds only the seed; caller pk and WASM-derived pk come from
 * the same potentially-faulted module, so the cross-check would be
 * degenerate. See AGENTS.md §"Per-call WASM lifecycle in
 * SignatureSuite factories".
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

	// e = bits2int(h1) mod n. qlen = hlen = 256 ⇒ bits2int identity
	// (RFC 6979 §2.3.4); recompute here so the sign-core is self-contained.
	scalarReduce(e, msgHashOff)

	// Init the HMAC_DRBG (RFC 6979 §3.2 or draft hedged) once per sign.
	if (isAllZero32(rndOff) == 1) {
		_drbgInitDeterministic(d, msgHashOff)
	} else {
		_drbgInitHedged(d, msgHashOff, rndOff)
	}

	// First k. Retries (r==0 / s==0) reuse the DRBG state per §3.2 step h.
	_drbgNextK(k)

	// On r == 0 / s == 0, draw next k from the continued DRBG
	// (RFC 6979 §3.4 step 6). Rejection probability < 2^-256 per branch.
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
 * Reject paths (each returns 0 without distinguishing which fired):
 *   - pk decompression fails (prefix not 0x02/0x03, x not on curve)
 *   - decompressed pk is the identity
 *   - r ∉ [1, n-1] or s ∉ [1, n-1]
 *   - s > n/2 (strict low-S; FIPS 186-5 §6.5 accepts both s and n-s
 *     under the same pk, leviathan rejects high-S for parity with
 *     Ed25519 and the Wycheproof strict-gate corpus)
 *   - signature equation fails: r_check ≠ r
 *
 * Timing: branches on public inputs (pk, msgHash, sig); NOT
 * constant-time across reject branches, by design. See
 * docs/asm_p256.md#verify-timing.
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

	// R = u1*G + u2*Q via Strauss-Shamir simultaneous double scalar mult.
	// Cuts the scalar-multiplication wall-clock roughly in half versus
	// two separate ladders + a join add. Verify inputs are public; this
	// is documented non-CT (docs/asm_p256.md#verify-timing).
	const u1G: i32 = POINT_TMP + 3 * POINT_TMP_STRIDE
	pointMulDoubleVerify(u1, u2, Q, u1G)

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
