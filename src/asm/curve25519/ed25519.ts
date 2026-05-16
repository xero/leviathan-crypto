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
// src/asm/curve25519/ed25519.ts
//
// Ed25519 (RFC 8032 §5.1.5 keygen, §5.1.6 pure sign, §5.1.7 strict
// verify) and Ed25519ph (RFC 8032 §5.1.7 prehash, dom2 phflag=1). The
// strict-verification posture matches FIPS 186-5 §7.6.4: the
// cofactor-eight variant `[8s]G == [8](R + [k]A)` is NOT implemented.
// Small-order public-key rejection uses three substrate doublings and a
// single equality check against the identity, no constant-time scan
// against a hardcoded small-order point table (the no-tables posture
// continues from TASK-B).
//
// Embedded SHA-512 (verbatim port at ./sha512.ts) is the only hash
// primitive consumed; sha2.wasm is not orchestrated for the reasons
// documented at the head of ./sha512.ts.
//
// Wipe discipline: every export ends with wipeBuffers() (the index.ts
// export) for the success path, AND on every early return / abort
// (decompress failure, scalar non-canonical, ctxLen out of range,
// pk-mismatch fault check). Secret intermediates (clamped a, prefix,
// r, k, hash outputs, point coordinates of A / R / [k]A / [s]B) all
// live in the appended ED25519_* / SHA512_* regions of buffers.ts and
// are cleared by the BUFFER_END-bounded wipeBuffers fill.

import {
	SHA512_OUT_OFFSET,
	SHA512_INPUT_OFFSET,
	ED25519_SCALAR_A,
	ED25519_PREFIX,
	ED25519_R_SCALAR,
	ED25519_K_SCALAR,
	ED25519_PK_CHECK,
	ED25519_POINT_A,
	ED25519_POINT_R,
	ED25519_POINT_TMP1,
	ED25519_POINT_TMP2,
	BUFFER_END,
	MUTABLE_START,
	loadDom2Prefix,
} from './buffers'

import {
	sha512Init,
	sha512Update,
	sha512UpdateBytes,
	sha512Final,
} from './sha512'

import {
	edPointZero,
	edPointDouble,
	edPointAdd,
	edPointEqual,
	edPointMul,
	edPointMulBase,
} from './edwards'

import {
	edPointCompress,
	edPointDecompress,
} from './compress'

import {
	scalarClamp,
	scalarReduce64,
	scalarMulAdd,
	scalarIsCanonical,
} from './scalar'

// ── Internal helpers ───────────────────────────────────────────────────────

/**
 * Wipe the curve25519 module's mutable buffer region. Inlined copy of
 * index.ts wipeBuffers so ed25519 paths can call it on early returns
 * without dragging a circular import. The two are intentionally
 * byte-equivalent: both zero MUTABLE_START..BUFFER_END.
 */
@inline
function wipeAll(): void {
	memory.fill(MUTABLE_START, 0, BUFFER_END - MUTABLE_START)
}

/**
 * Constant-time compare 32 PUBLIC bytes. Used for the post-derivation
 * pk-fault-check in sign: the caller-supplied pk and the freshly
 * derived pk are both PUBLIC values (the seed is secret, but pk = [a]B
 * has no leakage advantage over a fresh derivation), so a plain
 * mismatch-OR loop suffices. Returns 0 if equal, non-zero otherwise.
 */
@inline
function bytes32Diff(a: i32, b: i32): i32 {
	let diff: i32 = 0
	for (let i: i32 = 0; i < 32; i++) {
		diff |= (load<u8>(a + i) as i32) ^ (load<u8>(b + i) as i32)
	}
	return diff
}

/**
 * dom2Update writes the dom2(F=1, C) prefix into the active SHA-512
 * instance per RFC 8032 §5.1:
 *   dom2(F, C) = "SigEd25519 no Ed25519 collisions" || octet(F) || octet(|C|) || C
 *
 * Used only by the Ed25519ph paths (sign / verify prehashed). Pure
 * Ed25519 omits the dom2 prefix entirely (RFC 8032 §5.1, "the empty
 * string for F=0 without context"); the pure sign / verify code does
 * not call this function.
 *
 * Caller MUST have ensured 0 ≤ ctxLen ≤ 255 (RFC 8032 §5.1 limit).
 * The high-level export checks ctxLen up front and rejects out-of-range
 * before calling here.
 *
 * Layout written to SHA512_INPUT_OFFSET (≤ 128 bytes):
 *   [0..31]      "SigEd25519 no Ed25519 collisions" (loadDom2Prefix)
 *   [32]         F = 1
 *   [33]         |C|
 *   [34..34+|C|] C bytes
 *
 * Total prefix size is at most 34 + 255 = 289 bytes; we feed it through
 * sha512UpdateBytes (chunked) using SHA512_INPUT_OFFSET as staging.
 * Since SHA512_INPUT_OFFSET is 128 bytes and 34 ≤ 128, the prefix
 * header always fits in one stage; we then sha512Update(34) and follow
 * with a sha512UpdateBytes for the context.
 */
@inline
function dom2Update(ctxOff: i32, ctxLen: i32): void {
	// Write the dom2 32-byte ASCII prefix + F + |C| into SHA-512 staging.
	loadDom2Prefix(SHA512_INPUT_OFFSET)
	store<u8>(SHA512_INPUT_OFFSET + 32, 1)               // F = 1 (Ed25519ph)
	store<u8>(SHA512_INPUT_OFFSET + 33, ctxLen as u8)
	sha512Update(34)
	if (ctxLen > 0) {
		sha512UpdateBytes(ctxOff, ctxLen)
	}
}

/**
 * Derive the Ed25519 secret scalar `a` and signing-prefix `prefix`
 * from a 32-byte seed per RFC 8032 §5.1.5:
 *
 *   h = SHA-512(seed)
 *   a = clamp(h[0..32])       (RFC 7748 §5 / RFC 8032 §5.1.5)
 *   prefix = h[32..64]
 *
 * Writes a (32 bytes) → ED25519_SCALAR_A, prefix (32 bytes) →
 * ED25519_PREFIX. Both are secret-bearing and live in the buffers
 * wiped by wipeAll().
 *
 * Leaves SHA-512 state dirty; the caller's next SHA-512 hash MUST start
 * with sha512Init().
 */
@inline
function deriveScalarAndPrefix(seedOff: i32): void {
	sha512Init()
	sha512UpdateBytes(seedOff, 32)
	sha512Final()
	scalarClamp(ED25519_SCALAR_A, SHA512_OUT_OFFSET)
	memory.copy(ED25519_PREFIX, SHA512_OUT_OFFSET + 32, 32)
}

// ── ed25519Keygen (RFC 8032 §5.1.5) ────────────────────────────────────────

/**
 * Deterministic key generation from a 32-byte seed.
 *
 *   seedOff: read 32 bytes (the user's secret seed; see RFC 8032 §5.1.5).
 *   pkOff:   write 32 bytes (encoded verifying key A per §5.1.2).
 *
 * Mandatory wipe at the end: SHA-512 state, clamped `a`, prefix, and
 * the extended-coord point A are all secret-dependent.
 */
export function ed25519Keygen(seedOff: i32, pkOff: i32): void {
	deriveScalarAndPrefix(seedOff)
	edPointMulBase(ED25519_POINT_A, ED25519_SCALAR_A)
	edPointCompress(pkOff, ED25519_POINT_A)
	wipeAll()
}

// ── ed25519Sign pure (RFC 8032 §5.1.6) ─────────────────────────────────────

/**
 * Produce a 64-byte (R || s) signature over `msg` for the given seed.
 *
 *   seedOff: read 32 bytes (Ed25519 secret seed)
 *   pkOff:   read 32 bytes (encoded verifying key, caller-supplied to
 *            avoid re-derivation cost; verified internally against the
 *            freshly derived pk and abort-on-mismatch to defeat
 *            fault-injection: a caller passing an incorrect pk would
 *            otherwise produce a signature that fails to verify under
 *            the claimed pk)
 *   msgOff:  msgLen bytes of message
 *   sigOff:  write 64 bytes (R || s)
 *
 * Pure Ed25519 omits the dom2 prefix entirely per RFC 8032 §5.1.
 *
 * Wipe coverage on the success path: SHA-512 state buffers, h, a,
 * prefix, r_hash, k_hash, r, k, point coords of A and R_point. All live
 * in the SHA-512 and ED25519_* regions and are cleared by wipeAll.
 *
 * Fault check: if the freshly-derived pk disagrees with pkOff, wipe and
 * abort (unreachable). The env-provided `abort` shim in the TS layer
 * surfaces this as a thrown error.
 */
export function ed25519Sign(seedOff: i32, pkOff: i32, msgOff: i32, msgLen: i32, sigOff: i32): void {
	// Derive (a, prefix) and pk_check = compress([a]B); compare to caller's pk.
	deriveScalarAndPrefix(seedOff)
	edPointMulBase(ED25519_POINT_A, ED25519_SCALAR_A)
	edPointCompress(ED25519_PK_CHECK, ED25519_POINT_A)
	if (bytes32Diff(ED25519_PK_CHECK, pkOff) != 0) {
		wipeAll()
		unreachable()
	}

	// r = SHA-512(prefix || message) mod L
	sha512Init()
	sha512UpdateBytes(ED25519_PREFIX, 32)
	sha512UpdateBytes(msgOff, msgLen)
	sha512Final()
	scalarReduce64(ED25519_R_SCALAR, SHA512_OUT_OFFSET)

	// R = [r]B, then encode R into sigOff[0..32]
	edPointMulBase(ED25519_POINT_R, ED25519_R_SCALAR)
	edPointCompress(sigOff, ED25519_POINT_R)

	// k = SHA-512(R || pk || message) mod L
	sha512Init()
	sha512UpdateBytes(sigOff,    32)
	sha512UpdateBytes(pkOff,     32)
	sha512UpdateBytes(msgOff, msgLen)
	sha512Final()
	scalarReduce64(ED25519_K_SCALAR, SHA512_OUT_OFFSET)

	// s = (k*a + r) mod L → sigOff[32..64]
	scalarMulAdd(sigOff + 32, ED25519_K_SCALAR, ED25519_SCALAR_A, ED25519_R_SCALAR)

	wipeAll()
}

// ── ed25519Verify pure (RFC 8032 §5.1.7 strict) ────────────────────────────

/**
 * Strict (cofactor-less) verification per FIPS 186-5 §7.6.4 / RFC 8032
 * §5.1.7. Returns 1 on success, 0 on failure.
 *
 *   pkOff:  read 32 bytes (encoded verifying key A)
 *   msgOff: msgLen bytes of message
 *   sigOff: read 64 bytes (R || s)
 *
 * Failure paths (each wipes before returning 0):
 *   - pk decode fails (non-canonical y ≥ p, off-curve, or x=0 with sign=1)
 *   - R decode fails  (same conditions on the R component)
 *   - s ≥ L          (strict-S check; the ACVP `testPassed=false`
 *                     "modify s" records hit this path)
 *   - [8]A == identity (small-order public key; A is in the prime-order
 *                       subgroup iff its order is L, in which case [8]A
 *                       is non-identity)
 *   - [s]B != R + [k]A (signature equation does not hold)
 *
 * Strict semantics matters for ACVP `testPassed` agreement: the
 * cofactor-eight equation `[8s]G == [8](R + [k]A)` is permissive of
 * malleated S and small-order R; FIPS 186-5 requires the strict form
 * implemented here.
 */
export function ed25519Verify(pkOff: i32, msgOff: i32, msgLen: i32, sigOff: i32): i32 {
	// Decode pk and R. edPointDecompress returns 0 on:
	//   - non-canonical encoding (y ≥ p in the encoded form)
	//   - off-curve point
	//   - the (x=0, x_0=1) edge case (RFC 8032 §5.1.3 step 4)
	if (edPointDecompress(ED25519_POINT_A, pkOff) == 0) {
		wipeAll()
		return 0
	}
	if (edPointDecompress(ED25519_POINT_R, sigOff) == 0) {
		wipeAll()
		return 0
	}

	// s must be in [0, L). Per FIPS 186-5 §7.6.4 strict-S. The ACVP
	// "modify s" failure records depend on this rejection.
	if (scalarIsCanonical(sigOff + 32) == 0) {
		wipeAll()
		return 0
	}

	// Small-order public-key rejection: [8]A != identity.
	// Mathematically, A is small-order iff its order divides 8, iff
	// [8]A is identity. Three substrate doublings + one equality check
	// against (0:1:1:0).
	edPointDouble(ED25519_POINT_TMP1, ED25519_POINT_A)
	edPointDouble(ED25519_POINT_TMP1, ED25519_POINT_TMP1)
	edPointDouble(ED25519_POINT_TMP1, ED25519_POINT_TMP1)
	edPointZero(ED25519_POINT_TMP2)
	if (edPointEqual(ED25519_POINT_TMP1, ED25519_POINT_TMP2) == 1) {
		wipeAll()
		return 0
	}

	// k = SHA-512(R || pk || message) mod L
	sha512Init()
	sha512UpdateBytes(sigOff,    32)
	sha512UpdateBytes(pkOff,     32)
	sha512UpdateBytes(msgOff, msgLen)
	sha512Final()
	scalarReduce64(ED25519_K_SCALAR, SHA512_OUT_OFFSET)

	// Strict equation: [s]B == R + [k]A.
	// LHS = [s]B in TMP1 (overwriting the [8]A doubling chain), kA in
	// TMP2 (overwriting the staged identity), RHS = R + kA accumulated
	// back into TMP2 (edPointAdd allows out to alias either operand).
	edPointMulBase(ED25519_POINT_TMP1, sigOff + 32)
	edPointMul(ED25519_POINT_TMP2, ED25519_K_SCALAR, ED25519_POINT_A)
	edPointAdd(ED25519_POINT_TMP2, ED25519_POINT_R, ED25519_POINT_TMP2)

	const result: i32 = edPointEqual(ED25519_POINT_TMP1, ED25519_POINT_TMP2)
	wipeAll()
	return result
}

// ── ed25519SignPrehashed (RFC 8032 §5.1.7 prehash) ─────────────────────────

/**
 * Produce a 64-byte (R || s) Ed25519ph signature over the SHA-512
 * digest of the message, with optional context.
 *
 *   seedOff:  read 32 bytes (Ed25519 secret seed)
 *   pkOff:    read 32 bytes (caller-supplied verifying key)
 *   digestOff: read 64 bytes (pre-computed SHA-512(message))
 *   ctxOff:   ctxLen bytes of context (may be empty)
 *   ctxLen:   0 ≤ ctxLen ≤ 255 (RFC 8032 §5.1 limit); larger aborts
 *   sigOff:   write 64 bytes (R || s)
 *
 * Differences from pure Ed25519 (§5.1.6) per RFC 8032 §5.1.7:
 *   1. The dom2(F=1, ctx) prefix precedes both SHA-512 inputs.
 *   2. The message is replaced by its pre-hashed SHA-512 digest.
 */
export function ed25519SignPrehashed(seedOff: i32, pkOff: i32, digestOff: i32, ctxOff: i32, ctxLen: i32, sigOff: i32): void {
	if (ctxLen > 255) {
		wipeAll()
		unreachable()
	}

	deriveScalarAndPrefix(seedOff)
	edPointMulBase(ED25519_POINT_A, ED25519_SCALAR_A)
	edPointCompress(ED25519_PK_CHECK, ED25519_POINT_A)
	if (bytes32Diff(ED25519_PK_CHECK, pkOff) != 0) {
		wipeAll()
		unreachable()
	}

	// r = SHA-512(dom2(1, ctx) || prefix || digest) mod L
	sha512Init()
	dom2Update(ctxOff, ctxLen)
	sha512UpdateBytes(ED25519_PREFIX, 32)
	sha512UpdateBytes(digestOff,      64)
	sha512Final()
	scalarReduce64(ED25519_R_SCALAR, SHA512_OUT_OFFSET)

	edPointMulBase(ED25519_POINT_R, ED25519_R_SCALAR)
	edPointCompress(sigOff, ED25519_POINT_R)

	// k = SHA-512(dom2(1, ctx) || R || pk || digest) mod L
	sha512Init()
	dom2Update(ctxOff, ctxLen)
	sha512UpdateBytes(sigOff,    32)
	sha512UpdateBytes(pkOff,     32)
	sha512UpdateBytes(digestOff, 64)
	sha512Final()
	scalarReduce64(ED25519_K_SCALAR, SHA512_OUT_OFFSET)

	scalarMulAdd(sigOff + 32, ED25519_K_SCALAR, ED25519_SCALAR_A, ED25519_R_SCALAR)

	wipeAll()
}

// ── ed25519VerifyPrehashed (RFC 8032 §5.1.7 prehash strict) ────────────────

/**
 * Strict verification of an Ed25519ph signature. Returns 1 on success,
 * 0 on failure. Same strict-S / small-order rejection / equation check
 * as the pure path, plus the dom2(F=1, ctx) prefix before the running
 * SHA-512.
 *
 * Context > 255 bytes returns 0 (no abort, unlike the sign path; this
 * matches the verify semantics where every invalid input maps to "not
 * verified" rather than a runtime error).
 */
export function ed25519VerifyPrehashed(pkOff: i32, digestOff: i32, ctxOff: i32, ctxLen: i32, sigOff: i32): i32 {
	if (ctxLen > 255) {
		wipeAll()
		return 0
	}

	if (edPointDecompress(ED25519_POINT_A, pkOff) == 0) {
		wipeAll()
		return 0
	}
	if (edPointDecompress(ED25519_POINT_R, sigOff) == 0) {
		wipeAll()
		return 0
	}
	if (scalarIsCanonical(sigOff + 32) == 0) {
		wipeAll()
		return 0
	}

	edPointDouble(ED25519_POINT_TMP1, ED25519_POINT_A)
	edPointDouble(ED25519_POINT_TMP1, ED25519_POINT_TMP1)
	edPointDouble(ED25519_POINT_TMP1, ED25519_POINT_TMP1)
	edPointZero(ED25519_POINT_TMP2)
	if (edPointEqual(ED25519_POINT_TMP1, ED25519_POINT_TMP2) == 1) {
		wipeAll()
		return 0
	}

	// k = SHA-512(dom2(1, ctx) || R || pk || digest) mod L
	sha512Init()
	dom2Update(ctxOff, ctxLen)
	sha512UpdateBytes(sigOff,    32)
	sha512UpdateBytes(pkOff,     32)
	sha512UpdateBytes(digestOff, 64)
	sha512Final()
	scalarReduce64(ED25519_K_SCALAR, SHA512_OUT_OFFSET)

	edPointMulBase(ED25519_POINT_TMP1, sigOff + 32)
	edPointMul(ED25519_POINT_TMP2, ED25519_K_SCALAR, ED25519_POINT_A)
	edPointAdd(ED25519_POINT_TMP2, ED25519_POINT_R, ED25519_POINT_TMP2)

	const result: i32 = edPointEqual(ED25519_POINT_TMP1, ED25519_POINT_TMP2)
	wipeAll()
	return result
}
