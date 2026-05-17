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
// src/asm/p256/rfc6979.ts
//
// RFC 6979 §3.2 deterministic K derivation and the
// draft-irtf-cfrg-det-sigs-with-noise-05 §4 hedged variant for P-256
// + SHA-256.
//
// Public entry points (the two existing helpers; both run the full
// init-plus-one-extraction sequence and remain byte-compatible with
// RFC 6979 §A.2.5):
//
//   deriveKDeterministic(d, msgHash, kOut)
//     RFC 6979 §3.2 verbatim. Drives HMAC-SHA-256 over
//     (V || 0x00 || int2octets(x) || bits2octets(h1)) and
//     (V || 0x01 || int2octets(x) || bits2octets(h1)) per steps d/f,
//     then the inner V = HMAC_K(V) feedback. Reproduces the RFC 6979
//     §A.2.5 P-256 / SHA-256 expected `k` byte-for-byte.
//
//   deriveKHedged(d, msgHash, rnd, kOut)
//     draft-irtf-cfrg-det-sigs-with-noise-05 §4 updated steps d/f
//     (described in the hedged section below).
//
// Both wrappers delegate to a two-phase API used internally by the
// ECDSA sign loop:
//
//   _drbgInitDeterministic(d, msgHash)
//   _drbgInitHedged(d, msgHash, rnd)
//     Run RFC 6979 §3.2 steps b through g (or the hedged equivalent).
//     Leave the HMAC_DRBG state (K, V) at offsets HMAC_DRBG_K /
//     HMAC_DRBG_V ready for sampling.
//
//   _drbgNextK(kOut)
//     Run §3.2 step h: produce one candidate k in [1, n-1], advancing
//     K / V across in-range rejection. The accepted k lives in V on
//     return, so subsequent calls cleanly produce subsequent k's: the
//     next hmacKofV() step advances V to HMAC_K(V_accepted), which is
//     statistically independent of the prior k.
//
// The two-phase split is what the §3.4 r=0 / s=0 retry path in
// ecdsa.ts requires. RFC 6979 §3.4 step 6 says "compute a new k from
// the next iteration of the loop in step 5"; for deterministic ECDSA
// this means continue the DRBG, NOT re-initialise it. A naïve
// re-init produces the same k and infinite-loops; the two-phase API
// makes the correct sequencing the only one available to the caller.
//
// Both extraction paths output k ∈ [1, n-1] in 32-byte BE form to
// `kOut`. The in-range rejection-sampling loop is constant-time-
// skipped per RFC 6979 §3.2's informative note: the probability of
// one extra HMAC iteration is bounded by (2^256 - n) / 2^256 < 2^-128
// for P-256.
//
// Buffer usage:
//   HMAC_DRBG_K (32 bytes): K state across HMAC calls
//   HMAC_DRBG_V (32 bytes): V state across HMAC calls
//   SCALAR_TMP slot 5 (32 bytes): h1 reduced mod n (bits2octets output)
//   SHA256_INPUT_OFFSET (64 bytes): scratch for HMAC key and message
//                                   chunks (one block at a time)
//
// The embedded SHA-256 + HMAC port (./sha256.ts + ./hmac_sha256.ts)
// keeps every HMAC call inside one WASM call: zero JS<->WASM boundary
// crossings during the rejection loop.

import {
	HMAC_DRBG_K, HMAC_DRBG_V,
	SCALAR_TMP, SCALAR_TMP_STRIDE,
	SHA256_INPUT_OFFSET, SHA256_OUT_OFFSET,
} from './buffers'

import {
	scalarReduce, scalarIsCanonical, scalarIsZero,
} from './scalar'

import {
	hmac256Init, hmac256Update, hmac256UpdateBytes, hmac256Final,
} from './hmac_sha256'

// ── Helper: HMAC_K(content) → write to outOff (32 bytes) ───────────────────
//
// content is supplied as a sequence of (src, len) pairs by the caller
// staging it through hmac256UpdateBytes. This helper is the per-call
// init + final pattern; the caller threads UpdateBytes between.
//
// We can't pass variadic arguments in AssemblyScript, so the call
// sites inline init / update / final.

// ── deriveKDeterministic: RFC 6979 §3.2 verbatim ───────────────────────────

/**
 * d:        32 bytes BE, private scalar (assumed canonical, in [1, n-1])
 * msgHash:  32 bytes BE, SHA-256(M)
 * kOut:     32 bytes BE, output nonce k ∈ [1, n-1]
 *
 * Equivalent to `_drbgInitDeterministic(d, msgHash); _drbgNextK(kOut)`.
 * Kept as a public entry for direct callers (substrate gate tests and
 * any external consumer that needs only one k per (d, M) pair).
 */
export function deriveKDeterministic(d: i32, msgHash: i32, kOut: i32): void {
	_drbgInitDeterministic(d, msgHash)
	_drbgNextK(kOut)
}

// ── deriveKHedged: draft-irtf-cfrg-det-sigs-with-noise-05 §4 ───────────────

/**
 * d:        32 bytes BE, private scalar
 * msgHash:  32 bytes BE, SHA-256(M)
 * rnd:      32 bytes, additional entropy Z (caller-supplied; all-zero
 *           is a valid input and produces the draft's "Z = 0" variant,
 *           which is NOT byte-equivalent to RFC 6979 §3.2 deterministic
 *           K — the hedged construction zero-pads to a different
 *           HMAC input length per the draft's intentional domain
 *           separation, see §5 of the draft).
 * kOut:     32 bytes BE, output nonce k ∈ [1, n-1]
 *
 * Equivalent to `_drbgInitHedged(d, msgHash, rnd); _drbgNextK(kOut)`.
 */
export function deriveKHedged(d: i32, msgHash: i32, rnd: i32, kOut: i32): void {
	_drbgInitHedged(d, msgHash, rnd)
	_drbgNextK(kOut)
}

// ── _drbgInitDeterministic: RFC 6979 §3.2 steps b through g ────────────────
//
// Establish the (K, V) HMAC_DRBG state at HMAC_DRBG_K / HMAC_DRBG_V.
// After return, _drbgNextK can be called any number of times to draw
// successive in-range k values.

export function _drbgInitDeterministic(d: i32, msgHash: i32): void {
	// Stage h1_mod_n = bits2octets(h1) per RFC 6979 §2.3.4. For SHA-256
	// the input h1 is exactly qlen = 256 bits, so bits2int(h1) = h1 as
	// BE integer. bits2octets = int2octets(h1 mod n).
	const h1mn: i32 = SCALAR_TMP + 5 * SCALAR_TMP_STRIDE
	scalarReduce(h1mn, msgHash)

	// Step b: V = 0x01 × 32
	memory.fill(HMAC_DRBG_V, 0x01, 32)
	// Step c: K = 0x00 × 32
	memory.fill(HMAC_DRBG_K, 0x00, 32)

	// Step d: K = HMAC_K(V || 0x00 || x || h1mn)
	hmac256InitWithK()
	hmac256UpdateBytes(HMAC_DRBG_V, 32)
	stageByte(0x00)
	hmac256UpdateBytes(d, 32)
	hmac256UpdateBytes(h1mn, 32)
	hmac256Final()
	memory.copy(HMAC_DRBG_K, SHA256_OUT_OFFSET, 32)

	// Step e: V = HMAC_K(V)
	hmacKofV()

	// Step f: K = HMAC_K(V || 0x01 || x || h1mn)
	hmac256InitWithK()
	hmac256UpdateBytes(HMAC_DRBG_V, 32)
	stageByte(0x01)
	hmac256UpdateBytes(d, 32)
	hmac256UpdateBytes(h1mn, 32)
	hmac256Final()
	memory.copy(HMAC_DRBG_K, SHA256_OUT_OFFSET, 32)

	// Step g: V = HMAC_K(V)
	hmacKofV()
}

// ── _drbgInitHedged: hedged equivalent of init ─────────────────────────────
//
// Per draft-irtf-cfrg-det-sigs-with-noise-05 §4 the K refresh in
// steps d and f changes to:
//
//   K = HMAC_K(V || sep || Z || 000... || int2octets(x) || 000...
//       || bits2octets(h1))
//
// where the zero-padding is chosen so that
// (V || sep || Z || 000...) and (int2octets(x) || 000...) are each
// the smallest multiple of the HMAC-SHA-256 block size (64 bytes).
// For 32-byte V, Z, x this yields:
//   (V || sep || Z || 000...)         = 128 bytes (65 +  63 pad)
//   (int2octets(x) || 000...)         =  64 bytes (32 +  32 pad)
//   bits2octets(h1)                   =  32 bytes
//
// Total per HMAC call: 224 bytes.
//
// Step e and g (V = HMAC_K(V)) are unchanged from RFC 6979 §3.2.

export function _drbgInitHedged(d: i32, msgHash: i32, rnd: i32): void {
	const h1mn: i32 = SCALAR_TMP + 5 * SCALAR_TMP_STRIDE
	scalarReduce(h1mn, msgHash)

	memory.fill(HMAC_DRBG_V, 0x01, 32)
	memory.fill(HMAC_DRBG_K, 0x00, 32)

	// Step d (hedged): K = HMAC_K(V || 0x00 || Z || pad || x || pad || h1mn)
	hedgedRefresh(d, rnd, h1mn, 0x00)
	// Step e: V = HMAC_K(V)
	hmacKofV()
	// Step f (hedged): same shape as step d with 0x01.
	hedgedRefresh(d, rnd, h1mn, 0x01)
	// Step g: V = HMAC_K(V)
	hmacKofV()
}

// ── _drbgNextK: RFC 6979 §3.2 step h ───────────────────────────────────────
//
// Draw one k ∈ [1, n-1] from the established DRBG. May iterate
// internally for k ∉ [1, n-1]: this is the spec's in-range
// rejection-sampling loop (probability of even one rejection is
// < 2^-128 for P-256).
//
// On accept, V holds the accepted k bytes. The next call to
// _drbgNextK begins with hmacKofV(), which advances V to
// HMAC_K(V_accepted), a fresh sample independent of the previous k.
// This is the §3.4 r=0 / s=0 retry path's required semantics: a new
// k drawn from the CONTINUED DRBG, never a re-initialisation.

export function _drbgNextK(kOut: i32): void {
	while (true) {
		hmacKofV()
		memory.copy(kOut, HMAC_DRBG_V, 32)
		// Accept iff k ∈ [1, n-1] (canonical AND nonzero).
		const canonical: i32 = scalarIsCanonical(kOut)
		const nonzero:   i32 = 1 - scalarIsZero(kOut)
		if ((canonical & nonzero) == 1) {
			return
		}
		// In-range reject: K = HMAC_K(V || 0x00), V = HMAC_K(V).
		// Same shape for the deterministic and hedged paths; the
		// draft is silent on rejection-loop modifications so the loop
		// re-keys with K = HMAC_K(V || 0x00) (no Z reuse), matching
		// the RFC 6979 §3.2 rejection step verbatim.
		hmac256InitWithK()
		hmac256UpdateBytes(HMAC_DRBG_V, 32)
		stageByte(0x00)
		hmac256Final()
		memory.copy(HMAC_DRBG_K, SHA256_OUT_OFFSET, 32)
		hmacKofV()
	}
}

// ── Internal helpers ────────────────────────────────────────────────────────

// Initialise HMAC with K = HMAC_DRBG_K (32 bytes). The hmac256Init
// API consumes its key from SHA256_INPUT_OFFSET; we stage K there
// first.
@inline
function hmac256InitWithK(): void {
	memory.copy(SHA256_INPUT_OFFSET, HMAC_DRBG_K, 32)
	hmac256Init(32)
}

// Push a single byte into the running inner hash.
@inline
function stageByte(b: u8): void {
	store<u8>(SHA256_INPUT_OFFSET, b)
	hmac256Update(1)
}

// V = HMAC_K(V). Re-initialises HMAC, feeds V, writes the HMAC
// output back into V.
@inline
function hmacKofV(): void {
	hmac256InitWithK()
	hmac256UpdateBytes(HMAC_DRBG_V, 32)
	hmac256Final()
	memory.copy(HMAC_DRBG_V, SHA256_OUT_OFFSET, 32)
}

// One hedged refresh of K. Implements the draft's updated step (d) or
// step (f) depending on `sep`:
//
//   K = HMAC_K(V || sep || Z || 000...(63) || x || 000...(32) || h1mn)
//
// where:
//   sep = 0x00 for step (d), 0x01 for step (f)
//   Z   = caller's rnd (32 bytes; copied through unchanged)
//   x   = caller's d (32 bytes BE)
//   h1mn = bits2octets(h1) staged at SCALAR_TMP slot 5
//
// Zero padding lengths chosen per the draft's "smallest multiple of
// the hash block size" rule with HMAC-SHA-256 block = 64:
//   |V| + |sep| + |Z| = 65 → pad 63 to reach 128.
//   |x| = 32             → pad 32 to reach 64.
@inline
function hedgedRefresh(d: i32, rnd: i32, h1mn: i32, sep: u8): void {
	hmac256InitWithK()
	hmac256UpdateBytes(HMAC_DRBG_V, 32)
	stageByte(sep)
	hmac256UpdateBytes(rnd, 32)
	// Zero padding (63 bytes). Stage zero bytes through
	// SHA256_INPUT_OFFSET in 63-byte chunks; the helper handles
	// chunking up to 64 bytes per call.
	memory.fill(SHA256_INPUT_OFFSET, 0, 63)
	hmac256Update(63)
	// int2octets(x): 32 bytes.
	hmac256UpdateBytes(d, 32)
	// Zero padding (32 bytes).
	memory.fill(SHA256_INPUT_OFFSET, 0, 32)
	hmac256Update(32)
	// bits2octets(h1): 32 bytes.
	hmac256UpdateBytes(h1mn, 32)
	hmac256Final()
	memory.copy(HMAC_DRBG_K, SHA256_OUT_OFFSET, 32)
}
