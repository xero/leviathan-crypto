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
// src/asm/mldsa/sampling.ts
//
// ML-DSA — rejection sampling kernels for ExpandA / ExpandS.
// FIPS 204 §7.3 Algorithms 30 (RejNTTPoly) and 31 (RejBoundedPoly), plus
// Algorithms 14 (CoeffFromThreeBytes) and 15 (CoeffFromHalfByte) used
// per-byte inside the loops.
//
// CT POSTURE — REQUIRED READING:
//
//   • RejNTTPoly samples Â from the *public* seed ρ. Data-dependent branching
//     here does not leak secret information; the matrix Â is a public output
//     of ExpandA. Same posture as Kyber's rej_uniform.
//
//   • RejBoundedPoly samples s₁/s₂ from the *secret* seed ρ′. Despite the
//     seed being secret, the rejection-sampler's acceptance rate is uniform
//     over each input byte regardless of seed value (each byte is uniformly
//     distributed in [0, 256)). The number of iterations leaked through
//     branching depends only on the public byte stream G/H produced by
//     SHAKE — it is not a function of the secret seed contents in a way that
//     reveals the secret. The Dilithium reference implementation makes the
//     same trade-off and FIPS 204 §7.3 endorses it. Documented here so
//     reviewers do not "constant-time-ify" the loop, which would oversample
//     and waste entropy without improving security.
//
// Both kernels are the inner per-block stage of the sampling pipeline. Phase-4
// orchestration owns the SHAKE128/SHAKE256 absorb/squeeze loop and calls the
// kernel repeatedly, advancing the polynomial counter, until 256 coefficients
// have been accepted.

import { Q, N } from './params';

// ── rej_ntt_poly — FIPS 204 Algorithm 30 ────────────────────────────────────
//
// Inner sampling loop for RejNTTPoly. Each 3-byte group from the SHAKE128
// stream is mapped to one candidate (FIPS 204 Algorithm 14
// CoeffFromThreeBytes); the candidate is accepted if it lies in [0, q).
//
// The 0x7F mask on b₂ clears the top bit (line 3 of Alg 14): after the mask,
// the 23-bit value is in [0, 2²³ − 1]; since q ≈ 2²³ − 2¹³ + 1, ~3% of
// candidates are rejected.
//
// Returns the number of coefficients written this call. Caller passes
// ctrStart so the function resumes from the last partial fill.
export function rej_ntt_poly(polyOff: i32, ctrStart: i32, bufOff: i32, bufLen: i32): i32 {
	let ctr: i32 = ctrStart;
	let pos: i32 = 0;
	while (ctr < N && pos + 3 <= bufLen) {
		const b0: u32 = <u32>load<u8>(bufOff + pos);
		const b1: u32 = <u32>load<u8>(bufOff + pos + 1);
		const b2: u32 = <u32>load<u8>(bufOff + pos + 2);
		// CoeffFromThreeBytes (Alg 14): z = ((b₂ & 0x7F) << 16) | (b₁ << 8) | b₀
		const z: i32 = <i32>(((b2 & 0x7F) << 16) | (b1 << 8) | b0);
		pos += 3;
		if (z < Q) {
			store<i32>(polyOff + ctr * 4, z);
			ctr++;
		}
	}
	return ctr - ctrStart;
}

// ── rej_bounded_poly — FIPS 204 Algorithm 31 ────────────────────────────────
//
// Inner sampling loop for RejBoundedPoly. Each input byte yields up to two
// candidates via CoeffFromHalfByte (Alg 15) — the low and high nibbles.
//
// CoeffFromHalfByte:
//   if η = 2 and b < 15  →  return 2 − (b mod 5)     ∈ {-2,-1,0,1,2}
//   if η = 4 and b < 9   →  return 4 − b              ∈ {-4,-3,-2,-1,0,1,2,3,4}
//   else                 →  ⊥  (rejected)
//
// `eta` is a runtime parameter (2 or 4); the branch is data-independent
// because eta is fixed per parameter set. Returns coefficients written.
export function rej_bounded_poly(polyOff: i32, ctrStart: i32, bufOff: i32, bufLen: i32, eta: i32): i32 {
	let ctr: i32 = ctrStart;
	let pos: i32 = 0;
	while (ctr < N && pos < bufLen) {
		const z:  u32 = <u32>load<u8>(bufOff + pos);
		const z0: u32 = z & 0x0F;
		const z1: u32 = z >> 4;
		pos++;
		if (eta == 2) {
			if (z0 < 15) {
				// 2 − (z0 mod 5). AS lacks fast `%`; explicit subtract is fine.
				const v: i32 = 2 - <i32>(z0 - (z0 / 5) * 5);
				store<i32>(polyOff + ctr * 4, v);
				ctr++;
			}
			if (ctr < N && z1 < 15) {
				const v: i32 = 2 - <i32>(z1 - (z1 / 5) * 5);
				store<i32>(polyOff + ctr * 4, v);
				ctr++;
			}
		} else {
			// eta == 4
			if (z0 < 9) {
				store<i32>(polyOff + ctr * 4, 4 - <i32>z0);
				ctr++;
			}
			if (ctr < N && z1 < 9) {
				store<i32>(polyOff + ctr * 4, 4 - <i32>z1);
				ctr++;
			}
		}
	}
	return ctr - ctrStart;
}

// ── sample_in_ball — FIPS 204 Algorithm 29 ──────────────────────────────────
//
// CT posture: SampleInBall consumes c̃ (signature commitment hash) — derived
// from H(μ || w₁Encode(w₁)). Both inputs to that hash are public:
// μ is published in the message representative; w₁Encode(w₁) is reconstructable
// from the signature itself (Verify_internal recomputes it). The final
// signature includes c̃ in plaintext. Hence SampleInBall's data-dependent
// branching reveals only public information. Documented per FIPS 204 §7.3.
//
// Resumable shape — the orchestration layer pre-squeezes one SHAKE block
// (typically 136 bytes for SHAKE256) and calls this kernel. If the buffer is
// exhausted before all τ samples land, the kernel returns the last
// not-yet-filled index `i`, and the caller squeezes another block and calls
// again with that `i` as `startI`.
//
// First call contract — caller must:
//   1. Zero `polyOff` (256 × i32 = 1024 bytes).
//   2. Squeeze 8 bytes of the SHAKE stream into `signsOff`.
//   3. Squeeze N bytes into `posBytesOff` (any N ≥ 0 — caller's choice).
//   4. Call sample_in_ball(polyOff, signsOff, posBytesOff, N, tau, 256-tau).
//
// Subsequent calls:
//   5. Squeeze fresh bytes into `posBytesOff` (replacing the consumed ones).
//   6. Call again with `startI` set to the previous return value.
//
// Returns:
//   256       — success: all τ samples placed, full polynomial populated.
//   value < 256 — buffer exhausted; resume with this value as startI.
export function sample_in_ball(
	polyOff:    i32,
	signsOff:   i32,
	posBytesOff: i32,
	posBytesLen: i32,
	tau:        i32,
	startI:     i32,
): i32 {
	let pos: i32 = 0;
	for (let i: i32 = startI; i < N; i++) {
		// Inner rejection: read bytes until j ≤ i. If we run out of bytes
		// before finding a valid j, return i so the caller resumes here.
		let j: i32 = 0;
		while (true) {
			if (pos >= posBytesLen) return i;
			j = <i32>load<u8>(posBytesOff + pos);
			pos++;
			if (j <= i) break;
		}
		// c[i] ← c[j] (might be 0 or a previously-placed ±1)
		const cj: i32 = load<i32>(polyOff + j * 4);
		store<i32>(polyOff + i * 4, cj);
		// c[j] ← (-1)^h[i + τ - 256], where h is the bit-string of signsOff.
		const bitIdx: i32 = i + tau - N;          // ∈ [0, τ)
		const byte:   i32 = <i32>load<u8>(signsOff + (bitIdx >> 3));
		const bit:    i32 = (byte >> (bitIdx & 7)) & 1;
		// 1 - 2·bit  ⇒  +1 if bit=0, -1 if bit=1
		store<i32>(polyOff + j * 4, 1 - (bit << 1));
	}
	return N;
}
