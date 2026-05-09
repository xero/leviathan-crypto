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
// src/ts/mldsa/sign.ts
//
// FIPS 204 §6.2 Algorithm 7 — ML-DSA.Sign_internal.
// Drives the rejection-sampling loop. Each iteration produces a candidate
// (z, h); when all four norm/popcount checks pass the signature is encoded
// and returned. Implementation is hardened against the four ways an
// implementer can silently lose SUF-CMA: (a) skipping any of the four
// reject conditions, (b) re-using rnd between hedged signatures, (c)
// pre-adding r and z before make_hint (the kernel does the canonical
// r+z reduction internally), (d) failing to wipe ρ'' / μ / y / ⟨cs1⟩ /
// ⟨cs2⟩ / ⟨ct0⟩ / r₀ / signing-key NTT residues from WASM memory after
// returning. See §3.6.3 for the wipe contract.
//
// Slot allocation through one iteration body:
//   POLYVEC_SLOT_0  ŝ₁  (NTT, persistent through loop)
//   POLYVEC_SLOT_1  ŝ₂  (NTT, persistent)
//   POLYVEC_SLOT_2  t̂₀  (NTT, persistent)
//   POLYVEC_SLOT_3  y_time → ⟨cs₂⟩ → r₀ → ⟨ct₀⟩ → h
//   POLYVEC_SLOT_4  y_ntt → w₁ → ⟨cs₁⟩ → z
//   POLYVEC_SLOT_5  w_ntt → w_time → (w − ⟨cs₂⟩)
//   POLY_SLOT_0     signs (8 bytes — sample_in_ball signsOff)
//   POLY_SLOT_1     c (then ĉ in NTT domain, persistent within iteration)
//   POLY_SLOT_7     reserved scratch for polyvec_pointwise_acc_montgomery
//
// XOF/PRF region carries ExpandMask SHAKE squeeze, w1Encode bytes, and
// SampleInBall position bytes — all single-use within an iteration.
//
// CT POSTURE — rejection-sampling loop branches:
//   The four reject conditions (‖z‖∞, ‖r₀‖∞, ‖⟨ct₀⟩‖∞, popcount(h)) are
//   data-dependent on secret-derived intermediates. Each `continue` reveals
//   that this iteration's candidate was out-of-bound, which is the same
//   statistical signal already exposed by the SHAKE output stream changing
//   per κ. The leak is the iteration count, not key bits. FIPS 204 §3.6.3
//   endorses this trade-off; the Dilithium reference does the same. The
//   constant-time-mandatory comparison (c̃ in verify) lives in verify.ts.

import type { MlDsaExports, Sha3Exports } from './types.js';
import type { MlDsaParams } from './params.js';
import { wipe } from '../utils.js';
import { sha3Absorb, shake256HashConcat } from './sha3-helpers.js';
import { expandA, expandMask } from './expand.js';

const POLY_BYTES   = 1024;
const D            = 13;
const Q            = 8380417;
const SHAKE256_RATE = 136;

// Per FIPS 204 Appendix C, expected iterations are 4–7 across parameter
// sets (geometric distribution with success probability p ≈ 1/expected ≈
// 0.20–0.26). Spec minimum bound for implementations that choose to
// bound: 814.
//
// 1000 gives a nominal 20% headroom over the spec minimum, but the actual
// safety margin is far larger: Pr[fail within 1000 iterations] = (1-p)^1000
// ≈ 10⁻⁹⁴ to 10⁻¹³¹ across parameter sets — many orders of magnitude past
// any cryptographic threshold (compare 2⁻¹²⁸ ≈ 10⁻³⁹). The bound exists
// for liveness (deterministic failure on pathological inputs) rather than
// as a probability tail-cut; liboqs and the pq-crystals reference make
// the same engineering choice.
//
// Adversarial poisoning of the rejection-sampling rate would require
// controlling ρ'' = H(K ‖ rnd ‖ μ). K is in sk (private), so an attacker
// without the signing key cannot bias the iteration count regardless of
// what they do with the message, ctx, or (in derand mode) caller-supplied
// rnd. The natural per-iteration success probability holds.
const MAX_SIGN_ITERATIONS = 1000;

function bitlen(n: number): number {
	let b = 0; let x = n;
	while (x > 0) {
		b++; x >>>= 1;
	}
	return b;
}

/**
 * ML-DSA.Sign_internal — FIPS 204 Algorithm 7.
 *
 * Inputs:
 *   sk     — encoded signing key (skBytes per parameter set)
 *   MPrime — domain-separated message bytes (caller-built via constructMPrime)
 *   rnd    — 32-byte randomness (random for hedged, all-zero for deterministic,
 *            caller-supplied for derand/CAVP)
 *
 * Output: σ (sigBytes) — encoded per Algorithm 26 (sigEncode).
 *
 * Wipe contract: every WASM region that held a secret or secret-derived
 * intermediate is zeroed before return. TS-side scratch (μ, ρ'', c̃, the
 * w1 byte slice) wipes via try/finally even on early throw.
 */
export function mldsaSignInternal(
	mx: MlDsaExports,
	sx: Sha3Exports,
	params: MlDsaParams,
	sk: Uint8Array,
	MPrime: Uint8Array,
	rnd: Uint8Array,
): Uint8Array {
	const { k, l, eta, tau, lambda, gamma1, gamma2, beta, omega, sigBytes } = params;
	const lambdaOver4   = lambda >>> 2;                 // 32 / 48 / 64
	const etaBitlen     = bitlen(2 * eta);              // 3 (η=2) or 4 (η=4)
	const etaPolyBytes  = (256 * etaBitlen) >> 3;       // 96 or 128
	const t0PolyBytes   = (256 * D) >> 3;               // 416
	const t0LowEdge     = (1 << (D - 1)) - 1;           // 4095
	const t0HighEdge    = (1 << (D - 1));               // 4096
	const c             = 1 + bitlen(gamma1 - 1);       // 18 or 20
	const zPolyBytes    = 32 * c;                       // 576 or 640
	// w₁ field: m = (q − 1) / (2γ₂); width = bitlen(m − 1).
	// γ₂=(q-1)/88 ⇒ m=44 ⇒ width=6;  γ₂=(q-1)/32 ⇒ m=16 ⇒ width=4.
	const w1Bitlen      = bitlen(((Q - 1) / (2 * gamma2)) - 1);
	const w1PolyBytes   = (256 * w1Bitlen) >> 3;
	const w1TotalBytes  = k * w1PolyBytes;

	// ── WASM offsets ─────────────────────────────────────────────────────
	const matOff   = mx.getMatrixSlot();
	const slot0    = mx.getPolyvecSlot0();   // ŝ₁
	const slot1    = mx.getPolyvecSlot1();   // ŝ₂
	const slot2    = mx.getPolyvecSlot2();   // t̂₀
	const slot3    = mx.getPolyvecSlot3();   // y_time / ⟨cs₂⟩ / r₀ / ⟨ct₀⟩ / h
	const slot4    = mx.getPolyvecSlot4();   // y_ntt / w₁ / ⟨cs₁⟩ / z
	const slot5    = mx.getPolyvecSlot5();   // w / w − ⟨cs₂⟩
	const polySlotBase = mx.getPolySlotBase();
	const polySlot0 = mx.getPolySlot0();     // signs (8 bytes)
	const polySlot1 = mx.getPolySlot1();     // c → ĉ
	const sigOff   = mx.getSigOffset();
	const xofOff   = mx.getXofPrfOffset();
	const seedOff  = mx.getSeedOffset();
	const trOff    = mx.getTrOffset();
	const skOff    = mx.getSkOffset();
	const cTildeOff = mx.getCTildeOffset();
	const msgRepOff = mx.getMsgRepOffset();

	const mlMem    = new Uint8Array(mx.memory.buffer);
	const sha3Mem  = new Uint8Array(sx.memory.buffer);
	const sha3OutOff = sx.getOutOffset();

	// ── TS-side sensitive buffers — wiped in finally ─────────────────────
	let mu:     Uint8Array | undefined;
	let rhoPP:  Uint8Array | undefined;
	let cTilde: Uint8Array | undefined;
	let w1Bytes: Uint8Array | undefined;

	try {
		// ── skDecode — FIPS 204 §7.2 Algorithm 25 ────────────────────────
		// sk = ρ ‖ K ‖ tr ‖ s₁ ‖ s₂ ‖ t₀  (offsets per Algorithm 24).
		const rho = sk.subarray(0,    32);
		const K   = sk.subarray(32,   64);
		const tr  = sk.subarray(64,  128);
		let off = 128;

		// s₁ — ℓ polynomials, BitUnpack(η, η) per Alg 25 line 4
		for (let r = 0; r < l; r++) {
			mlMem.set(sk.subarray(off, off + etaPolyBytes), xofOff);
			mx.bit_unpack(slot0 + r * POLY_BYTES, xofOff, eta, eta);
			off += etaPolyBytes;
		}
		// FIPS 204 §7.2 / Alg 25 line 5: s₁ coefficients must lie in [-η, η].
		// bit_unpack at width bitlen(2η) overshoots that range for η ∈ {2,4}
		// (η=2 yields [-5, 2]; η=4 yields [-11, 4]) when sk bytes are tampered
		// or corrupted — reject before producing a wrong signature.
		if (mx.polyvec_chknorm(slot0, eta + 1, l) !== 0)
			throw new RangeError('leviathan-crypto: signing key s₁ coefficient out of [-η, η]');
		// s₂ — k polynomials, BitUnpack(η, η)
		for (let r = 0; r < k; r++) {
			mlMem.set(sk.subarray(off, off + etaPolyBytes), xofOff);
			mx.bit_unpack(slot1 + r * POLY_BYTES, xofOff, eta, eta);
			off += etaPolyBytes;
		}
		if (mx.polyvec_chknorm(slot1, eta + 1, k) !== 0)
			throw new RangeError('leviathan-crypto: signing key s₂ coefficient out of [-η, η]');
		// t₀ — k polynomials, BitUnpack(2^(d-1)-1, 2^(d-1)) — Alg 25 line 6
		// bit_unpack(2^(d-1)-1, 2^(d-1)) decodes exactly to [-(2^(d-1)-1), 2^(d-1)]
		// which matches the spec range — no caddq-style range check needed.
		for (let r = 0; r < k; r++) {
			mlMem.set(sk.subarray(off, off + t0PolyBytes), xofOff);
			mx.bit_unpack(slot2 + r * POLY_BYTES, xofOff, t0LowEdge, t0HighEdge);
			off += t0PolyBytes;
		}

		// ── FIPS 204 Alg 7 lines 2–5: ŝ₁ ← NTT(s₁); ŝ₂ ← NTT(s₂);
		//                             t̂₀ ← NTT(t₀); Â ← ExpandA(ρ) ────
		// Each NTT'd polyvec is then tomont'd so subsequent
		// poly_pointwise_montgomery products with a regular-form ĉ yield
		// regular (non-Montgomery) results — matches the keygen tomont
		// pattern (src/ts/mldsa/keygen.ts step 4 (c)). Without tomont the
		// post-invNTT values carry an extra R⁻¹ factor and ACVP fails.
		mx.polyvec_ntt(slot0, l);
		mx.polyvec_tomont(slot0, l);
		mx.polyvec_ntt(slot1, k);
		mx.polyvec_tomont(slot1, k);
		mx.polyvec_ntt(slot2, k);
		mx.polyvec_tomont(slot2, k);
		expandA(mx, sx, params, rho, matOff);

		// ── Line 6: μ ← H(BytesToBits(tr) ‖ M', 64) ───────────────────────
		// Byte-oriented SHAKE wrapper: BytesToBits is a no-op (we absorb tr
		// directly). ACVP gates byte-equality of μ implicitly through σ
		// equality on the deterministic-rnd vectors.
		mu = shake256HashConcat(sx, [tr, MPrime], 64);

		// ── Line 7: ρ'' ← H(K ‖ rnd ‖ μ, 64) ──────────────────────────────
		rhoPP = shake256HashConcat(sx, [K, rnd, mu], 64);

		// ── Line 8: κ ← 0 ────────────────────────────────────────────────
		let kappa = 0;
		cTilde = new Uint8Array(lambdaOver4);

		let success = false;

		// ── Line 10–31: rejection-sampling loop ──────────────────────────
		for (let iter = 0; iter < MAX_SIGN_ITERATIONS; iter++) {
			// Line 11: y ← ExpandMask(ρ'', κ) at slot3 (time domain) ──────
			expandMask(mx, sx, params, rhoPP, kappa, slot3);

			// Line 12: w ← NTT⁻¹(Â · NTT(y))
			// Copy y_time → slot4, NTT in place, matrix product → slot5,
			// inverse NTT → time domain, caddq → canonical for HighBits.
			mlMem.copyWithin(slot4, slot3, slot3 + l * POLY_BYTES);
			mx.polyvec_ntt(slot4, l);                                // ŷ at slot4 (regular)
			mx.polyvec_tomont(slot4, l);                             // ŷ ← ŷ·R so the matrix kernel's R⁻¹ leaves regular result
			mx.polyvec_matrix_pointwise_montgomery(slot5, matOff, slot4, k, l);
			mx.polyvec_invntt(slot5, k);
			mx.polyvec_caddq(slot5, k);                              // w canonical at slot5

			// Line 13: w₁ ← HighBits(w) at slot4 (overwrites ŷ, no longer needed)
			mx.polyvec_highbits(slot4, slot5, k, gamma2);

			// Line 14: c̃ ← H(μ ‖ w₁Encode(w₁), λ/4) ─────────────────────
			// w₁Encode = Σ SimpleBitPack(w₁[i], (q-1)/(2γ₂) - 1) — width per param set.
			for (let r = 0; r < k; r++) {
				mx.simple_bit_pack(xofOff + r * w1PolyBytes, slot4 + r * POLY_BYTES, w1Bitlen);
			}
			// w₁ from a rejected iteration is secret-derived (HighBits
			// of NTT⁻¹(Â · NTT(y)); y came from ρ''). Wipe the prior
			// slice before reslicing fresh bytes for this iteration.
			if (w1Bytes) wipe(w1Bytes);
			w1Bytes = mlMem.slice(xofOff, xofOff + w1TotalBytes);
			const cTildeNew = shake256HashConcat(sx, [mu, w1Bytes], lambdaOver4);
			cTilde.set(cTildeNew);
			// cTildeNew is public-derivable (c̃ ships inside σ) but TS-side
			// hygiene matches the rest of the per-iteration scratch.
			wipe(cTildeNew);

			// Line 15: c ← SampleInBall(c̃) at polySlot1 (time domain) ──
			// FIPS 204 Algorithm 29: SHAKE256(c̃) drives sign-bits (first
			// 8 squeeze bytes) and position selection (subsequent bytes).
			// Resumable kernel — squeeze further blocks until all τ samples
			// land. polySlot0 is signs scratch; xofOff is position bytes.
			mlMem.fill(0, polySlot1, polySlot1 + POLY_BYTES);
			sx.shake256Init();
			sha3Absorb(sx, cTilde);
			sx.shakePad();

			sx.shakeSqueezeBlock();
			mlMem.set(sha3Mem.subarray(sha3OutOff,     sha3OutOff +   8), polySlot0);
			mlMem.set(sha3Mem.subarray(sha3OutOff + 8, sha3OutOff + SHAKE256_RATE), xofOff);
			let sampleI = mx.sample_in_ball(polySlot1, polySlot0, xofOff, SHAKE256_RATE - 8, tau, 256 - tau);
			while (sampleI < 256) {
				sx.shakeSqueezeBlock();
				mlMem.set(sha3Mem.subarray(sha3OutOff, sha3OutOff + SHAKE256_RATE), xofOff);
				sampleI = mx.sample_in_ball(polySlot1, polySlot0, xofOff, SHAKE256_RATE, tau, sampleI);
			}

			// Line 16: ĉ ← NTT(c) — single polynomial in place ─────────
			mx.ntt(polySlot1);

			// Line 17: ⟨cs₁⟩ ← NTT⁻¹(ĉ ∘ ŝ₁) at slot4 (overwrites w₁) ──
			// Phase 3 has poly_pointwise_montgomery (per-poly) and
			// polyvec_pointwise_montgomery (per-vec, expects same-length
			// input). For c·s₁ where c is one polynomial and s₁ is a
			// length-ℓ vec, drive a TS-side loop over the poly variant.
			for (let r = 0; r < l; r++) {
				mx.poly_pointwise_montgomery(
					slot4 + r * POLY_BYTES,
					polySlot1,
					slot0 + r * POLY_BYTES,
				);
			}
			mx.polyvec_invntt(slot4, l);

			// Line 19: z ← y + ⟨cs₁⟩ at slot4 ──────────────────────────
			mx.polyvec_add(slot4, slot3, slot4, l);
			// ‖z‖∞ check needs centered residues. polyvec_reduce produces
			// (-q/2, q/2]; chknorm is correct on that form per phase-3 contract.
			mx.polyvec_reduce(slot4, l);

			// Line 21 (first half): ‖z‖∞ ≥ γ₁ − β ⇒ reject ─────────────
			if (mx.polyvec_chknorm(slot4, gamma1 - beta, l) !== 0) {
				kappa += l;
				continue;
			}

			// Line 18: ⟨cs₂⟩ ← NTT⁻¹(ĉ ∘ ŝ₂) at slot3 (overwrites y_time) ─
			for (let r = 0; r < k; r++) {
				mx.poly_pointwise_montgomery(
					slot3 + r * POLY_BYTES,
					polySlot1,
					slot1 + r * POLY_BYTES,
				);
			}
			mx.polyvec_invntt(slot3, k);
			mx.polyvec_reduce(slot3, k);
			mx.polyvec_caddq(slot3, k);                              // canonical for sub→reduce→caddq round-trip

			// Line 20: r₀ ← LowBits(w − ⟨cs₂⟩). Compute (w − ⟨cs₂⟩) at
			// slot5 (overwrites w — we no longer need w independently;
			// downstream both r₀ and h derive from w − ⟨cs₂⟩).
			mx.polyvec_sub(slot5, slot5, slot3, k);
			mx.polyvec_reduce(slot5, k);
			mx.polyvec_caddq(slot5, k);                              // canonical for lowbits + make_hint

			// r₀ at slot3 (overwrites ⟨cs₂⟩, no longer needed)
			mx.polyvec_lowbits(slot3, slot5, k, gamma2);

			// Line 21 (second half): ‖r₀‖∞ ≥ γ₂ − β ⇒ reject ──────────
			if (mx.polyvec_chknorm(slot3, gamma2 - beta, k) !== 0) {
				kappa += l;
				continue;
			}

			// Line 24: ⟨ct₀⟩ ← NTT⁻¹(ĉ ∘ t̂₀) at slot3 (overwrites r₀) ─
			for (let r = 0; r < k; r++) {
				mx.poly_pointwise_montgomery(
					slot3 + r * POLY_BYTES,
					polySlot1,
					slot2 + r * POLY_BYTES,
				);
			}
			mx.polyvec_invntt(slot3, k);
			mx.polyvec_reduce(slot3, k);                             // centered for chknorm

			// Line 26 (first half): ‖⟨ct₀⟩‖∞ ≥ γ₂ ⇒ reject. Note the
			// bound is γ₂ (NOT γ₂ − β) — the missing β subtract is a
			// common copy/paste error.
			if (mx.polyvec_chknorm(slot3, gamma2, k) !== 0) {
				kappa += l;
				continue;
			}
			mx.polyvec_caddq(slot3, k);                              // canonical for make_hint z input

			// Line 25: h ← MakeHint(−⟨ct₀⟩, w − ⟨cs₂⟩ + ⟨ct₀⟩).
			// MakeHint(z, r) = [HighBits(r) ≠ HighBits(r + z)] is symmetric
			// in (r, r+z), so passing z = ⟨ct₀⟩ and r = w − ⟨cs₂⟩ produces
			// h[i] = [HighBits(w − ⟨cs₂⟩) ≠ HighBits(w − ⟨cs₂⟩ + ⟨ct₀⟩)] —
			// the same predicate. Avoids the explicit −⟨ct₀⟩ canonicalise.
			// polyvec_make_hint aliases-safe with z; h overwrites slot3.
			const popcount = mx.polyvec_make_hint(slot3, slot3, slot5, k, gamma2);

			// Line 26 (second half): popcount > ω ⇒ reject ─────────────
			if (popcount > omega) {
				kappa += l;
				continue;
			}

			// All four hard checks passed — encode signature.
			// Line 32: σ ← sigEncode(c̃, z mod± q, h) — Algorithm 26.
			mlMem.set(cTilde, sigOff);                               // c̃ (λ/4 bytes)
			const sigZOff = sigOff + lambdaOver4;
			for (let r = 0; r < l; r++) {
				// z is in centered residues post polyvec_reduce; bit_pack(γ₁-1, γ₁)
				// expects [-(γ₁-1), γ₁]. ‖z‖∞ < γ₁ - β guarantees range.
				mx.bit_pack(sigZOff + r * zPolyBytes, slot4 + r * POLY_BYTES, gamma1 - 1, gamma1);
			}
			mx.hint_bit_pack(sigZOff + l * zPolyBytes, slot3, k, omega);

			success = true;
			break;
		}

		if (!success) {
			throw new Error(
				`leviathan-crypto: ML-DSA signing exceeded ${MAX_SIGN_ITERATIONS} rejection-sample iterations`
				+ ' (FIPS 204 Appendix C suggests min 814; bound here gives ~20% headroom)',
			);
		}

		// Slice σ before any wipes — slice copies, so wipes after this
		// don't touch the returned Uint8Array.
		const sig = mlMem.slice(sigOff, sigOff + sigBytes);
		return sig;
	} finally {
		// ── Wipe scratch (FIPS 204 §3.6.3 — Intermediate Values) ────────
		// Runs on the success path AND on any throw (sk-range violation,
		// loop-bound exceedance, kernel error). Without this in finally,
		// an early throw between skDecode and sigEncode would leave
		// sk-derived state in WASM memory.
		//
		// All polyvec slots 0..5 held secret or secret-derived values:
		// ŝ₁/ŝ₂/t̂₀ are NTT-domain copies of secret-key components;
		// y, ⟨cs₁⟩/⟨cs₂⟩/⟨ct₀⟩, w − ⟨cs₂⟩, r₀, z, h are all per-iteration
		// secret-derived intermediates. Highest severity: t̂₀ (recovers
		// the low bits of t — secret part of sk) and y (used in computing
		// z; compromise leaks rejection-sampling state).
		mlMem.fill(0, mx.getPolyvecSlotBase(), mx.getPolyvecSlotBase() + 6 * mx.getPolyvecSlotSize());
		// Poly slots: signs (POLY_SLOT_0, public — c̃ derived), c (POLY_SLOT_1,
		// public — derivable from c̃), and POLY_SLOT_7 holding the last
		// matrix-vector product partial (secret-derived via y_ntt). Wipe all
		// 8 contiguous slots in one fill — cheap and avoids residue gaps.
		mlMem.fill(0, polySlotBase, polySlotBase + 8 * POLY_BYTES);
		// XOF/PRF region last held SampleInBall position bytes (public, c̃-derived)
		// or ExpandMask outputs (secret, ρ''-derived) on the rejected path.
		mlMem.fill(0, xofOff, xofOff + 8192);
		// Public-derivable but cheap to wipe for hygiene:
		mlMem.fill(0, cTildeOff, cTildeOff + 64);
		mlMem.fill(0, msgRepOff, msgRepOff + 64);
		// Defensive: SEED, TR, SK regions — Sign_internal does not write
		// to these (we extract sk components via TS subarrays), but a
		// prior op may have left residue. Cheap wipe closes that window.
		mlMem.fill(0, seedOff, seedOff + 128);
		mlMem.fill(0, trOff,   trOff   + 64);
		mlMem.fill(0, skOff,   skOff   + params.skBytes);

		// SHA3 module: STATE / INPUT / OUT all carried K, μ, ρ'', c̃, and
		// the SampleInBall stream. Wipe before returning.
		sx.wipeBuffers();

		// TS-side scratch — wipe last so any wipe()-throws don't skip
		// the WASM cleanup above.
		if (mu)      wipe(mu);
		if (rhoPP)   wipe(rhoPP);
		if (cTilde)  wipe(cTilde);
		if (w1Bytes) wipe(w1Bytes);
	}
}
