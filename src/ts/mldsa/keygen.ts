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
// src/ts/mldsa/keygen.ts
//
// FIPS 204 §6.1 Algorithm 6, ML-DSA.KeyGen_internal.
// Implements the deterministic xi-seeded key generator used by both the
// public keygen() (random ξ) and keygenDerand(ξ) entry points. Output is
// (pk, sk) byte-encoded per Algorithms 22 (pkEncode) and 24 (skEncode).
//
// Slot map (matrix slot + 6 polyvec slots):
//   MATRIX_SLOT      Â (matrix, k×ℓ polynomials in NTT domain, public)
//   POLYVEC_SLOT_0   s₁ (time domain, preserved for skEncode bit_pack)
//   POLYVEC_SLOT_1   s₂ (time domain, preserved for skEncode bit_pack)
//   POLYVEC_SLOT_2   t = NTT⁻¹(Â · ŝ₁) + s₂  (intermediate, secret-derived)
//   POLYVEC_SLOT_3   t₁ (high bits of t, public, encoded into pk)
//   POLYVEC_SLOT_4   t₀ (low bits of t, secret, encoded into sk)
//   POLYVEC_SLOT_5   ŝ₁ (NTT-domain Montgomery-form copy of s₁; consumed by
//                       the matrix product, then wiped). Time-domain s₁
//                       must survive in slot 0 for the sk BitPack step.
//
// POLY_SLOT_7 is reserved as scratch by polyvec_pointwise_acc_montgomery
// (called via polyvec_matrix_pointwise_montgomery); we never touch it.

import type { MlDsaExports, Sha3Exports, MlDsaKeyPair } from './types.js';
import type { MlDsaParams } from './params.js';
import { wipe } from '../utils.js';
import { shake256HashConcat } from './sha3-helpers.js';
import { expandA, expandS } from './expand.js';

const POLY_BYTES = 1024;
const D          = 13;             // FIPS 204 §4 Table 1, d=13 for all sets

// Bitlen helper. bitlen(n) = floor(log2(n)) + 1 for n > 0. For ML-DSA we
// only ever feed it positive n, so the n=0 branch is a defensive return.
function bitlen(n: number): number {
	let b = 0;
	let x = n;
	while (x > 0) {
		b++; x >>>= 1;
	}
	return b;
}

/**
 * ML-DSA.KeyGen_internal, FIPS 204 Algorithm 6.
 *
 * Input  ξ (32 bytes): the keygen seed. Produced internally by `keygen()`
 *                      via `randomBytes(32)`, or supplied by `keygenDerand`.
 * Output (pk, sk) byte-encoded per Alg 22 (pkEncode) and Alg 24 (skEncode).
 *
 * Wipe contract on return: every WASM region that held a secret or
 * secret-derived intermediate is zeroed. Public regions (matrix Â, t₁,
 * pk, ρ) are deliberately not wiped, they can be re-derived from the
 * returned pk/sk anyway. The caller is expected to wipe the local ξ
 * buffer it allocated; this function does not own that buffer.
 */
export function mldsaKeygenInternal(
	mx: MlDsaExports,
	sx: Sha3Exports,
	params: MlDsaParams,
	xi: Uint8Array,
): MlDsaKeyPair {
	const { k, l, eta, paramSet, pkBytes, skBytes } = params;
	const mlMem = new Uint8Array(mx.memory.buffer);

	// ── Slot offsets ────────────────────────────────────────────────────
	const matOff    = mx.getMatrixSlot();
	const s1Off     = mx.getPolyvecSlot0();
	const s2Off     = mx.getPolyvecSlot1();
	const tOff      = mx.getPolyvecSlot2();
	const t1Off     = mx.getPolyvecSlot3();
	const t0Off     = mx.getPolyvecSlot4();
	const s1NttOff  = mx.getPolyvecSlot5();
	const seedOff   = mx.getSeedOffset();
	const pkOff     = mx.getPkOffset();
	const skOff     = mx.getSkOffset();
	const trOff     = mx.getTrOffset();
	const xofOff    = mx.getXofPrfOffset();

	// Layout cross-check at runtime: confirm the matrix-slot sizing covers
	// this parameter set's k·ℓ polys. Cheap ratchet against future changes
	// to buffers.ts that might shrink the region.
	const matSize = mx.getMatrixSlotSize();
	if (k * l * POLY_BYTES > matSize)
		throw new Error(
			`leviathan-crypto: mldsa MATRIX_SLOT too small for ${paramSet} `
			+ `(needs ${k * l * POLY_BYTES}, have ${matSize})`,
		);

	let rho:      Uint8Array | undefined;
	let rhoPrime: Uint8Array | undefined;
	let kRand:    Uint8Array | undefined;
	let seed128:  Uint8Array | undefined;

	try {
		// ── Step 1: H(ξ ‖ k_byte ‖ ℓ_byte, 1024 bits) → ρ‖ρ′‖K ─────────
		// FIPS 204 §6.1 Algorithm 6 line 1. The k/ℓ domain-separator bytes
		// are the post-IPD addition (FIPS 204 §D.3) defending against
		// cross-parameter-set seed reuse, IntegerToBytes(k,1) and
		// IntegerToBytes(ℓ,1).
		const kByte = new Uint8Array([k & 0xFF]);
		const lByte = new Uint8Array([l & 0xFF]);
		seed128 = shake256HashConcat(sx, [xi, kByte, lByte], 128);

		// Mirror H output into the WASM SEED region. This isn't strictly
		// required (we only consume ρ/ρ′/K via TS-side slices below) but
		// it lets the keygen-scratch-wipe gate verify that the SEED region
		// is wiped, regardless of whether we pre-staged it. Wiped on exit.
		mlMem.set(seed128, seedOff);

		// Split: ρ(32) ‖ ρ′(64) ‖ K(32). Slice copies isolate each piece
		// from the seed128 buffer so we can scrub each at known life-end.
		rho      = seed128.slice(0,   32);
		rhoPrime = seed128.slice(32,  96);
		kRand    = seed128.slice(96, 128);

		// ── Step 2: Â ← ExpandA(ρ) ────────────────────────────────────
		// FIPS 204 Algorithm 32. Output is in NTT domain, regular form.
		expandA(mx, sx, params, rho, matOff);

		// ── Step 3: (s₁, s₂) ← ExpandS(ρ′) ────────────────────────────
		// FIPS 204 Algorithm 33. Time-domain. expandS wipes its local
		// seed scratch on exit.
		expandS(mx, sx, params, rhoPrime, s1Off, s2Off);

		// ── Step 4: t ← NTT⁻¹(Â · NTT(s₁)) + s₂ ───────────────────────
		// FIPS 204 Algorithm 6 line 5. Stages:
		//   (a) Copy s₁ → ŝ₁-slot. Time-domain s₁ in slot_0 must survive
		//       for the BitPack step in skEncode (Algorithm 24); the
		//       NTT/tomont/multiply chain destroys its argument.
		//   (b) NTT(ŝ₁) in place, regular form.
		//   (c) tomont(ŝ₁): each coefficient ×R so that the subsequent
		//       pointwise_montgomery's R⁻¹ leaves a regular-form product.
		//   (d) Matrix-vector product Â·ŝ₁ → polyvec_slot_2.
		//   (e) NTT⁻¹ in place → time-domain Â·s₁.
		//   (f) Add s₂ coefficient-wise.
		//   (g) Reduce + caddq so coefficients are canonical [0, q-1],
		//       required by power2round per the WASM polynomial-layer contract.
		mlMem.copyWithin(s1NttOff, s1Off, s1Off + l * POLY_BYTES);
		mx.polyvec_ntt(s1NttOff, l);
		mx.polyvec_tomont(s1NttOff, l);
		mx.polyvec_matrix_pointwise_montgomery(tOff, matOff, s1NttOff, k, l);
		mx.polyvec_invntt(tOff, k);
		mx.polyvec_add(tOff, tOff, s2Off, k);
		mx.polyvec_reduce(tOff, k);
		mx.polyvec_caddq(tOff, k);

		// ── Step 5: (t₁, t₀) ← Power2Round(t, d) ──────────────────────
		// FIPS 204 Algorithm 35. Per-coefficient on the canonical-residue
		// polyvec t.
		mx.polyvec_power2round(t1Off, t0Off, tOff, k);

		// ── Step 6: pk ← pkEncode(ρ, t₁) ──────────────────────────────
		// FIPS 204 Algorithm 22. pk = ρ ‖ Σ SimpleBitPack(t₁[i], 2^c-1)
		// where c = bitlen(q-1) - d = 23 - 13 = 10 → 320 bytes per poly.
		const t1Bitlen = bitlen(8380417 - 1) - D;   // 23 - 13 = 10
		const t1PolyBytes = (256 * t1Bitlen) >> 3;  // 320
		mlMem.set(rho, pkOff);
		for (let i = 0; i < k; i++) {
			mx.simple_bit_pack(
				pkOff + 32 + i * t1PolyBytes,
				t1Off + i * POLY_BYTES,
				t1Bitlen,
			);
		}

		// ── Step 7: tr ← H(pk, 512 bits) ──────────────────────────────
		// 64-byte SHAKE256 of the public key. Cached in sk so signing
		// doesn't have to re-derive it.
		const pkBytesView = mlMem.subarray(pkOff, pkOff + pkBytes);
		const tr = shake256HashConcat(sx, [pkBytesView], 64);
		mlMem.set(tr, trOff);
		wipe(tr);

		// ── Step 8: sk ← skEncode(ρ, K, tr, s₁, s₂, t₀) ───────────────
		// FIPS 204 Algorithm 24. Layout:
		//   ρ(32) ‖ K(32) ‖ tr(64) ‖
		//   BitPack(s₁[i], η, η)    × ℓ   each = 32·bitlen(2η)
		//   BitPack(s₂[i], η, η)    × k
		//   BitPack(t₀[i], 2^(d-1)-1, 2^(d-1))  × k    each = 32·d = 416
		const etaBitlen   = bitlen(2 * eta);                 // 3 (η=2) or 4 (η=4)
		const etaPolyBytes = (256 * etaBitlen) >> 3;          // 96 or 128
		const t0PolyBytes  = (256 * D) >> 3;                  // 416
		const t0LowEdge    = (1 << (D - 1)) - 1;              // 4095
		const t0HighEdge   = (1 << (D - 1));                  // 4096

		mlMem.set(rho,      skOff);
		mlMem.set(kRand,    skOff + 32);
		mlMem.set(mlMem.subarray(trOff, trOff + 64), skOff + 64);

		let off = skOff + 32 + 32 + 64;  // = skOff + 128
		for (let i = 0; i < l; i++) {
			mx.bit_pack(off + i * etaPolyBytes, s1Off + i * POLY_BYTES, eta, eta);
		}
		off += l * etaPolyBytes;
		for (let i = 0; i < k; i++) {
			mx.bit_pack(off + i * etaPolyBytes, s2Off + i * POLY_BYTES, eta, eta);
		}
		off += k * etaPolyBytes;
		for (let i = 0; i < k; i++) {
			mx.bit_pack(off + i * t0PolyBytes, t0Off + i * POLY_BYTES, t0LowEdge, t0HighEdge);
		}
		off += k * t0PolyBytes;

		// Sanity: encoded sk length must match the parameter-set size.
		// A miscompute here is the kind of silent failure ACVP eventually
		// catches but the layout assertion catches faster.
		if (off - skOff !== skBytes)
			throw new Error(
				`leviathan-crypto: mldsa skEncode length mismatch for ${paramSet} `
				+ `(wrote ${off - skOff}, expected ${skBytes})`,
			);

		// ── Step 9: slice public outputs out of WASM memory ───────────
		// Use slice() (copy) so the returned arrays are independent of
		// the WASM linear memory we are about to wipe.
		const pk = mlMem.slice(pkOff, pkOff + pkBytes);
		const sk = mlMem.slice(skOff, skOff + skBytes);

		// ── Wipe scratch (FIPS 204 §3.6.3, Intermediate Values) ──────
		// Every region that held secret or secret-derived bytes is
		// zeroed. Public regions (ρ via SEED, pk, MATRIX_SLOT holding Â,
		// POLYVEC_SLOT_3 holding t₁) we leave untouched, they are not
		// secrets, but the SEED region also held ρ′ and K so it gets
		// wiped in full.
		//
		// Severity ranking:
		//   - SEED_OFFSET held ρ′ (expands to s₁/s₂) and K (used in
		//     signing for deterministic per-message randomness). Highest
		//     severity: ρ′ leak ⇒ recoverable signing key from ρ.
		//   - SK_OFFSET holds the encoded sk; also long-lived, but the
		//     caller already received this, no marginal disclosure
		//     beyond keeping it in memory longer than needed.
		//   - POLYVEC_SLOT_0/1/4 held s₁, s₂, t₀ (full secret-key state).
		//   - POLYVEC_SLOT_2 held t (secret-derived; t₀ exposes low bits).
		//   - XOF_PRF_OFFSET held the last SHAKE block, which after
		//     ExpandS contained ρ′-derived bytes.
		// Public regions intentionally skipped: PK, MATRIX_SLOT (Â), t₁.
		mlMem.fill(0, seedOff,   seedOff   + 128);                  // ρ ‖ ρ′ ‖ K
		mlMem.fill(0, trOff,     trOff     + 64);                   // tr (public-derived but no need to keep)
		mlMem.fill(0, skOff,     skOff     + skBytes);              // encoded sk
		mlMem.fill(0, s1Off,     s1Off     + l * POLY_BYTES);       // s₁ (time-domain)
		mlMem.fill(0, s1NttOff,  s1NttOff  + l * POLY_BYTES);       // ŝ₁ (NTT/Montgomery)
		mlMem.fill(0, s2Off,     s2Off     + k * POLY_BYTES);       // s₂
		mlMem.fill(0, tOff,      tOff      + k * POLY_BYTES);       // t
		mlMem.fill(0, t0Off,     t0Off     + k * POLY_BYTES);       // t₀
		mlMem.fill(0, xofOff,    xofOff    + 8192);                 // XOF/PRF scratch

		// SHA3 module's input/state/output regions held ρ′ chunks and
		// the H(ξ‖k‖ℓ) output. Wipe before returning so no residue
		// persists across the public-API boundary.
		sx.wipeBuffers();

		return { verificationKey: pk, signingKey: sk };
	} finally {
		// TS-side scratch, wipe even on early throw.
		if (seed128)  wipe(seed128);
		if (rho)      wipe(rho);
		if (rhoPrime) wipe(rhoPrime);
		if (kRand)    wipe(kRand);
	}
}
