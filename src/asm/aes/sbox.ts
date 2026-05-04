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
// src/asm/aes/sbox.ts
//
// Bitsliced AES S-box (forward only) using the Canright tower-field
// decomposition.
//
// Reference: D. Canright, "A Very Compact S-box for AES", CHES 2005
// §2, §2.1 (chosen normal basis: ν=0xEC, N=0xBC, W=0xBD), §3 (gate
// optimizations), and Käsper-Schwabe 2009 §4.2 (uses Canright's
// decomposition for software bitslicing).
//
// Operates in place on 8 v128 registers in BITSLICED_STATE_OFFSET.
// state[k] holds bit-k of every byte across all 8 parallel blocks
// (k=0 LSB, k=7 MSB; Käsper-Schwabe §4.1). Sub-results are spilled to
// CANRIGHT_SCRATCH_OFFSET v128 slots.
//
// Algorithm: s = (M·X)·gf256_inv(X⁻¹·a) ⊕ b
//   where X is the standard-basis representation of the tower basis
//   (Y_i·Z_j·W_k tensor products, computed via direct GF(2⁸) arithmetic
//   from Canright §2.1's [Y¹⁶,Y]=[0xFE,0xFF], [Z⁴,Z]=[0x5D,0x5C],
//   [W²,W]=[0xBC,0xBD]), M is the AES affine matrix (Canright §2),
//   and b = 0x63 is the affine constant (Canright §2 / FIPS 197 §5.1.1).

import {
	BITSLICED_STATE_OFFSET,
	CANRIGHT_SCRATCH_OFFSET,
} from './buffers'

// ── Bitsliced state slot helpers ────────────────────────────────────────────

/** Load v128 register at bit-position k of bitsliced state. k ∈ {0..7}. */
@inline function bget(k: i32): v128 {
	return v128.load(BITSLICED_STATE_OFFSET + (k << 4));
}

/** Store v128 v at bit-position k of bitsliced state. k ∈ {0..7}. */
@inline function bset(k: i32, v: v128): void {
	v128.store(BITSLICED_STATE_OFFSET + (k << 4), v);
}

/** Load scratch v128 slot i. i ∈ {0..63}. */
@inline function cget(i: i32): v128 {
	return v128.load(CANRIGHT_SCRATCH_OFFSET + (i << 4));
}

/** Store scratch v128 slot i. i ∈ {0..63}. */
@inline function cset(i: i32, v: v128): void {
	v128.store(CANRIGHT_SCRATCH_OFFSET + (i << 4), v);
}

// ── GF(2⁴) helpers (each "bit" is one v128) ─────────────────────────────────
//
// A GF(2²) element is represented as 2 v128's (W²-coord, W-coord). A GF(2⁴)
// element is 4 v128's, structured as (Γ₁_W², Γ₁_W, Γ₀_W², Γ₀_W) from index 0
// (high) to 3 (low). A GF(2⁸) element in subfield basis is 8 v128's structured
// as 4 high (γ₁) + 4 low (γ₀).

/**
 * GF(2²) multiplication, normal basis [W², W] with W²·W = 1, W²·W² = W,
 * W·W = W². Reference: Canright 2005 §2.1 (closed-form derivation in
 * design notes §6.3): result_W² = a₁b₁ ⊕ e, result_W = a₀b₀ ⊕ e where
 * e = a₀b₁ ⊕ a₁b₀, with a₀ = W²-coord and a₁ = W-coord.
 *
 * Writes 2 v128's to scratch slots [out, out+1].
 */
@inline function gf4_mul_to(
	out: i32,
	a0: v128, a1: v128,
	b0: v128, b1: v128,
): void {
	const e = v128.xor(v128.and(a0, b1), v128.and(a1, b0));
	cset(out,     v128.xor(v128.and(a1, b1), e));
	cset(out + 1, v128.xor(v128.and(a0, b0), e));
}

/**
 * GF(2⁴) multiplication, normal basis [Z⁴, Z] over GF(2²), with norm N = W².
 * Reference: Canright 2005 §2.1 (Fig 3 / eq 4 specialised to the chosen
 * normal basis). Composes three GF(2²) multiplications and one N-scaling
 * via the Karatsuba-like identity:
 *   result_Z⁴ = N·(Γ₁⊕Γ₀)·(Δ₁⊕Δ₀) ⊕ Γ₁·Δ₁
 *   result_Z  = N·(Γ₁⊕Γ₀)·(Δ₁⊕Δ₀) ⊕ Γ₀·Δ₀
 *
 * Writes 4 v128's to scratch slots [out..out+3].
 */
@inline function gf16_mul_to(
	out: i32,
	a0: v128, a1: v128, a2: v128, a3: v128,
	b0: v128, b1: v128, b2: v128, b3: v128,
): void {
	// (Γ₁ ⊕ Γ₀) for both operands — pair sums in GF(2²).
	const sa0 = v128.xor(a0, a2);
	const sa1 = v128.xor(a1, a3);
	const sb0 = v128.xor(b0, b2);
	const sb1 = v128.xor(b1, b3);
	// φ = gf4_mul(Γ₁⊕Γ₀, Δ₁⊕Δ₀)
	const ep   = v128.xor(v128.and(sa0, sb1), v128.and(sa1, sb0));
	const phi0 = v128.xor(v128.and(sa1, sb1), ep);
	const phi1 = v128.xor(v128.and(sa0, sb0), ep);
	// F = N ⊗ φ = (φ₁, φ₀ ⊕ φ₁)  — Canright eq 8.
	const F0 = phi1;
	const F1 = v128.xor(phi0, phi1);
	// Γ₁·Δ₁ — gf4_mul(a₀_high pair, b₀_high pair).
	const eh = v128.xor(v128.and(a0, b1), v128.and(a1, b0));
	const ah0 = v128.xor(v128.and(a1, b1), eh);
	const ah1 = v128.xor(v128.and(a0, b0), eh);
	// Γ₀·Δ₀ — gf4_mul(a₀_low pair, b₀_low pair).
	const el = v128.xor(v128.and(a2, b3), v128.and(a3, b2));
	const al0 = v128.xor(v128.and(a3, b3), el);
	const al1 = v128.xor(v128.and(a2, b2), el);
	// c_Z⁴ = F ⊕ Γ₁Δ₁; c_Z = F ⊕ Γ₀Δ₀.
	cset(out + 0, v128.xor(F0, ah0));
	cset(out + 1, v128.xor(F1, ah1));
	cset(out + 2, v128.xor(F0, al0));
	cset(out + 3, v128.xor(F1, al1));
}

/**
 * Combined "scale square by ν" in GF(2⁴), normal basis [Z⁴, Z], with
 * ν = N²Z. Reference: Canright 2005 §2.1 eq 7 (closed form):
 *   ν ⊗ (Γ₁Z⁴ + Γ₀Z)² = (Γ₁ ⊕ Γ₀)² Z⁴ + (N ⊗ Γ₀)² Z
 *
 * Squaring in GF(2²) is a free bit-swap; scaling by N is "(g₀, g₀⊕g₁)".
 *
 * Writes 4 v128's to scratch slots [out..out+3].
 */
@inline function gf16_sq_scale_nu_to(
	out: i32,
	a0: v128, a1: v128, a2: v128, a3: v128,
): void {
	// sum = Γ₁ ⊕ Γ₀ = (a0⊕a2, a1⊕a3) in GF(2²).
	const s0 = v128.xor(a0, a2);
	const s1 = v128.xor(a1, a3);
	// sum² = swap(sum) — gf4_sq is just (W²-coord, W-coord) ↔ (W-coord, W²-coord).
	// sum² placed at out+0 (Z⁴-coord W² lane), out+1 (Z⁴-coord W lane).
	cset(out + 0, s1);
	cset(out + 1, s0);
	// (N ⊗ Γ₀) = (a3, a2 ⊕ a3) — gf4_scale_N(a2, a3) per Canright eq 8.
	// Then square via swap ⇒ ((a2⊕a3), a3).
	cset(out + 2, v128.xor(a2, a3));
	cset(out + 3, a3);
}

// ── Composed S-box ──────────────────────────────────────────────────────────

/**
 * Forward AES S-box on 8 parallel blocks in bitsliced layout.
 *
 * Reads 8 v128 from BITSLICED_STATE_OFFSET; writes 8 v128 back to the
 * same offsets. Uses CANRIGHT_SCRATCH_OFFSET for intermediates.
 *
 * Reference: Canright 2005 §2-§4 + Käsper-Schwabe 2009 §4.2. The
 * pipeline is:
 *
 *   1. Apply X⁻¹ (standard polynomial basis → tower normal basis).
 *   2. Compute γ⁻¹ in GF(2⁸) via tower decomposition (Canright eq 5).
 *   3. Apply M·X (back to standard basis, with AES affine M folded in).
 *   4. XOR with affine constant b = 0x63 (= bit-flip on bits 0,1,5,6).
 *
 * The matrices X (and X⁻¹, M·X) are derived in design notes §6.2 from
 * the basis-element tensor products Y_i · Z_j · W_k, computed in GF(2⁸)
 * standard polynomial basis. The AES affine matrix M and constant b
 * are from Canright §2 (= FIPS 197 §5.1.1 eq 5.4 with bit-7-MSB
 * convention).
 */
export function sboxBitsliced(): void {
	// Load bitsliced state. s[k] = bit-k slice (k=0 LSB, k=7 MSB) per
	// Käsper-Schwabe §4.1.
	const s0 = bget(0);
	const s1 = bget(1);
	const s2 = bget(2);
	const s3 = bget(3);
	const s4 = bget(4);
	const s5 = bget(5);
	const s6 = bget(6);
	const s7 = bget(7);

	// ── Step 1: X⁻¹ — standard basis → tower normal basis ──────────────
	// Reference: design notes §6.2. X⁻¹ derived by Gaussian elimination
	// over GF(2) on the columns of X, where X column i = (Y_(i₂)·Z_(i₁)·W_(i₀))
	// in standard polynomial basis.
	// Output bit p (subfield) = XOR over standard bits q where X⁻¹[p][q]=1.
	const t0 = v128.xor(v128.xor(v128.xor(s0, s1), v128.xor(s2, s3)), s6);
	const t1 = v128.xor(v128.xor(s0, s5), s6);
	const t2 = s0;
	const t3 = v128.xor(v128.xor(v128.xor(s0, s1), v128.xor(s3, s4)), s7);
	const t4 = v128.xor(v128.xor(v128.xor(s0, s5), s6), s7);
	const t5 = v128.xor(v128.xor(s0, s1), v128.xor(s5, s6));
	const t6 = v128.xor(v128.xor(s0, s4), v128.xor(s5, s6));
	const t7 = v128.xor(v128.xor(v128.xor(s0, s1), s2), v128.xor(v128.xor(s5, s6), s7));

	// Subfield-byte bit assignment (high-to-low): t7,t6 = γ₁_Γ₁ (W²,W) ;
	// t5,t4 = γ₁_Γ₀ ; t3,t2 = γ₀_Γ₁ ; t1,t0 = γ₀_Γ₀.
	// So γ₁ = (t7, t6, t5, t4) and γ₀ = (t3, t2, t1, t0).

	// ── Step 2a: γ₁γ₀ — GF(2⁴) multiply ──────────────────────────────
	// Slots 8..11 = γ₁ · γ₀.
	gf16_mul_to(8, t7, t6, t5, t4, t3, t2, t1, t0);

	// ── Step 2b: ν · (γ₁⊕γ₀)² — Canright eq 7 ────────────────────────
	// Sum γ₁⊕γ₀ in GF(2⁴) is (t7⊕t3, t6⊕t2, t5⊕t1, t4⊕t0).
	// Slots 16..19 = ν · sum².
	gf16_sq_scale_nu_to(
		16,
		v128.xor(t7, t3),
		v128.xor(t6, t2),
		v128.xor(t5, t1),
		v128.xor(t4, t0),
	);

	// ── Step 2c: θ = γ₁γ₀ ⊕ ν·(γ₁⊕γ₀)²  ──────────────────────────────
	// Canright eq 5 specialised to τ = 1.
	const th0 = v128.xor(cget(8),  cget(16));
	const th1 = v128.xor(cget(9),  cget(17));
	const th2 = v128.xor(cget(10), cget(18));
	const th3 = v128.xor(cget(11), cget(19));

	// ── Step 2d: θ⁻¹ = gf16_inv(θ) ───────────────────────────────────
	// Canright eq 5 at the GF(2⁴) level. θ = Θ₁Z⁴ + Θ₀Z; inversion uses
	// θ_inner = Θ₁Θ₀ + N(Θ₁⊕Θ₀)² in GF(2²), then the GF(2²) inverse =
	// gf4_sq (squaring) since GF(2²)* has order 3.
	// Θ₁ = (th0, th1) ; Θ₀ = (th2, th3).
	// Θ₁Θ₀ = gf4_mul to slots 20..21.
	gf4_mul_to(20, th0, th1, th2, th3);
	// (Θ₁ ⊕ Θ₀)² in GF(2²) is gf4_sq(swap) = (th0⊕th2, th1⊕th3) swapped
	//   → ((th1⊕th3), (th0⊕th2)).
	const sum_sq0 = v128.xor(th1, th3);
	const sum_sq1 = v128.xor(th0, th2);
	// N · (Θ₁⊕Θ₀)² in GF(2²) per Canright eq 8 = (sum_sq1, sum_sq0⊕sum_sq1).
	const Ns0 = sum_sq1;
	const Ns1 = v128.xor(sum_sq0, sum_sq1);
	// θ_inner = Θ₁Θ₀ ⊕ N·(Θ₁⊕Θ₀)² in GF(2²).
	const ti0 = v128.xor(cget(20), Ns0);
	const ti1 = v128.xor(cget(21), Ns1);
	// θ_inner⁻¹ = gf4_sq(ti) = (ti1, ti0).
	const tin0 = ti1;
	const tin1 = ti0;
	// Output of GF(2⁴) inverter: Θinv_Z⁴ = θ_inner⁻¹ · Θ₀ ; Θinv_Z = θ_inner⁻¹ · Θ₁.
	// (Canright eq 5 at GF(2⁴) level: output Z⁴ coord = θinv · input Z coord.)
	gf4_mul_to(22, tin0, tin1, th2, th3);    // slots 22..23 = Θinv_Z⁴
	gf4_mul_to(24, tin0, tin1, th0, th1);    // slots 24..25 = Θinv_Z
	// θ⁻¹ in GF(2⁴) = (slots 22..25) = (Θinv_Z⁴_W², Θinv_Z⁴_W, Θinv_Z_W², Θinv_Z_W).

	// ── Step 2e: δ₁ = θ⁻¹ · γ₀ ; δ₀ = θ⁻¹ · γ₁ ───────────────────────
	// Canright eq 5 at GF(2⁸) level: γ⁻¹ = δ₁Y¹⁶ + δ₀Y where δ₁ = θ⁻¹·γ₀,
	// δ₀ = θ⁻¹·γ₁. (Note the swap: high output coord uses low input coord.)
	const ti_a = cget(22);
	const ti_b = cget(23);
	const ti_c = cget(24);
	const ti_d = cget(25);
	gf16_mul_to(28, ti_a, ti_b, ti_c, ti_d, t3, t2, t1, t0);   // δ₁ = θinv · γ₀
	gf16_mul_to(32, ti_a, ti_b, ti_c, ti_d, t7, t6, t5, t4);   // δ₀ = θinv · γ₁

	// Subfield output u (8 bits, high-to-low): u[7..4] = δ₁ ; u[3..0] = δ₀.
	const u7 = cget(28);
	const u6 = cget(29);
	const u5 = cget(30);
	const u4 = cget(31);
	const u3 = cget(32);
	const u2 = cget(33);
	const u1 = cget(34);
	const u0 = cget(35);

	// ── Step 3+4: M·X and ⊕ b ────────────────────────────────────────
	// Reference: design notes §6.2. M·X is the AES affine matrix M (Canright
	// §2) composed with the basis change X. Output bit p (standard) = XOR
	// over subfield bits q where (M·X)[p][q]=1, then XOR with bit p of b=0x63.
	// b = 0x63 = 01100011 → bits {0,1,5,6} are 1; we apply v128.not on those.
	const allOnes = v128.not(v128.splat<i32>(0));

	// out[0] = u[1] ⊕ u[4] ⊕ u[6] ⊕ b₀(=1)
	bset(0, v128.xor(v128.xor(v128.xor(u1, u4), u6), allOnes));
	// out[1] = u[1] ⊕ u[4] ⊕ u[5] ⊕ b₁(=1)
	bset(1, v128.xor(v128.xor(v128.xor(u1, u4), u5), allOnes));
	// out[2] = u[0] ⊕ u[2] ⊕ u[3] ⊕ u[5] ⊕ u[6] ⊕ b₂(=0)
	bset(2, v128.xor(v128.xor(v128.xor(u0, u2), u3), v128.xor(u5, u6)));
	// out[3] = u[3] ⊕ u[4] ⊕ u[5] ⊕ u[6] ⊕ u[7] ⊕ b₃(=0)
	bset(3, v128.xor(v128.xor(v128.xor(u3, u4), u5), v128.xor(u6, u7)));
	// out[4] = u[3] ⊕ u[5] ⊕ u[7] ⊕ b₄(=0)
	bset(4, v128.xor(v128.xor(u3, u5), u7));
	// out[5] = u[0] ⊕ u[6] ⊕ b₅(=1)
	bset(5, v128.xor(v128.xor(u0, u6), allOnes));
	// out[6] = u[3] ⊕ u[7] ⊕ b₆(=1)
	bset(6, v128.xor(v128.xor(u3, u7), allOnes));
	// out[7] = u[3] ⊕ u[5] ⊕ b₇(=0)
	bset(7, v128.xor(u3, u5));
}
