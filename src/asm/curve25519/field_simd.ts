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
// src/asm/curve25519/field_simd.ts
//
// GF(2^255-19) field arithmetic, 2-way paired (v128-external) path.
// A "paired field element" packs two independent 5×51-bit field elements
// into 80 bytes, with each limb position occupying one v128 (i64x2) lane
// pair: lane 0 holds element A's limb, lane 1 holds element B's limb.
//
//   offset  0..15  : limb 0 (lane 0 = A[0], lane 1 = B[0])
//   offset 16..31  : limb 1
//   offset 32..47  : limb 2
//   offset 48..63  : limb 3
//   offset 64..79  : limb 4
//
// Operations exported here genuinely use v128 SIMD intrinsics. They are
// consumed by edwards_simd.ts for the dalek-style "parallel formulas"
// approach (Hisil-Wong-Carter-Dawson §3.1 + eprint 2018/098): the
// Edwards addition's many independent additions / subtractions over
// (Y±X), (Z, T), (D ± C) etc. pair cleanly into v128 i64x2 ops,
// halving the field-add / field-sub count.
//
// Multiplication / squaring are intentionally NOT provided in paired
// form: AssemblyScript's v128 intrinsic set lacks a native 64-bit ×
// 64-bit → 128-bit lane multiply, so a paired feMul would need a manual
// 4-piece split via i64x2.extmul_low_i32x4 / extmul_high_i32x4 plus
// carry-tracking via XOR-then-signed-compare workarounds. The resulting
// ~150 lines of dense v128 code only buys a marginal speedup over two
// scalar feMul calls under typical WASM engines (extmul throughput is
// not faster than the i64-mul-plus-split that scalar feMul already
// uses). Per TASK-B's clause "if a v128-paired form genuinely does
// not improve a particular operation, only the non-`_simd` form lands"
// the paired multiplication / squaring forms are NOT shipped; callers
// in edwards_simd.ts use the scalar feMul / feSqr for the four
// independent products in the Hisil-Wong-Carter-Dawson addition and
// rely on this file only for the high-volume additions / subtractions
// / conditional swaps that pair efficiently in v128.

// ── Paired add / sub / neg ──────────────────────────────────────────────────
//
// Each operation reads 5 v128s (one per limb position), performs the
// lane-parallel i64x2 op, and stores 5 v128s. Both lanes evolve
// independently. Limb bounds match the scalar feAdd / feSub semantics
// (canonical inputs produce limbs ≤ 2^52; further ops may grow to ~2^53
// before requiring a reduce-and-carry pass via feMulPair-equivalent).

/** out_pair = a_pair + b_pair (no reduction; each limb is added in v128). */
export function feAddPair(out: i32, a: i32, b: i32): void {
	for (let i: i32 = 0; i < 5; i++) {
		const off: i32 = i << 4
		v128.store(out + off, i64x2.add(v128.load(a + off), v128.load(b + off)))
	}
}

/** out_pair = a_pair - b_pair (per the scalar feSub posture: adds 2p per limb). */
export function feSubPair(out: i32, a: i32, b: i32): void {
	// 2p limb constants per scalar field.ts:
	//   limb 0: 2^52 - 38   = 0xFFFFFFFFFFFDA
	//   limb 1..4: 2^52 - 2 = 0xFFFFFFFFFFFFE
	const TWO_P_0_PAIR:       v128 = i64x2.splat(0xFFFFFFFFFFFDA)
	const TWO_P_NONZERO_PAIR: v128 = i64x2.splat(0xFFFFFFFFFFFFE)
	v128.store(out +  0, i64x2.sub(i64x2.add(v128.load(a +  0), TWO_P_0_PAIR),       v128.load(b +  0)))
	v128.store(out + 16, i64x2.sub(i64x2.add(v128.load(a + 16), TWO_P_NONZERO_PAIR), v128.load(b + 16)))
	v128.store(out + 32, i64x2.sub(i64x2.add(v128.load(a + 32), TWO_P_NONZERO_PAIR), v128.load(b + 32)))
	v128.store(out + 48, i64x2.sub(i64x2.add(v128.load(a + 48), TWO_P_NONZERO_PAIR), v128.load(b + 48)))
	v128.store(out + 64, i64x2.sub(i64x2.add(v128.load(a + 64), TWO_P_NONZERO_PAIR), v128.load(b + 64)))
}

/** out_pair = -a_pair (each lane independently). */
export function feNegPair(out: i32, a: i32): void {
	const TWO_P_0_PAIR:       v128 = i64x2.splat(0xFFFFFFFFFFFDA)
	const TWO_P_NONZERO_PAIR: v128 = i64x2.splat(0xFFFFFFFFFFFFE)
	v128.store(out +  0, i64x2.sub(TWO_P_0_PAIR,       v128.load(a +  0)))
	v128.store(out + 16, i64x2.sub(TWO_P_NONZERO_PAIR, v128.load(a + 16)))
	v128.store(out + 32, i64x2.sub(TWO_P_NONZERO_PAIR, v128.load(a + 32)))
	v128.store(out + 48, i64x2.sub(TWO_P_NONZERO_PAIR, v128.load(a + 48)))
	v128.store(out + 64, i64x2.sub(TWO_P_NONZERO_PAIR, v128.load(a + 64)))
}

// ── Paired copy and unpack helpers ─────────────────────────────────────────

/** Copy a paired field element (80 bytes). */
export function fePairCopy(dst: i32, src: i32): void {
	for (let i: i32 = 0; i < 5; i++) {
		const off: i32 = i << 4
		v128.store(dst + off, v128.load(src + off))
	}
}

/**
 * Unpack a paired field element into two scalar field elements
 * (40 bytes each). Lane 0 (low i64) → eltA, lane 1 (high i64) → eltB.
 */
export function fePairUnpack(eltA: i32, eltB: i32, pair: i32): void {
	for (let i: i32 = 0; i < 5; i++) {
		const v: v128 = v128.load(pair + (i << 4))
		store<i64>(eltA + (i << 3), i64x2.extract_lane(v, 0))
		store<i64>(eltB + (i << 3), i64x2.extract_lane(v, 1))
	}
}

/**
 * Pack two scalar field elements (40 bytes each) into a paired
 * field element (80 bytes). eltA → lane 0, eltB → lane 1.
 */
export function fePairPack(pair: i32, eltA: i32, eltB: i32): void {
	for (let i: i32 = 0; i < 5; i++) {
		const a: i64 = load<i64>(eltA + (i << 3))
		const b: i64 = load<i64>(eltB + (i << 3))
		v128.store(pair + (i << 4), i64x2(a, b))
	}
}

// ── Paired conditional swap ─────────────────────────────────────────────────

/**
 * Conditionally swap two paired field elements based on a single
 * `swap` flag that applies to BOTH lanes in lock-step (per-lane swap
 * flags would defeat the SIMD pairing). When swap=1, a_pair and b_pair
 * are exchanged in linear memory; when swap=0, neither is touched.
 * Constant-time: the v128 XOR-mask-XOR sequence is branch-free.
 */
export function feCondSwapPair(a: i32, b: i32, swap: i32): void {
	const mask:    i64 = -((swap as i64) & 1)
	const maskVec: v128 = i64x2.splat(mask)
	for (let i: i32 = 0; i < 5; i++) {
		const off: i32 = i << 4
		const ai:  v128 = v128.load(a + off)
		const bi:  v128 = v128.load(b + off)
		const t:   v128 = v128.and(maskVec, v128.xor(ai, bi))
		v128.store(a + off, v128.xor(ai, t))
		v128.store(b + off, v128.xor(bi, t))
	}
}
