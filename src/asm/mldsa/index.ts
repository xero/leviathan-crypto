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
// src/asm/mldsa/index.ts
//
// ML-DSA WASM module — public exports.
// FIPS 204 — Module-Lattice-Based Digital Signature Standard.
//
// Phase-3 surface: phase-2 reduce/NTT primitives plus the polynomial layer
// (poly + polyvec arithmetic, bit-pack/unpack encoding, rounding kernels,
// rejection-sampling kernels, SampleInBall). Algorithm-level KeyGen / Sign /
// Verify are TS-orchestrated in phase 4.

// ── Buffer layout (buffers.ts) ──────────────────────────────────────────────

export {
	getModuleId, getMemoryPages,
	getPolySlotBase, getPolySlotSize,
	getPolySlot0, getPolySlot1, getPolySlot2, getPolySlot3,
	getPolySlot4, getPolySlot5, getPolySlot6, getPolySlot7,
	getMatrixSlot, getMatrixSlotSize,
	getPolyvecSlotBase, getPolyvecSlotSize,
	getPolyvecSlot0, getPolyvecSlot1, getPolyvecSlot2, getPolyvecSlot3,
	getPolyvecSlot4, getPolyvecSlot5, getPolyvecSlot6, getPolyvecSlot7,
	getSeedOffset, getTrOffset, getMsgRepOffset, getCTildeOffset,
	getPkOffset, getSkOffset, getSigOffset,
	getXofPrfOffset,
	wipeBuffers,
} from './buffers';

// ── Reduction primitives (reduce.ts) ────────────────────────────────────────

export { montgomery_reduce, barrett_reduce, fqmul } from './reduce';

// ── NTT (ntt.ts / ntt_simd.ts) ──────────────────────────────────────────────
// Public NTT path is SIMD. Scalar versions remain available for cross-checks.

export { getZetasOffset, getZeta, BitRev8 }            from './ntt';
export { ntt as ntt_scalar, invntt as invntt_scalar }  from './ntt';
export { ntt_simd as ntt, invntt_simd as invntt }      from './ntt_simd';

// ── Polynomial arithmetic (poly.ts / poly_simd.ts) ──────────────────────────
// SIMD versions are the public surface for add/sub/reduce/caddq/pointwise;
// scalar versions are exposed under explicit aliases for the SIMD/scalar gate.
// freeze and chknorm are scalar-only (data-dependent control flow, see header
// comments in poly.ts).

export { poly_freeze, poly_chknorm, poly_tomont } from './poly';
export {
	poly_add    as poly_add_scalar,
	poly_sub    as poly_sub_scalar,
	poly_reduce as poly_reduce_scalar,
	poly_caddq  as poly_caddq_scalar,
	poly_pointwise_montgomery as poly_pointwise_montgomery_scalar,
} from './poly';

export {
	poly_add_simd                  as poly_add,
	poly_sub_simd                  as poly_sub,
	poly_reduce_simd               as poly_reduce,
	poly_caddq_simd                as poly_caddq,
	poly_pointwise_montgomery_simd as poly_pointwise_montgomery,
} from './poly_simd';

// ── Bit-pack encoding (encoding.ts) ─────────────────────────────────────────

export {
	simple_bit_pack, bit_pack,
	simple_bit_unpack, bit_unpack,
	hint_bit_pack, hint_bit_unpack,
} from './encoding';

// ── Rounding kernels (rounding.ts) ──────────────────────────────────────────

export {
	power2round, decompose,
	highbits, lowbits,
	make_hint, use_hint,
} from './rounding';

// ── Polyvec wrappers (polyvec.ts) ───────────────────────────────────────────

export {
	polyvec_add, polyvec_sub,
	polyvec_reduce, polyvec_caddq, polyvec_freeze, polyvec_tomont,
	polyvec_ntt, polyvec_invntt,
	polyvec_pointwise_montgomery,
	polyvec_pointwise_acc_montgomery,
	polyvec_matrix_pointwise_montgomery,
	polyvec_chknorm,
	polyvec_power2round, polyvec_decompose,
	polyvec_highbits, polyvec_lowbits,
	polyvec_make_hint, polyvec_use_hint,
} from './polyvec';

// ── Sampling kernels (sampling.ts) ──────────────────────────────────────────

export {
	rej_ntt_poly, rej_bounded_poly,
	sample_in_ball,
} from './sampling';
