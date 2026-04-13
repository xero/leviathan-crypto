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
// src/asm/kyber/index.ts
//
// ML-KEM (Kyber) WASM module — public exports.
// FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard.

// ── Buffer layout ─────────────────────────────────────────────────────────────

export {
	getModuleId, getMemoryPages,
	getPolySlotBase, getPolySlotSize,
	getPolySlot0, getPolySlot1, getPolySlot2, getPolySlot3, getPolySlot4,
	getPolySlot5, getPolySlot6, getPolySlot7, getPolySlot8, getPolySlot9,
	getPolyvecSlotBase, getPolyvecSlotSize,
	getPolyvecSlot0, getPolyvecSlot1, getPolyvecSlot2, getPolyvecSlot3,
	getPolyvecSlot4, getPolyvecSlot5, getPolyvecSlot6, getPolyvecSlot7,
	getSeedOffset, getMsgOffset, getPkOffset, getSkOffset, getCtOffset,
	getCtPrimeOffset, getXofPrfOffset,
	wipeBuffers,
} from './buffers';

// ── NTT (ntt.ts / ntt_simd.ts) ───────────────────────────────────────────────
// Public exports use SIMD implementations. Scalar aliases retained for tests.

export { getZetasOffset, getZeta, basemul }          from './ntt';
export { ntt as ntt_scalar, invntt as invntt_scalar } from './ntt';
export { ntt_simd as ntt, invntt_simd as invntt }    from './ntt_simd';

// ── Arithmetic (reduce.ts) ────────────────────────────────────────────────────
// Exported for Gate 2 unit tests. @inline in AS means inlined at call sites but
// still callable from outside the module.

export { montgomery_reduce, barrett_reduce, fqmul } from './reduce';

// ── Polynomial (poly.ts / poly_simd.ts) ──────────────────────────────────────
// Serialization, compression, message encoding and basemul stay scalar.
// add, sub, reduce, ntt-wrappers re-pointed to SIMD implementations.

export {
	poly_tobytes, poly_frombytes,
	poly_compress, poly_decompress,
	poly_frommsg, poly_tomsg,
	poly_tomont,
	poly_basemul_montgomery,
	poly_getnoise,
} from './poly';

export {
	poly_add_simd  as poly_add,
	poly_sub_simd  as poly_sub,
	poly_reduce_simd as poly_reduce,
	poly_ntt_simd  as poly_ntt,
	poly_invntt_simd as poly_invntt,
} from './poly_simd';

// ── Polyvec (polyvec.ts) ──────────────────────────────────────────────────────

export {
	polyvec_tobytes, polyvec_frombytes,
	polyvec_compress, polyvec_decompress,
	polyvec_ntt, polyvec_invntt,
	polyvec_reduce, polyvec_add,
	polyvec_basemul_acc_montgomery,
	polyvec_modulus_check,
} from './polyvec';

// ── Sampling (sampling.ts) ────────────────────────────────────────────────────

export { rej_uniform } from './sampling';

// ── Constant-time (verify.ts) ─────────────────────────────────────────────────

export { ct_verify, ct_cmov } from './verify';
