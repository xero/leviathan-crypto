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
// Phase 2 surface: buffer layout, ring arithmetic primitives (Montgomery and
// Barrett), and NTT / inverse-NTT in both scalar (cross-check) and SIMD
// (production) form. Higher-level operations land in phases 3+.

// ── Buffer layout (buffers.ts) ──────────────────────────────────────────────

export {
	getModuleId, getMemoryPages,
	getPolySlotBase, getPolySlotSize,
	getPolySlot0, getPolySlot1, getPolySlot2, getPolySlot3,
	getPolySlot4, getPolySlot5, getPolySlot6, getPolySlot7,
	getPolyvecSlotBase, getPolyvecSlotSize,
	getPolyvecSlot0, getPolyvecSlot1, getPolyvecSlot2, getPolyvecSlot3,
	getSeedOffset, getMsgRepOffset, getPkOffset, getSkOffset, getSigOffset,
	getXofPrfOffset,
	wipeBuffers,
} from './buffers';

// ── Reduction primitives (reduce.ts) ────────────────────────────────────────
// Exported for unit-test introspection — @inline functions remain callable
// from outside the WASM module.

export { montgomery_reduce, barrett_reduce, fqmul } from './reduce';

// ── NTT (ntt.ts / ntt_simd.ts) ──────────────────────────────────────────────
// Public NTT path is SIMD. Scalar versions are exposed under explicit aliases
// for the SIMD == scalar gate test (test/unit/mldsa/ntt_simd_gate.test.ts).

export { getZetasOffset, getZeta, BitRev8 }            from './ntt';
export { ntt as ntt_scalar, invntt as invntt_scalar }  from './ntt';
export { ntt_simd as ntt, invntt_simd as invntt }      from './ntt_simd';
