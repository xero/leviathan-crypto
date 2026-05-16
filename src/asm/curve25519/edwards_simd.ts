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
// src/asm/curve25519/edwards_simd.ts
//
// edwards25519 addition, dalek "parallel formulas" (eprint 2018/098)
// posture. TASK-B step 11.
//
// Background. The Hisil-Wong-Carter-Dawson §3.1 addition formula has
// eight independent field multiplications (A = (Y1-X1)*(Y2-X2),
// B = (Y1+X1)*(Y2+X2), C = T1*2d*T2 (two muls), D = 2*Z1*Z2,
// X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G) and a similar pattern of
// independent field adds / subs. Dalek's eprint 2018/098 argues these
// pair cleanly onto 2-way SIMD lanes, halving the throughput cost.
//
// The pairing win materialises only with a fast paired 64x64→128
// field multiplication. AssemblyScript's v128 intrinsic set does NOT
// expose a native paired 64-bit multiply; the closest available
// primitive is i64x2.extmul_low_i32x4 / extmul_high_i32x4 (paired
// 32x32→64), and synthesizing a paired 64x64→128 from it requires a
// manual 4-piece split plus carry-tracking via XOR-flip + signed
// compare (no i64x2 unsigned compare). Empirically under V8 / Spider-
// Monkey / engine V8/WasmTime, that emulated path is not measurably
// faster than two scalar feMul calls in sequence: extmul throughput
// is not better than i64-mul plus 4-piece split, and the additional
// pack / unpack overhead consumes the marginal vector win.
//
// Per TASK-B step-11 escape clause ("if a v128-paired form genuinely
// does not improve a particular operation, only the non-`_simd` form
// lands") the paired field multiplication is NOT shipped. The
// substrate's edPointAdd in edwards.ts is the single point-addition
// entry; this file ships a `edPointAddPair` only as a convenience
// double-call wrapper for callers that genuinely have two
// independent additions to process. The wrapper invokes scalar
// edPointAdd twice in sequence; field_simd.ts's paired add / sub /
// neg / condswap ops are exercised by edPointAdd indirectly only if
// a future caller paths through them, but on TASK-B's substrate the
// scalar path is the canonical edPointAdd.
//
// The current TASK-B scope has no internal consumer for
// edPointAddPair; it is exposed for TASK-C / TASK-D batch verify
// paths to opt into.

import { edPointAdd } from './edwards'

/**
 * Batched extended-coord Edwards addition: outA = aA + bA and
 * outB = aB + bB. See file header for the scalar-vs-paired tradeoff
 * rationale. Currently implemented as two sequential edPointAdd
 * calls; the function exists to anchor the batched-addition API for
 * future TASK-C / TASK-D consumers without forcing a callable
 * mid-task algorithm rewrite.
 */
export function edPointAddPair(
	outA: i32, outB: i32,
	aA:   i32, aB:   i32,
	bA:   i32, bB:   i32,
): void {
	edPointAdd(outA, aA, bA)
	edPointAdd(outB, aB, bB)
}
