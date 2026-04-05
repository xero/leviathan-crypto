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
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▄          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
//
// src/asm/kyber/reduce.ts
//
// ML-KEM (Kyber) — modular arithmetic: Montgomery and Barrett reduction.
// FIPS 203 §4.5 (implicitly) and pq-crystals/kyber ref/reduce.c.

import { Q, QINV, BARRETT_V, BARRETT_SHIFT } from './params';

/**
 * Montgomery reduction.
 * FIPS 203 §4.5 — given a ∈ {-q·2^15, ..., q·2^15 - 1},
 * returns a·R^{-1} mod q where R = 2^16, result in {-(q-1), ..., q-1}.
 */
@inline
export function montgomery_reduce(a: i32): i16 {
	// t = (i16)(a * QINV) — keep only low 16 bits (mod 2^16)
	const t: i16 = <i16>(<i32><i16>a * QINV);
	// result = (a - t*q) >> 16
	return <i16>((a - t * Q) >> 16);
}

/**
 * Barrett reduction (centered).
 * Returns representative in [-(q-1)/2, (q-1)/2].
 * pq-crystals/kyber main branch ref/reduce.c barrett_reduce.
 */
@inline
export function barrett_reduce(a: i16): i16 {
	// t = round(a / q) ≈ (v * a + 2^25) >> 26 where v = floor((2^26 + q/2)/q)
	const t: i16 = <i16>((<i32>BARRETT_V * <i32>a + (1 << (BARRETT_SHIFT - 1))) >> BARRETT_SHIFT);
	return <i16>(<i32>a - <i32>t * Q);
}

/**
 * Multiplication in Z_q, Montgomery domain.
 * Returns a·b·R^{-1} mod q where R = 2^16.
 */
@inline
export function fqmul(a: i16, b: i16): i16 {
	return montgomery_reduce(<i32>a * <i32>b);
}
