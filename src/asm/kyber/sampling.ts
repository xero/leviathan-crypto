//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒ █ ▒ ▒ ▒ █
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
// src/asm/kyber/sampling.ts
//
// ML-KEM (Kyber) — uniform rejection sampling for matrix A coefficient generation.
// FIPS 203 §4.2.1 — Algorithm 6 (SampleNTT).
// Reference: pq-crystals/kyber main ref/indcpa.c rej_uniform().
//
// Note: this function has data-dependent branching — that is acceptable because
// it operates on public seeds only (matrix A generation, not key material).

import { Q } from './params';

/**
 * Rejection sampling: extract coefficients in [0, q) from a byte buffer.
 * FIPS 203 §4.2.1 Algorithm 6 — inner sampling loop.
 * Each 3-byte group encodes two 12-bit candidates. Accepts if < q.
 * @param polyOffset output polynomial offset (256×i16)
 * @param ctrStart   starting coefficient index (resume after partial fill)
 * @param bufOffset  input byte buffer offset
 * @param buflen     input buffer byte length
 * @returns number of coefficients written (≤ 256 - ctrStart)
 */
export function rej_uniform(polyOffset: i32, ctrStart: i32, bufOffset: i32, buflen: i32): i32 {
	let ctr: i32 = ctrStart;
	let pos: i32 = 0;
	while (ctr < 256 && pos + 3 <= buflen) {
		const b0: u16 = <u16>load<u8>(bufOffset + pos);
		const b1: u16 = <u16>load<u8>(bufOffset + pos + 1);
		const b2: u16 = <u16>load<u8>(bufOffset + pos + 2);
		const val0: u16 = (b0 | (b1 << 8)) & 0xFFF;
		const val1: u16 = ((b1 >> 4) | (b2 << 4)) & 0xFFF;
		pos += 3;
		if (<i32>val0 < Q) {
			store<i16>(polyOffset + ctr * 2, <i16>val0);
			ctr += 1;
		}
		if (ctr < 256 && <i32>val1 < Q) {
			store<i16>(polyOffset + ctr * 2, <i16>val1);
			ctr += 1;
		}
	}
	return ctr - ctrStart;
}
