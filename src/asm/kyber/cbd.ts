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
// src/asm/kyber/cbd.ts
//
// ML-KEM (Kyber) — Centered Binomial Distribution sampling.
// FIPS 203 §4.2.2 SamplePolyCBD_η — Algorithm 7 (η=2) and Algorithm 8 (η=3).
// Reference: pq-crystals/kyber main ref/cbd.c.

/**
 * CBD with η=2. Samples 256 coefficients in [−2, 2].
 * FIPS 203 Algorithm 7 — SamplePolyCBD_2.
 * Input: 128-byte PRF output buffer (2×N/4 = 2×64 = 128 bytes).
 * @param polyOffset output 256×i16 polynomial
 * @param bufOffset input 128-byte buffer
 */
export function cbd2(polyOffset: i32, bufOffset: i32): void {
	// pq-crystals/kyber ref/cbd.c cbd2()
	// Process 4 bytes at a time → 8 coefficients. N/8 = 32 iterations.
	for (let i: i32 = 0; i < 32; i++) {
		// Load 4 bytes as little-endian u32
		const b0: u32 = <u32>load<u8>(bufOffset + 4*i);
		const b1: u32 = <u32>load<u8>(bufOffset + 4*i + 1);
		const b2: u32 = <u32>load<u8>(bufOffset + 4*i + 2);
		const b3: u32 = <u32>load<u8>(bufOffset + 4*i + 3);
		const t: u32 = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
		// Bit interleave: d[j] = popcount of 2 bit pairs
		let d: u32 = t & 0x55555555;
		d += (t >> 1) & 0x55555555;
		// Extract 8 pairs of 2-bit values → coefficients a−b ∈ {−2,…,2}
		for (let j: i32 = 0; j < 8; j++) {
			const a: i16 = <i16>((d >> (4*j    )) & 3);
			const b: i16 = <i16>((d >> (4*j + 2)) & 3);
			store<i16>(polyOffset + (8*i + j)*2, a - b);
		}
	}
}

/**
 * CBD with η=3. Samples 256 coefficients in [−3, 3].
 * FIPS 203 Algorithm 8 — SamplePolyCBD_3.
 * Input: 192-byte PRF output buffer (3×N/4 = 3×64 = 192 bytes).
 * @param polyOffset output 256×i16 polynomial
 * @param bufOffset input 192-byte buffer
 */
export function cbd3(polyOffset: i32, bufOffset: i32): void {
	// pq-crystals/kyber ref/cbd.c cbd3()
	// Process 3 bytes at a time → 4 coefficients
	for (let i: i32 = 0; i < 64; i++) {
		// Load 3 bytes as little-endian 24-bit value
		const b0: u32 = <u32>load<u8>(bufOffset + 3*i);
		const b1: u32 = <u32>load<u8>(bufOffset + 3*i + 1);
		const b2: u32 = <u32>load<u8>(bufOffset + 3*i + 2);
		const t: u32 = b0 | (b1 << 8) | (b2 << 16);
		// Bit interleave: d[j] = popcount of 3 bit triples
		let d: u32 = t & 0x00249249;
		d += (t >> 1) & 0x00249249;
		d += (t >> 2) & 0x00249249;
		// Extract 4 pairs of 3-bit values → coefficients a−b ∈ {−3,…,3}
		for (let j: i32 = 0; j < 4; j++) {
			const a: i16 = <i16>((d >> (6*j    )) & 7);
			const b: i16 = <i16>((d >> (6*j + 3)) & 7);
			store<i16>(polyOffset + (4*i + j)*2, a - b);
		}
	}
}
