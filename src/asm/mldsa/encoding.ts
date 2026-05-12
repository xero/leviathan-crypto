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
// src/asm/mldsa/encoding.ts
//
// ML-DSA, bit-level packing of polynomials and hint vectors.
// FIPS 204 §7.1 Algorithms 16-21.
//
// ML-DSA uses bit-pack widths that vary by parameter set and field. Across
// the three parameter sets (44/65/87) the union of widths used by phase-4
// orchestration is { 3, 4, 6, 10, 13, 18, 20 }:
//
//   bitlen   Where used                          Algorithm
//   ──────── ────────────────────────────────── ─────────
//      3     s1, s2  (η = 2; BitPack a=b=2)     skEncode / skDecode
//      4     s1, s2  (η = 4; BitPack a=b=4)     skEncode / skDecode
//      4     w1      (γ₂ = (q-1)/32)            w1Encode  (SimpleBitPack)
//      6     w1      (γ₂ = (q-1)/88)            w1Encode  (SimpleBitPack)
//     10     t1                                 pkEncode  (SimpleBitPack)
//     13     t0      (BitPack a=2^12−1, b=2^12) skEncode / skDecode
//     18     z       (γ₁ = 2^17)                sigEncode / sigDecode
//     20     z       (γ₁ = 2^19)                sigEncode / sigDecode
//
// The functions in this file accept the width or (a,b) range as a runtime
// argument; phase-4 wrappers pick the right value per parameter set.
//
// HintBitUnpack (Alg 21) implements three malformed-input checks (lines 4, 9,
// 17 of the spec). Skipping any of them breaks SUF-CMA per FIPS 204 §D.3.
// Returning -1 here maps to ⊥ in the TS verifier path. This is the fix that
// landed in FIPS 204 final relative to the IPD draft.

import { N } from './params';

// ── simple_bit_pack, FIPS 204 Algorithm 16 ─────────────────────────────────
// Encode 256 coefficients ∈ [0, 2^bitlen − 1] as a 32·bitlen byte string.
// Caller guarantees the range. The accumulator never holds more than
// 7 + bitlen bits (≤ 27 for the widest ML-DSA field), well within u64.
export function simple_bit_pack(rByteOff: i32, polyOff: i32, bitlen: i32): void {
	let acc:    u64 = 0;
	let nbits:  i32 = 0;
	let outIdx: i32 = 0;
	for (let i: i32 = 0; i < N; i++) {
		const w: u64 = <u64>load<i32>(polyOff + i * 4);
		acc |= w << <u64>nbits;
		nbits += bitlen;
		while (nbits >= 8) {
			store<u8>(rByteOff + outIdx, <u8>(acc & 0xFF));
			outIdx++;
			acc >>= 8;
			nbits -= 8;
		}
	}
	// 256 · bitlen is a multiple of 8 for every bitlen ≥ 1, so the accumulator
	// is always empty here. No final flush needed.
}

// ── bit_pack, FIPS 204 Algorithm 17 ────────────────────────────────────────
// Encode 256 coefficients ∈ [-a, b] by writing (b − w_i) at bitlen(a+b) bits.
// bitlen(n) for n > 0 is the position of the most-significant 1 plus 1, i.e.
// 32 − clz(n). For a + b = 0 the field collapses to width 0; that case never
// occurs in ML-DSA (smallest is η = 2 → a + b = 4 → bitlen = 3).
export function bit_pack(rByteOff: i32, polyOff: i32, a: i32, b: i32): void {
	const sum:    i32 = a + b;
	const bitlen: i32 = 32 - <i32>clz(sum);
	let acc:    u64 = 0;
	let nbits:  i32 = 0;
	let outIdx: i32 = 0;
	for (let i: i32 = 0; i < N; i++) {
		// (b − w_i) is non-negative in [0, a+b] when w_i ∈ [-a, b].
		const v: u64 = <u64>(b - load<i32>(polyOff + i * 4));
		acc |= v << <u64>nbits;
		nbits += bitlen;
		while (nbits >= 8) {
			store<u8>(rByteOff + outIdx, <u8>(acc & 0xFF));
			outIdx++;
			acc >>= 8;
			nbits -= 8;
		}
	}
}

// ── simple_bit_unpack, FIPS 204 Algorithm 18 ───────────────────────────────
// Decode 32·bitlen bytes into 256 coefficients ∈ [0, 2^bitlen − 1].
// Per spec, "When b + 1 is a power of 2, the coefficients are in [0, b]",
// so the natural unsigned range and the spec range coincide for ML-DSA.
export function simple_bit_unpack(polyOff: i32, vByteOff: i32, bitlen: i32): void {
	const mask: u64 = (<u64>1 << <u64>bitlen) - 1;
	let acc:   u64 = 0;
	let nbits: i32 = 0;
	let inIdx: i32 = 0;
	for (let i: i32 = 0; i < N; i++) {
		while (nbits < bitlen) {
			acc |= (<u64>load<u8>(vByteOff + inIdx)) << <u64>nbits;
			inIdx++;
			nbits += 8;
		}
		store<i32>(polyOff + i * 4, <i32>(acc & mask));
		acc >>= <u64>bitlen;
		nbits -= bitlen;
	}
}

// ── bit_unpack, FIPS 204 Algorithm 19 ──────────────────────────────────────
// Decode 32·bitlen(a+b) bytes into 256 coefficients ∈ [b - 2^c + 1, b], where
// c = bitlen(a+b). For widths where a+b+1 is a power of 2 (t0, z) this is
// exactly [-a, b]; for the η=2 (a+b=4) and η=4 (a+b=8) widths the unsigned
// span exceeds a+b+1, so malformed input may produce coefficients outside
// [-a, b]. Range validation is the caller's responsibility, `mldsaSignInternal`
// (src/ts/mldsa/sign.ts) follows each s₁/s₂ unpack with `polyvec_chknorm(slot,
// η+1, …)` and throws RangeError on out-of-range coefficients per FIPS 204
// §7.2 / Alg 25 line 5.
export function bit_unpack(polyOff: i32, vByteOff: i32, a: i32, b: i32): void {
	const sum:    i32 = a + b;
	const bitlen: i32 = 32 - <i32>clz(sum);
	const mask:   u64 = (<u64>1 << <u64>bitlen) - 1;
	let acc:   u64 = 0;
	let nbits: i32 = 0;
	let inIdx: i32 = 0;
	for (let i: i32 = 0; i < N; i++) {
		while (nbits < bitlen) {
			acc |= (<u64>load<u8>(vByteOff + inIdx)) << <u64>nbits;
			inIdx++;
			nbits += 8;
		}
		const u: i32 = <i32>(acc & mask);  // unsigned in [0, a+b]
		store<i32>(polyOff + i * 4, b - u);
		acc >>= <u64>bitlen;
		nbits -= bitlen;
	}
}

// ── hint_bit_pack, FIPS 204 Algorithm 20 ───────────────────────────────────
// Encode a hint polyvec h ∈ R₂^k (with ≤ ω total set bits) as ω + k bytes.
// Each polynomial in h occupies one i32 slot per coefficient; only values 0
// or 1 are valid. The first ω bytes hold the positions of the set bits in
// each polynomial (in coefficient order), and y[ω + i] is the running
// cumulative count after polynomial i.
export function hint_bit_pack(rByteOff: i32, hPvOff: i32, k: i32, omega: i32): void {
	// Zero the output buffer (ω + k bytes).
	memory.fill(rByteOff, 0, omega + k);
	let index: i32 = 0;
	for (let i: i32 = 0; i < k; i++) {
		const polyOff: i32 = hPvOff + i * 1024;
		for (let j: i32 = 0; j < N; j++) {
			if (load<i32>(polyOff + j * 4) != 0) {
				store<u8>(rByteOff + index, <u8>j);
				index++;
			}
		}
		store<u8>(rByteOff + omega + i, <u8>index);
	}
}

// ── hint_bit_unpack, FIPS 204 Algorithm 21 ─────────────────────────────────
// Decode ω + k bytes into a hint polyvec, returning -1 on malformed input.
// The three malformed-input checks (lines 4, 9, 17 of Alg 21) are
// SUF-CMA-critical per FIPS 204 §D.3:
//
//   Line 4 , y[ω+i] must be in [Index, ω].         Range check on cumulative
//                                                   count: must not regress
//                                                   nor exceed ω.
//   Line 9 , within poly i, positions strictly      Prevents two encodings
//             ascending: y[Index − 1] < y[Index].   of the same h.
//   Line 17, trailing bytes y[Index..ω−1] are 0.   Same reason.
//
// Returning -1 on any failure lets the TS caller short-circuit to ⊥ before
// running the rest of verification (Alg 8 line 3).
export function hint_bit_unpack(hPvOff: i32, vByteOff: i32, k: i32, omega: i32): i32 {
	// Zero the output polyvec (k × 1024 bytes of i32 coefficients).
	memory.fill(hPvOff, 0, k * 1024);
	let index: i32 = 0;
	for (let i: i32 = 0; i < k; i++) {
		const yWi: i32 = <i32>load<u8>(vByteOff + omega + i);
		// Check 1 (Alg 21 line 4): y[ω+i] ∈ [Index, ω].
		if (yWi < index || yWi > omega) return -1;
		const first:   i32 = index;
		const polyOff: i32 = hPvOff + i * 1024;
		while (index < yWi) {
			if (index > first) {
				// Check 2 (Alg 21 line 9): y[Index − 1] < y[Index], strict
				// ascending positions inside the same polynomial.
				const prev: i32 = <i32>load<u8>(vByteOff + index - 1);
				const cur:  i32 = <i32>load<u8>(vByteOff + index);
				if (prev >= cur) return -1;
			}
			const pos: i32 = <i32>load<u8>(vByteOff + index);
			store<i32>(polyOff + pos * 4, 1);
			index++;
		}
	}
	// Check 3 (Alg 21 line 17): trailing bytes in [Index, ω) must be zero.
	for (let i: i32 = index; i < omega; i++) {
		if (<i32>load<u8>(vByteOff + i) != 0) return -1;
	}
	return 0;
}
