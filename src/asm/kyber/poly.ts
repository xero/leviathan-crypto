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
// src/asm/kyber/poly.ts
//
// ML-KEM (Kyber) — polynomial operations: serialization, compression, arithmetic.
// FIPS 203 §4 (ByteEncode/ByteDecode, Compress/Decompress, NTT operations).

import { Q, POLY_BYTES, HALF_Q,
         COMPRESS4_MUL, COMPRESS4_ADD, COMPRESS4_SHIFT,
         COMPRESS5_MUL, COMPRESS5_ADD, COMPRESS5_SHIFT } from './params';
import { montgomery_reduce, barrett_reduce, fqmul } from './reduce';
import { ntt, invntt, basemul, getZeta } from './ntt';
import { cbd2, cbd3 } from './cbd';

// ── Serialization ─────────────────────────────────────────────────────────────

/**
 * Serialize polynomial to 384 bytes (12-bit packing).
 * FIPS 203 ByteEncode_12 (Algorithm 4 with d=12).
 */
export function poly_tobytes(rOffset: i32, polyOffset: i32): void {
	for (let i: i32 = 0; i < 128; i++) {
		let t0: u16 = <u16>load<i16>(polyOffset + (2 * i) * 2);
		let t1: u16 = <u16>load<i16>(polyOffset + (2 * i + 1) * 2);
		// Map negative to positive
		t0 += <u16>((<i16>t0 >> 15) & <i16>Q);
		t1 += <u16>((<i16>t1 >> 15) & <i16>Q);
		store<u8>(rOffset + 3 * i,     <u8>t0);
		store<u8>(rOffset + 3 * i + 1, <u8>((t0 >> 8) | (t1 << 4)));
		store<u8>(rOffset + 3 * i + 2, <u8>(t1 >> 4));
	}
}

/**
 * Deserialize 384 bytes to polynomial (12-bit packing).
 * FIPS 203 ByteDecode_12 (Algorithm 5 with d=12).
 */
export function poly_frombytes(polyOffset: i32, aOffset: i32): void {
	for (let i: i32 = 0; i < 128; i++) {
		const b0: u16 = <u16>load<u8>(aOffset + 3 * i);
		const b1: u16 = <u16>load<u8>(aOffset + 3 * i + 1);
		const b2: u16 = <u16>load<u8>(aOffset + 3 * i + 2);
		store<i16>(polyOffset + (2 * i) * 2,     <i16>((b0 | (b1 << 8)) & 0xFFF));
		store<i16>(polyOffset + (2 * i + 1) * 2, <i16>(((b1 >> 4) | (b2 << 4)) & 0xFFF));
	}
}

// ── Compression ───────────────────────────────────────────────────────────────

/**
 * Compress and serialize polynomial.
 * FIPS 203 Compress_d then ByteEncode_d.
 * dv=4 → 128 bytes output; dv=5 → 160 bytes output.
 */
export function poly_compress(rOffset: i32, polyOffset: i32, dv: i32): void {
	let u: i32, d0: u32;
	if (dv == 4) {
		for (let i: i32 = 0; i < 32; i++) {
			// Compress 8 coefficients to 4 bits each → 4 bytes
			// t[j] = ((u << 4) + 1665) * 80635 >> 28 & 0xF
			let t0: u32, t1: u32, t2: u32, t3: u32, t4: u32, t5: u32, t6: u32, t7: u32;
			u = <i32>load<i16>(polyOffset + (8*i+0)*2); u += (u >> 15) & Q;
			t0 = (<u32>(u << 4) + <u32>COMPRESS4_ADD) * <u32>COMPRESS4_MUL >> COMPRESS4_SHIFT;
			u = <i32>load<i16>(polyOffset + (8*i+1)*2); u += (u >> 15) & Q;
			t1 = (<u32>(u << 4) + <u32>COMPRESS4_ADD) * <u32>COMPRESS4_MUL >> COMPRESS4_SHIFT;
			u = <i32>load<i16>(polyOffset + (8*i+2)*2); u += (u >> 15) & Q;
			t2 = (<u32>(u << 4) + <u32>COMPRESS4_ADD) * <u32>COMPRESS4_MUL >> COMPRESS4_SHIFT;
			u = <i32>load<i16>(polyOffset + (8*i+3)*2); u += (u >> 15) & Q;
			t3 = (<u32>(u << 4) + <u32>COMPRESS4_ADD) * <u32>COMPRESS4_MUL >> COMPRESS4_SHIFT;
			u = <i32>load<i16>(polyOffset + (8*i+4)*2); u += (u >> 15) & Q;
			t4 = (<u32>(u << 4) + <u32>COMPRESS4_ADD) * <u32>COMPRESS4_MUL >> COMPRESS4_SHIFT;
			u = <i32>load<i16>(polyOffset + (8*i+5)*2); u += (u >> 15) & Q;
			t5 = (<u32>(u << 4) + <u32>COMPRESS4_ADD) * <u32>COMPRESS4_MUL >> COMPRESS4_SHIFT;
			u = <i32>load<i16>(polyOffset + (8*i+6)*2); u += (u >> 15) & Q;
			t6 = (<u32>(u << 4) + <u32>COMPRESS4_ADD) * <u32>COMPRESS4_MUL >> COMPRESS4_SHIFT;
			u = <i32>load<i16>(polyOffset + (8*i+7)*2); u += (u >> 15) & Q;
			t7 = (<u32>(u << 4) + <u32>COMPRESS4_ADD) * <u32>COMPRESS4_MUL >> COMPRESS4_SHIFT;
			store<u8>(rOffset + 4*i,   <u8>((t0 & 0xF) | ((t1 & 0xF) << 4)));
			store<u8>(rOffset + 4*i+1, <u8>((t2 & 0xF) | ((t3 & 0xF) << 4)));
			store<u8>(rOffset + 4*i+2, <u8>((t4 & 0xF) | ((t5 & 0xF) << 4)));
			store<u8>(rOffset + 4*i+3, <u8>((t6 & 0xF) | ((t7 & 0xF) << 4)));
		}
	} else {
		// dv == 5: 8 coefficients → 5 bytes
		for (let i: i32 = 0; i < 32; i++) {
			let t0: u32, t1: u32, t2: u32, t3: u32, t4: u32, t5: u32, t6: u32, t7: u32;
			u = <i32>load<i16>(polyOffset + (8*i+0)*2); u += (u >> 15) & Q;
			t0 = ((<u32>(u << 5) + <u32>COMPRESS5_ADD) * <u32>COMPRESS5_MUL >> COMPRESS5_SHIFT) & 0x1F;
			u = <i32>load<i16>(polyOffset + (8*i+1)*2); u += (u >> 15) & Q;
			t1 = ((<u32>(u << 5) + <u32>COMPRESS5_ADD) * <u32>COMPRESS5_MUL >> COMPRESS5_SHIFT) & 0x1F;
			u = <i32>load<i16>(polyOffset + (8*i+2)*2); u += (u >> 15) & Q;
			t2 = ((<u32>(u << 5) + <u32>COMPRESS5_ADD) * <u32>COMPRESS5_MUL >> COMPRESS5_SHIFT) & 0x1F;
			u = <i32>load<i16>(polyOffset + (8*i+3)*2); u += (u >> 15) & Q;
			t3 = ((<u32>(u << 5) + <u32>COMPRESS5_ADD) * <u32>COMPRESS5_MUL >> COMPRESS5_SHIFT) & 0x1F;
			u = <i32>load<i16>(polyOffset + (8*i+4)*2); u += (u >> 15) & Q;
			t4 = ((<u32>(u << 5) + <u32>COMPRESS5_ADD) * <u32>COMPRESS5_MUL >> COMPRESS5_SHIFT) & 0x1F;
			u = <i32>load<i16>(polyOffset + (8*i+5)*2); u += (u >> 15) & Q;
			t5 = ((<u32>(u << 5) + <u32>COMPRESS5_ADD) * <u32>COMPRESS5_MUL >> COMPRESS5_SHIFT) & 0x1F;
			u = <i32>load<i16>(polyOffset + (8*i+6)*2); u += (u >> 15) & Q;
			t6 = ((<u32>(u << 5) + <u32>COMPRESS5_ADD) * <u32>COMPRESS5_MUL >> COMPRESS5_SHIFT) & 0x1F;
			u = <i32>load<i16>(polyOffset + (8*i+7)*2); u += (u >> 15) & Q;
			t7 = ((<u32>(u << 5) + <u32>COMPRESS5_ADD) * <u32>COMPRESS5_MUL >> COMPRESS5_SHIFT) & 0x1F;
			store<u8>(rOffset + 5*i,   <u8>((t0>>0) | (t1<<5)));
			store<u8>(rOffset + 5*i+1, <u8>((t1>>3) | (t2<<2) | (t3<<7)));
			store<u8>(rOffset + 5*i+2, <u8>((t3>>1) | (t4<<4)));
			store<u8>(rOffset + 5*i+3, <u8>((t4>>4) | (t5<<1) | (t6<<6)));
			store<u8>(rOffset + 5*i+4, <u8>((t6>>2) | (t7<<3)));
		}
	}
}

/**
 * Deserialize and decompress polynomial.
 * FIPS 203 ByteDecode_d then Decompress_d.
 * dv=4 → read 128 bytes; dv=5 → read 160 bytes.
 */
export function poly_decompress(polyOffset: i32, aOffset: i32, dv: i32): void {
	if (dv == 4) {
		for (let i: i32 = 0; i < 128; i++) {
			const b: u8 = load<u8>(aOffset + i);
			// Decompress_4: round(x * q / 16) = (x*q + 8) >> 4
			store<i16>(polyOffset + (2*i)*2,   <i16>(((<u32>(b & 0xF) * <u32>Q) + 8) >> 4));
			store<i16>(polyOffset + (2*i+1)*2, <i16>(((<u32>(b >> 4)  * <u32>Q) + 8) >> 4));
		}
	} else {
		// dv == 5: 5 bytes → 8 × 5-bit values
		for (let i: i32 = 0; i < 32; i++) {
			const b0: u32 = <u32>load<u8>(aOffset + 5*i);
			const b1: u32 = <u32>load<u8>(aOffset + 5*i+1);
			const b2: u32 = <u32>load<u8>(aOffset + 5*i+2);
			const b3: u32 = <u32>load<u8>(aOffset + 5*i+3);
			const b4: u32 = <u32>load<u8>(aOffset + 5*i+4);
			const t0: u32 = (b0 >> 0);
			const t1: u32 = (b0 >> 5) | (b1 << 3);
			const t2: u32 = (b1 >> 2);
			const t3: u32 = (b1 >> 7) | (b2 << 1);
			const t4: u32 = (b2 >> 4) | (b3 << 4);
			const t5: u32 = (b3 >> 1);
			const t6: u32 = (b3 >> 6) | (b4 << 2);
			const t7: u32 = (b4 >> 3);
			// Decompress_5: round(x & 0x1F * q / 32) = ((x&31)*q + 16) >> 5
			store<i16>(polyOffset + (8*i+0)*2, <i16>(((t0 & 31) * <u32>Q + 16) >> 5));
			store<i16>(polyOffset + (8*i+1)*2, <i16>(((t1 & 31) * <u32>Q + 16) >> 5));
			store<i16>(polyOffset + (8*i+2)*2, <i16>(((t2 & 31) * <u32>Q + 16) >> 5));
			store<i16>(polyOffset + (8*i+3)*2, <i16>(((t3 & 31) * <u32>Q + 16) >> 5));
			store<i16>(polyOffset + (8*i+4)*2, <i16>(((t4 & 31) * <u32>Q + 16) >> 5));
			store<i16>(polyOffset + (8*i+5)*2, <i16>(((t5 & 31) * <u32>Q + 16) >> 5));
			store<i16>(polyOffset + (8*i+6)*2, <i16>(((t6 & 31) * <u32>Q + 16) >> 5));
			store<i16>(polyOffset + (8*i+7)*2, <i16>(((t7 & 31) * <u32>Q + 16) >> 5));
		}
	}
}

// ── Message encoding ──────────────────────────────────────────────────────────

/**
 * Convert 32-byte message to polynomial (1-bit Decompress).
 * FIPS 203 ByteDecode_1 then Decompress_1.
 * Each bit maps to 0 or ⌈q/2⌉ = 1665. Constant-time — no branch on secret bit.
 */
export function poly_frommsg(polyOffset: i32, msgOffset: i32): void {
	for (let i: i32 = 0; i < 32; i++) {
		const b: u8 = load<u8>(msgOffset + i);
		for (let j: i32 = 0; j < 8; j++) {
			// mask = 0xFFFF if bit==1, else 0x0000 — constant-time
			const mask: i16 = <i16>(-( (<i32>b >> j) & 1 ));
			store<i16>(polyOffset + (8*i + j)*2, mask & <i16>HALF_Q);
		}
	}
}

/**
 * Convert polynomial to 32-byte message (1-bit Compress).
 * FIPS 203 Compress_1 then ByteEncode_1.
 * Uses division-free multiply-shift — no branch on coefficient.
 */
export function poly_tomsg(msgOffset: i32, polyOffset: i32): void {
	for (let i: i32 = 0; i < 32; i++) {
		let msg: u8 = 0;
		for (let j: i32 = 0; j < 8; j++) {
			// Compress_1: round(2*coeff/q) mod 2
			// = ((coeff << 1) + 1665) * 80635 >> 28 & 1
			let t: u32 = <u32><i32>load<i16>(polyOffset + (8*i + j)*2);
			t  = (t << 1) + <u32>COMPRESS4_ADD;
			t *= <u32>COMPRESS4_MUL;
			t >>= COMPRESS4_SHIFT;
			t &= 1;
			msg |= <u8>(t << j);
		}
		store<u8>(msgOffset + i, msg);
	}
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

/**
 * Pointwise addition. No modular reduction.
 */
export function poly_add(rOffset: i32, aOffset: i32, bOffset: i32): void {
	for (let i: i32 = 0; i < 256; i++) {
		store<i16>(rOffset + i*2,
			load<i16>(aOffset + i*2) + load<i16>(bOffset + i*2));
	}
}

/**
 * Pointwise subtraction. No modular reduction.
 */
export function poly_sub(rOffset: i32, aOffset: i32, bOffset: i32): void {
	for (let i: i32 = 0; i < 256; i++) {
		store<i16>(rOffset + i*2,
			load<i16>(aOffset + i*2) - load<i16>(bOffset + i*2));
	}
}

/**
 * Apply Barrett reduction to all 256 coefficients.
 * Result in [-(q-1)/2, (q-1)/2].
 */
export function poly_reduce(polyOffset: i32): void {
	for (let i: i32 = 0; i < 256; i++) {
		store<i16>(polyOffset + i*2, barrett_reduce(load<i16>(polyOffset + i*2)));
	}
}

/**
 * Convert all coefficients to Montgomery domain.
 * Multiplies each coefficient by R² mod q = 2^32 mod q = 1353.
 * Result = coeff × R mod q (in Montgomery form).
 */
export function poly_tomont(polyOffset: i32): void {
	// f = 2^32 mod 3329 = 1353. Derivation: 2^16 mod 3329 = 2285; 2285² mod 3329 = 1353.
	const f: i16 = 1353;
	for (let i: i32 = 0; i < 256; i++) {
		store<i16>(polyOffset + i*2,
			montgomery_reduce(<i32>load<i16>(polyOffset + i*2) * <i32>f));
	}
}

// ── NTT wrappers ──────────────────────────────────────────────────────────────

/**
 * Forward NTT followed by Barrett reduction. FIPS 203 Algorithm 9.
 */
export function poly_ntt(polyOffset: i32): void {
	ntt(polyOffset);
	poly_reduce(polyOffset);
}

/**
 * Inverse NTT (includes Montgomery factor f=1441). FIPS 203 Algorithm 10.
 */
export function poly_invntt(polyOffset: i32): void {
	invntt(polyOffset);
}

/**
 * Pointwise multiplication in NTT domain. FIPS 203 §4.3.
 * Calls basemul for each coefficient pair with alternating +ζ/-ζ.
 * @param rOffset output polynomial offset
 * @param aOffset first factor (NTT domain)
 * @param bOffset second factor (NTT domain)
 */
export function poly_basemul_montgomery(rOffset: i32, aOffset: i32, bOffset: i32): void {
	// pq-crystals/kyber ref/poly.c poly_basemul_montgomery():
	//   basemul(&r->coeffs[4*i],   &a->coeffs[4*i],   &b->coeffs[4*i],   zetas[64+i])
	//   basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -zetas[64+i])
	for (let i: i32 = 0; i < 64; i++) {
		// First pair (4i, 4i+1) with +zetas[64+i]
		basemul(rOffset + 4*i*2, aOffset + 4*i*2, bOffset + 4*i*2, 64 + i);
		// Second pair (4i+2, 4i+3) with -zetas[64+i]
		_basemul_neg(rOffset + (4*i+2)*2, aOffset + (4*i+2)*2, bOffset + (4*i+2)*2, 64 + i);
	}
}

// basemul with negated zeta value.
// -fqmul(a1*b1, ζ) = fqmul(a1*b1, -ζ). Linearity: montgomery_reduce(x*(-z)) = -montgomery_reduce(x*z).
@inline
function _basemul_neg(rOffset: i32, aOffset: i32, bOffset: i32, zetaIdx: i32): void {
	const a0: i16 = load<i16>(aOffset);
	const a1: i16 = load<i16>(aOffset + 2);
	const b0: i16 = load<i16>(bOffset);
	const b1: i16 = load<i16>(bOffset + 2);
	const zeta: i16 = getZeta(zetaIdx);
	// r[0] = a[0]*b[0] - a[1]*b[1]*ζ  (note: -ζ term)
	store<i16>(rOffset,     <i16>(<i32>fqmul(a0, b0) - <i32>fqmul(fqmul(a1, b1), zeta)));
	// r[1] = a[0]*b[1] + a[1]*b[0]     (same regardless of ±ζ)
	store<i16>(rOffset + 2, <i16>(<i32>fqmul(a0, b1) + <i32>fqmul(a1, b0)));
}

// ── Noise sampling ────────────────────────────────────────────────────────────

/**
 * Apply CBD to PRF output to sample a noisy polynomial. FIPS 203 SamplePolyCBD_η.
 * @param polyOffset output polynomial offset
 * @param bufOffset input byte buffer (eta*n/4 bytes: 128B for η=2, 192B for η=3)
 * @param eta ∈ {2, 3}
 */
export function poly_getnoise(polyOffset: i32, bufOffset: i32, eta: i32): void {
	if (eta == 2) {
		cbd2(polyOffset, bufOffset);
	} else {
		cbd3(polyOffset, bufOffset);
	}
}
