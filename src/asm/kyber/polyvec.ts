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
// src/asm/kyber/polyvec.ts
//
// ML-KEM (Kyber) — polyvec operations: serialization, compression, NTT, arithmetic.
// FIPS 203 — operations on vectors of k polynomials.
// Poly is 256×i16 = 512 bytes; polyvec is k×512 bytes.

import { Q, POLY_BYTES,
         COMPRESS10_MUL, COMPRESS10_ADD, COMPRESS10_SHIFT,
         COMPRESS11_MUL, COMPRESS11_ADD, COMPRESS11_SHIFT } from './params';
import { barrett_reduce } from './reduce';
import { POLY_ACC_OFFSET } from './buffers';
import { poly_tobytes, poly_frombytes, poly_basemul_montgomery } from './poly';
import {
	poly_add_simd  as poly_add,
	poly_reduce_simd as poly_reduce,
	poly_ntt_simd  as poly_ntt,
	poly_invntt_simd as poly_invntt,
} from './poly_simd';

// ── Serialization ───────────────────────────────────────────────────────────

/**
 * Serialize vector of polynomials. FIPS 203 — k × ByteEncode_12.
 */
export function polyvec_tobytes(rOffset: i32, pvOffset: i32, k: i32): void {
	for (let i: i32 = 0; i < k; i++) {
		poly_tobytes(rOffset + i * POLY_BYTES, pvOffset + i * 512);
	}
}

/**
 * Deserialize vector of polynomials. FIPS 203 — k × ByteDecode_12.
 */
export function polyvec_frombytes(pvOffset: i32, aOffset: i32, k: i32): void {
	for (let i: i32 = 0; i < k; i++) {
		poly_frombytes(pvOffset + i * 512, aOffset + i * POLY_BYTES);
	}
}

// ── Compression ─────────────────────────────────────────────────────────────

/**
 * Compress and serialize polyvec. FIPS 203 — k × Compress_du + ByteEncode_du.
 * du=10 → k×320 bytes; du=11 → k×352 bytes.
 * Uses 64-bit multiply for higher precision (pq-crystals/kyber ref/polyvec.c).
 */
export function polyvec_compress(rOffset: i32, pvOffset: i32, k: i32, du: i32): void {
	if (du == 10) {
		// 4 coefficients per group → 5 bytes (10 bits each)
		for (let i: i32 = 0; i < k; i++) {
			const polyBase: i32 = pvOffset + i * 512;
			const outBase:  i32 = rOffset  + i * (POLY_BYTES * 5 / 6); // k×320 / k
			// Actually: per-poly output = 320 bytes = N/4 * 5 = 64 * 5 bytes
			const outPoly: i32 = rOffset + i * 320;
			for (let j: i32 = 0; j < 64; j++) {
				let t0: i32 = <i32>load<i16>(polyBase + (4*j+0)*2);
				let t1: i32 = <i32>load<i16>(polyBase + (4*j+1)*2);
				let t2: i32 = <i32>load<i16>(polyBase + (4*j+2)*2);
				let t3: i32 = <i32>load<i16>(polyBase + (4*j+3)*2);
				// Map to positive
				t0 += (t0 >> 15) & Q;
				t1 += (t1 >> 15) & Q;
				t2 += (t2 >> 15) & Q;
				t3 += (t3 >> 15) & Q;
				// Compress_10: ((x << 10) + 1665) * 1290167 >> 32 & 0x3FF
				const c0: u16 = <u16>(((<u64>(<u32>t0 << 10) + COMPRESS10_ADD) * COMPRESS10_MUL >> COMPRESS10_SHIFT) & 0x3FF);
				const c1: u16 = <u16>(((<u64>(<u32>t1 << 10) + COMPRESS10_ADD) * COMPRESS10_MUL >> COMPRESS10_SHIFT) & 0x3FF);
				const c2: u16 = <u16>(((<u64>(<u32>t2 << 10) + COMPRESS10_ADD) * COMPRESS10_MUL >> COMPRESS10_SHIFT) & 0x3FF);
				const c3: u16 = <u16>(((<u64>(<u32>t3 << 10) + COMPRESS10_ADD) * COMPRESS10_MUL >> COMPRESS10_SHIFT) & 0x3FF);
				store<u8>(outPoly + 5*j,   <u8>(c0 >> 0));
				store<u8>(outPoly + 5*j+1, <u8>((c0 >> 8) | (c1 << 2)));
				store<u8>(outPoly + 5*j+2, <u8>((c1 >> 6) | (c2 << 4)));
				store<u8>(outPoly + 5*j+3, <u8>((c2 >> 4) | (c3 << 6)));
				store<u8>(outPoly + 5*j+4, <u8>(c3 >> 2));
			}
		}
	} else {
		// du == 11: 8 coefficients per group → 11 bytes (11 bits each)
		for (let i: i32 = 0; i < k; i++) {
			const polyBase: i32 = pvOffset + i * 512;
			const outPoly:  i32 = rOffset + i * 352;
			for (let j: i32 = 0; j < 32; j++) {
				let t0: i32 = <i32>load<i16>(polyBase + (8*j+0)*2);
				let t1: i32 = <i32>load<i16>(polyBase + (8*j+1)*2);
				let t2: i32 = <i32>load<i16>(polyBase + (8*j+2)*2);
				let t3: i32 = <i32>load<i16>(polyBase + (8*j+3)*2);
				let t4: i32 = <i32>load<i16>(polyBase + (8*j+4)*2);
				let t5: i32 = <i32>load<i16>(polyBase + (8*j+5)*2);
				let t6: i32 = <i32>load<i16>(polyBase + (8*j+6)*2);
				let t7: i32 = <i32>load<i16>(polyBase + (8*j+7)*2);
				t0 += (t0 >> 15) & Q; t1 += (t1 >> 15) & Q;
				t2 += (t2 >> 15) & Q; t3 += (t3 >> 15) & Q;
				t4 += (t4 >> 15) & Q; t5 += (t5 >> 15) & Q;
				t6 += (t6 >> 15) & Q; t7 += (t7 >> 15) & Q;
				const c0: u16 = <u16>(((<u64>(<u32>t0 << 11) + COMPRESS11_ADD) * COMPRESS11_MUL >> COMPRESS11_SHIFT) & 0x7FF);
				const c1: u16 = <u16>(((<u64>(<u32>t1 << 11) + COMPRESS11_ADD) * COMPRESS11_MUL >> COMPRESS11_SHIFT) & 0x7FF);
				const c2: u16 = <u16>(((<u64>(<u32>t2 << 11) + COMPRESS11_ADD) * COMPRESS11_MUL >> COMPRESS11_SHIFT) & 0x7FF);
				const c3: u16 = <u16>(((<u64>(<u32>t3 << 11) + COMPRESS11_ADD) * COMPRESS11_MUL >> COMPRESS11_SHIFT) & 0x7FF);
				const c4: u16 = <u16>(((<u64>(<u32>t4 << 11) + COMPRESS11_ADD) * COMPRESS11_MUL >> COMPRESS11_SHIFT) & 0x7FF);
				const c5: u16 = <u16>(((<u64>(<u32>t5 << 11) + COMPRESS11_ADD) * COMPRESS11_MUL >> COMPRESS11_SHIFT) & 0x7FF);
				const c6: u16 = <u16>(((<u64>(<u32>t6 << 11) + COMPRESS11_ADD) * COMPRESS11_MUL >> COMPRESS11_SHIFT) & 0x7FF);
				const c7: u16 = <u16>(((<u64>(<u32>t7 << 11) + COMPRESS11_ADD) * COMPRESS11_MUL >> COMPRESS11_SHIFT) & 0x7FF);
				store<u8>(outPoly + 11*j,    <u8>(c0 >>  0));
				store<u8>(outPoly + 11*j+1,  <u8>((c0 >>  8) | (c1 << 3)));
				store<u8>(outPoly + 11*j+2,  <u8>((c1 >>  5) | (c2 << 6)));
				store<u8>(outPoly + 11*j+3,  <u8>(c2 >>  2));
				store<u8>(outPoly + 11*j+4,  <u8>((c2 >> 10) | (c3 << 1)));
				store<u8>(outPoly + 11*j+5,  <u8>((c3 >>  7) | (c4 << 4)));
				store<u8>(outPoly + 11*j+6,  <u8>((c4 >>  4) | (c5 << 7)));
				store<u8>(outPoly + 11*j+7,  <u8>(c5 >>  1));
				store<u8>(outPoly + 11*j+8,  <u8>((c5 >>  9) | (c6 << 2)));
				store<u8>(outPoly + 11*j+9,  <u8>((c6 >>  6) | (c7 << 5)));
				store<u8>(outPoly + 11*j+10, <u8>(c7 >>  3));
			}
		}
	}
}

/**
 * Decompress polyvec. FIPS 203 — k × ByteDecode_du then Decompress_du.
 * du=10 → read k×320 bytes; du=11 → read k×352 bytes.
 */
export function polyvec_decompress(pvOffset: i32, aOffset: i32, k: i32, du: i32): void {
	if (du == 10) {
		for (let i: i32 = 0; i < k; i++) {
			const polyBase: i32 = pvOffset + i * 512;
			const inPoly:   i32 = aOffset  + i * 320;
			for (let j: i32 = 0; j < 64; j++) {
				const b0: u32 = <u32>load<u8>(inPoly + 5*j);
				const b1: u32 = <u32>load<u8>(inPoly + 5*j+1);
				const b2: u32 = <u32>load<u8>(inPoly + 5*j+2);
				const b3: u32 = <u32>load<u8>(inPoly + 5*j+3);
				const b4: u32 = <u32>load<u8>(inPoly + 5*j+4);
				const t0: u32 = (b0 | (b1 << 8)) & 0x3FF;
				const t1: u32 = ((b1 >> 2) | (b2 << 6)) & 0x3FF;
				const t2: u32 = ((b2 >> 4) | (b3 << 4)) & 0x3FF;
				const t3: u32 = ((b3 >> 6) | (b4 << 2)) & 0x3FF;
				// Decompress_10: (x * q + 512) >> 10
				store<i16>(polyBase + (4*j+0)*2, <i16>((t0 * <u32>Q + 512) >> 10));
				store<i16>(polyBase + (4*j+1)*2, <i16>((t1 * <u32>Q + 512) >> 10));
				store<i16>(polyBase + (4*j+2)*2, <i16>((t2 * <u32>Q + 512) >> 10));
				store<i16>(polyBase + (4*j+3)*2, <i16>((t3 * <u32>Q + 512) >> 10));
			}
		}
	} else {
		// du == 11
		for (let i: i32 = 0; i < k; i++) {
			const polyBase: i32 = pvOffset + i * 512;
			const inPoly:   i32 = aOffset  + i * 352;
			for (let j: i32 = 0; j < 32; j++) {
				const b0: u32  = <u32>load<u8>(inPoly + 11*j);
				const b1: u32  = <u32>load<u8>(inPoly + 11*j+1);
				const b2: u32  = <u32>load<u8>(inPoly + 11*j+2);
				const b3: u32  = <u32>load<u8>(inPoly + 11*j+3);
				const b4: u32  = <u32>load<u8>(inPoly + 11*j+4);
				const b5: u32  = <u32>load<u8>(inPoly + 11*j+5);
				const b6: u32  = <u32>load<u8>(inPoly + 11*j+6);
				const b7: u32  = <u32>load<u8>(inPoly + 11*j+7);
				const b8: u32  = <u32>load<u8>(inPoly + 11*j+8);
				const b9: u32  = <u32>load<u8>(inPoly + 11*j+9);
				const b10: u32 = <u32>load<u8>(inPoly + 11*j+10);
				const t0: u32 = (b0 | (b1 << 8)) & 0x7FF;
				const t1: u32 = ((b1 >> 3) | (b2 << 5)) & 0x7FF;
				const t2: u32 = ((b2 >> 6) | (b3 << 2) | (b4 << 10)) & 0x7FF;
				const t3: u32 = ((b4 >> 1) | (b5 << 7)) & 0x7FF;
				const t4: u32 = ((b5 >> 4) | (b6 << 4)) & 0x7FF;
				const t5: u32 = ((b6 >> 7) | (b7 << 1) | (b8 << 9)) & 0x7FF;
				const t6: u32 = ((b8 >> 2) | (b9 << 6)) & 0x7FF;
				const t7: u32 = ((b9 >> 5) | (b10 << 3)) & 0x7FF;
				// Decompress_11: (x * q + 1024) >> 11
				store<i16>(polyBase + (8*j+0)*2, <i16>((t0 * <u32>Q + 1024) >> 11));
				store<i16>(polyBase + (8*j+1)*2, <i16>((t1 * <u32>Q + 1024) >> 11));
				store<i16>(polyBase + (8*j+2)*2, <i16>((t2 * <u32>Q + 1024) >> 11));
				store<i16>(polyBase + (8*j+3)*2, <i16>((t3 * <u32>Q + 1024) >> 11));
				store<i16>(polyBase + (8*j+4)*2, <i16>((t4 * <u32>Q + 1024) >> 11));
				store<i16>(polyBase + (8*j+5)*2, <i16>((t5 * <u32>Q + 1024) >> 11));
				store<i16>(polyBase + (8*j+6)*2, <i16>((t6 * <u32>Q + 1024) >> 11));
				store<i16>(polyBase + (8*j+7)*2, <i16>((t7 * <u32>Q + 1024) >> 11));
			}
		}
	}
}

// ── NTT / arithmetic ────────────────────────────────────────────────────────

/**
 * Apply forward NTT to all polynomials in the vector. FIPS 203 Algorithm 9.
 */
export function polyvec_ntt(pvOffset: i32, k: i32): void {
	for (let i: i32 = 0; i < k; i++) {
		poly_ntt(pvOffset + i * 512);
	}
}

/**
 * Apply inverse NTT to all polynomials in the vector. FIPS 203 Algorithm 10.
 */
export function polyvec_invntt(pvOffset: i32, k: i32): void {
	for (let i: i32 = 0; i < k; i++) {
		poly_invntt(pvOffset + i * 512);
	}
}

/**
 * Apply Barrett reduction to all coefficients. FIPS 203 — Reduce.
 */
export function polyvec_reduce(pvOffset: i32, k: i32): void {
	for (let i: i32 = 0; i < k; i++) {
		poly_reduce(pvOffset + i * 512);
	}
}

/**
 * FIPS 203 §7.2 modulus check — scan the decoded polyvec and report whether
 * every coefficient satisfies c < Q. Does not mutate pv.
 *
 * Input: pvOffset points at k polynomials written by polyvec_frombytes.
 *        Coefficients are stored as i16, in [0, 4095] post-frombytes.
 * Returns: 0 iff every coefficient is in [0, Q-1]; 1 otherwise.
 *
 * Constant-time over the input bytes (OR-accumulator, no early exit). ek is
 * public so timing is not sensitive, but CT style matches the rest of the
 * validator path and keeps the cost predictable.
 */
export function polyvec_modulus_check(pvOffset: i32, k: i32): i32 {
	let bad: i32 = 0;
	const n: i32 = k * 256;
	for (let i: i32 = 0; i < n; i++) {
		const c: i32 = <i32>load<i16>(pvOffset + i * 2);
		// c >= Q ⇔ (Q - 1 - c) is negative ⇔ its sign bit is set.
		// Arithmetic shift by 31 sprays that bit across the word.
		bad |= (Q - 1 - c) >> 31;
	}
	return bad & 1;
}

/**
 * Pointwise addition. No modular reduction.
 */
export function polyvec_add(rOffset: i32, aOffset: i32, bOffset: i32, k: i32): void {
	for (let i: i32 = 0; i < k; i++) {
		poly_add(rOffset + i*512, aOffset + i*512, bOffset + i*512);
	}
}

/**
 * Inner product in NTT domain: r = Σ_{i=0}^{k-1} a[i]·b[i], then reduce.
 * FIPS 203 — used in MatMul and dot-product steps of IND-CPA.
 */
export function polyvec_basemul_acc_montgomery(rOffset: i32, aOffset: i32, bOffset: i32, k: i32): void {
	// pq-crystals/kyber ref/polyvec.c polyvec_basemul_acc_montgomery()
	// r = a[0]*b[0]
	poly_basemul_montgomery(rOffset, aOffset, bOffset);
	// r += a[i]*b[i] for i=1..k-1
	// We need a scratch polynomial. Use a fixed scratch slot outside this function's inputs.
	// For scratch, use a temp region at a high fixed address (not in user polyvec slots).
	// Using offset 34816 (just past XOF_PRF_BUFFER end) for temp poly: 34816..35327 (512B).
	const tmpOffset: i32 = POLY_ACC_OFFSET;
	for (let i: i32 = 1; i < k; i++) {
		poly_basemul_montgomery(tmpOffset, aOffset + i*512, bOffset + i*512);
		poly_add(rOffset, rOffset, tmpOffset);
	}
	poly_reduce(rOffset);
}
