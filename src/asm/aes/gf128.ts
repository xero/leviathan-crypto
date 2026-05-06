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
// src/asm/aes/gf128.ts
//
// GF(2^128) primitive used by AES-GCM (Phase 4a). Implements the
// "multiplication operation on blocks" of NIST SP 800-38D §6.3, exposed as
// a 4-bit windowed multiply by the fixed hash subkey H.
//
// Storage convention (SP 800-38D §6.3): a 128-bit block x_0 x_1 ... x_127
// represents the polynomial f(u) = x_0 + x_1·u + x_2·u^2 + … + x_127·u^127.
// In our 16-byte storage:
//   - bit 7 (MSB) of byte 0   = x_0   (u^0  coefficient — constant term)
//   - bit 0 (LSB) of byte 0   = x_7   (u^7)
//   - bit 7      of byte 1   = x_8
//   - …
//   - bit 0 (LSB) of byte 15 = x_127 (u^127 coefficient — highest power)
//
// The reduction polynomial bit-string R = `11100001 || 0^120` (representing
// u^7 + u^2 + u + 1) is byte 0 = 0xE1, all others zero. The full degree-128
// reduction polynomial is u^128 + u^7 + u^2 + u + 1.
//
// Multiplication algorithm: 4-bit windowed table indexed by nibbles of the
// running state. Build M[16] where M[k] = (sub-polynomial of nibble value k)
// · H. Convention: bit 3 of k → u^0 coefficient, bit 2 → u^1, bit 1 → u^2,
// bit 0 → u^3 (i.e. nibble's high bit = lowest power, matching GHASH byte
// order's "MSB = lowest power").
//
// Constant-time note. M[k] is read with k = a nibble of the secret-derived
// running state. On real CPUs this is NOT cache-line constant-time — the
// classic 4-bit-windowed GHASH side-channel surface is well documented.
// This is the same approach BoringSSL/OpenSSL/RustCrypto ship for
// pre-PCLMULQDQ paths. PCLMULQDQ is not available in WebAssembly SIMD,
// and table-free schoolbook is too slow for production use. The browser
// sandbox mitigates direct cross-process cache observation; full mitigation
// would require either CPU carry-less-multiply support or hardware-tied
// AES-GCM-SIV (phase 4b).

// ──────────────────────────────────────────────────────────────────────────
// Phase 4b note. AES-GCM-SIV (RFC 8452) uses POLYVAL, a sibling
// universal hash in a different field: reduction polynomial
// x^128 + x^127 + x^126 + x^121 + 1 (vs GHASH's x^128 + x^7 + x^2 + x + 1)
// and a bit-within-byte ordering where bit 0 of byte 0 is u^0 (vs GHASH's
// bit 7).
//
// RFC 8452 §3 gives the bridge:
//
//     POLYVAL(H, X_1..n) = ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
//                                            ByteReverse(X_1..n)))
//
// where ByteReverse reverses byte order in a 16-byte string. The
// within-byte bit flip falls out for free from the differing GHASH /
// POLYVAL bit-interpretation conventions — RFC 8452 §3: "the differing
// interpretations of bit order takes care of reversing the bits within
// each byte, and then reversing the bytes does the rest."
//
// Phase 4b chose path (a): a reflection wrapper around the existing
// gf128MulH multiplier. Per-SIV-operation setup byte-reverses the
// POLYVAL hash subkey, applies mulX_GHASH (defined in this file as
// `mulXGhash`), and feeds the result to `gf128InitTable`. Per-block
// absorption byte-reverses the block into GHASH bit convention, XORs
// into the running accumulator, and multiplies by H. `polyvalFinalize`
// byte-reverses the accumulator back to POLYVAL bit convention.
// `byteReverse16` and `mulXGhash` below are the two helpers required;
// the existing GF(2^128) primitive does not change.
//
// Path (b) — a POLYVAL-native multiplier with reduction byte 0x87 in
// LSB-first storage — was rejected: it would have added ~250 lines of
// parallel multiplier and a second 256-byte table for no algorithmic
// benefit on a runtime that lacks PCLMULQDQ.
// ──────────────────────────────────────────────────────────────────────────

import {
	H_OFFSET,
	GHASH_ACC_OFFSET,
	GF128_TABLE_OFFSET,
} from './buffers'

// ── Low-level helpers ──────────────────────────────────────────────────────

/**
 * Multiply the 128-bit value at `buf` by u in GF(2^128), storing the result
 * back at `buf`. Equivalent to SP 800-38D §6.3 Algorithm 1's V update step:
 *
 *     carry = LSB1(V)         // x_127 of the input
 *     V = V >> 1              // shift right (prepend 0, discard rightmost bit)
 *     if carry: V ^= R        // fold u^128 = u^7+u^2+u+1 back in
 *
 * Constant-time: every operation is a fixed-shape byte read/write or a
 * branch-free arithmetic mask.
 */
@inline function gf128MulU(buf: i32): void {
	// Snapshot original bytes; the shift reads byte j and j-1 of the *old*
	// value to compute the new byte j.
	const b0  = load<u8>(buf +  0);
	const b1  = load<u8>(buf +  1);
	const b2  = load<u8>(buf +  2);
	const b3  = load<u8>(buf +  3);
	const b4  = load<u8>(buf +  4);
	const b5  = load<u8>(buf +  5);
	const b6  = load<u8>(buf +  6);
	const b7  = load<u8>(buf +  7);
	const b8  = load<u8>(buf +  8);
	const b9  = load<u8>(buf +  9);
	const b10 = load<u8>(buf + 10);
	const b11 = load<u8>(buf + 11);
	const b12 = load<u8>(buf + 12);
	const b13 = load<u8>(buf + 13);
	const b14 = load<u8>(buf + 14);
	const b15 = load<u8>(buf + 15);

	const carry: u32 = (<u32>b15) & 1;
	const reduce: u8 = <u8>(carry * 0xE1);

	store<u8>(buf +  0, ((b0  >> 1)              ) ^ reduce);
	store<u8>(buf +  1, ((b1  >> 1) | ((b0  & 1) << 7)));
	store<u8>(buf +  2, ((b2  >> 1) | ((b1  & 1) << 7)));
	store<u8>(buf +  3, ((b3  >> 1) | ((b2  & 1) << 7)));
	store<u8>(buf +  4, ((b4  >> 1) | ((b3  & 1) << 7)));
	store<u8>(buf +  5, ((b5  >> 1) | ((b4  & 1) << 7)));
	store<u8>(buf +  6, ((b6  >> 1) | ((b5  & 1) << 7)));
	store<u8>(buf +  7, ((b7  >> 1) | ((b6  & 1) << 7)));
	store<u8>(buf +  8, ((b8  >> 1) | ((b7  & 1) << 7)));
	store<u8>(buf +  9, ((b9  >> 1) | ((b8  & 1) << 7)));
	store<u8>(buf + 10, ((b10 >> 1) | ((b9  & 1) << 7)));
	store<u8>(buf + 11, ((b11 >> 1) | ((b10 & 1) << 7)));
	store<u8>(buf + 12, ((b12 >> 1) | ((b11 & 1) << 7)));
	store<u8>(buf + 13, ((b13 >> 1) | ((b12 & 1) << 7)));
	store<u8>(buf + 14, ((b14 >> 1) | ((b13 & 1) << 7)));
	store<u8>(buf + 15, ((b15 >> 1) | ((b14 & 1) << 7)));
}

/**
 * Multiply the 128-bit value at `buf` by u^4 = four consecutive `· u` steps.
 * Used between nibble accumulations in the windowed multiply.
 */
@inline function gf128MulU4(buf: i32): void {
	gf128MulU(buf);
	gf128MulU(buf);
	gf128MulU(buf);
	gf128MulU(buf);
}

/** Copy 16 bytes from src to dst. */
@inline function copy16(src: i32, dst: i32): void {
	store<u64>(dst,     load<u64>(src));
	store<u64>(dst + 8, load<u64>(src + 8));
}

/** XOR 16 bytes from src into dst (dst ^= src). */
@inline function xor16(src: i32, dst: i32): void {
	store<u64>(dst,     load<u64>(dst)     ^ load<u64>(src));
	store<u64>(dst + 8, load<u64>(dst + 8) ^ load<u64>(src + 8));
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Build the 4-bit windowed multiplication table from H. Reads 16 bytes from
 * H_OFFSET, writes 256 bytes (16 entries × 16 bytes) to GF128_TABLE_OFFSET.
 *
 * Convention (SP 800-38D §6.3 read in conjunction with our GHASH byte order):
 * for a nibble integer value `k` representing four bits at consecutive
 * polynomial positions, bit 3 of `k` weights u^0 (constant), bit 2 weights
 * u^1, bit 1 weights u^2, bit 0 weights u^3. Hence:
 *
 *     M[8] = H        (bit 3 set → u^0 coefficient = 1)
 *     M[4] = H · u    (u^1)
 *     M[2] = H · u^2
 *     M[1] = H · u^3
 *
 * The other entries are XOR combinations.
 */
export function gf128InitTable(): void {
	const T: i32 = GF128_TABLE_OFFSET;

	// M[0] = 0
	store<u64>(T +  0, 0);
	store<u64>(T +  8, 0);

	// M[8] = H
	copy16(H_OFFSET, T + 8 * 16);

	// M[4] = M[8] · u
	copy16(T + 8 * 16, T + 4 * 16);
	gf128MulU(T + 4 * 16);

	// M[2] = M[4] · u
	copy16(T + 4 * 16, T + 2 * 16);
	gf128MulU(T + 2 * 16);

	// M[1] = M[2] · u
	copy16(T + 2 * 16, T + 1 * 16);
	gf128MulU(T + 1 * 16);

	// M[3]  = M[2] XOR M[1]
	copy16(T + 2 * 16, T + 3 * 16);
	xor16 (T + 1 * 16, T + 3 * 16);

	// M[5]  = M[4] XOR M[1]
	copy16(T + 4 * 16, T + 5 * 16);
	xor16 (T + 1 * 16, T + 5 * 16);

	// M[6]  = M[4] XOR M[2]
	copy16(T + 4 * 16, T + 6 * 16);
	xor16 (T + 2 * 16, T + 6 * 16);

	// M[7]  = M[4] XOR M[2] XOR M[1]
	copy16(T + 6 * 16, T + 7 * 16);
	xor16 (T + 1 * 16, T + 7 * 16);

	// M[9]  = M[8] XOR M[1]
	copy16(T + 8 * 16, T +  9 * 16);
	xor16 (T + 1 * 16, T +  9 * 16);

	// M[10] = M[8] XOR M[2]
	copy16(T + 8 * 16, T + 10 * 16);
	xor16 (T + 2 * 16, T + 10 * 16);

	// M[11] = M[8] XOR M[2] XOR M[1]
	copy16(T + 10 * 16, T + 11 * 16);
	xor16 (T +  1 * 16, T + 11 * 16);

	// M[12] = M[8] XOR M[4]
	copy16(T + 8 * 16, T + 12 * 16);
	xor16 (T + 4 * 16, T + 12 * 16);

	// M[13] = M[12] XOR M[1]
	copy16(T + 12 * 16, T + 13 * 16);
	xor16 (T +  1 * 16, T + 13 * 16);

	// M[14] = M[12] XOR M[2]
	copy16(T + 12 * 16, T + 14 * 16);
	xor16 (T +  2 * 16, T + 14 * 16);

	// M[15] = M[12] XOR M[2] XOR M[1]
	copy16(T + 14 * 16, T + 15 * 16);
	xor16 (T +  1 * 16, T + 15 * 16);
}

/**
 * Compute Z = X · H in GF(2^128) using the precomputed 4-bit windowed
 * table at GF128_TABLE_OFFSET. The output is written to GHASH_ACC_OFFSET;
 * the input is read from GHASH_ACC_OFFSET (in-place).
 *
 * Algorithm: Horner's rule on nibbles, processing from highest power to
 * lowest, multiplying by u^4 between accumulations:
 *
 *     Z = 0
 *     for j = 15 down to 0:
 *         Z = Z · u^4 XOR M[ X[j] & 0x0F ]    // low nibble: powers 8j+4..8j+7
 *         Z = Z · u^4 XOR M[ X[j] >> 4   ]    // high nibble: powers 8j..8j+3
 *
 * After 32 iterations Z = X · H.
 */
export function gf128MulH(): void {
	const T: i32 = GF128_TABLE_OFFSET;
	const X: i32 = GHASH_ACC_OFFSET;

	// We need to read X first (it's the input), then we can reuse the buffer
	// as the running Z accumulator. Snapshot X into 16 bytes of locals (two
	// u64) so we don't trash it as we update Z.
	const x_lo: u64 = load<u64>(X);
	const x_hi: u64 = load<u64>(X + 8);

	// Z = 0
	store<u64>(X,     0);
	store<u64>(X + 8, 0);

	// Process nibbles from highest power to lowest. In our byte-storage
	// convention, byte 15 holds the highest-power coefficients (u^120..u^127);
	// within each byte the LOW nibble holds the *higher* powers (8j+4..8j+7).
	for (let j: i32 = 15; j >= 0; j--) {
		// Extract byte j from the snapshot.
		// Bytes 0..7 are in x_lo (byte 0 = low byte), bytes 8..15 in x_hi.
		const byteVal: u32 =
			j < 8
				? <u32>((x_lo >> (<u64>(j * 8))) & 0xFF)
				: <u32>((x_hi >> (<u64>((j - 8) * 8))) & 0xFF);

		const lowNib:  u32 = byteVal & 0x0F;
		const highNib: u32 = byteVal >> 4;

		// Z = Z · u^4 XOR M[lowNib]
		gf128MulU4(X);
		xor16(T + (<i32>lowNib)  * 16, X);

		// Z = Z · u^4 XOR M[highNib]
		gf128MulU4(X);
		xor16(T + (<i32>highNib) * 16, X);
	}
}

// ── POLYVAL/GHASH bridge helpers (RFC 8452 §3, Appendix A) ─────────────────

/**
 * Reverse the byte order of a 16-byte block. Implements the `ByteReverse`
 * operation from RFC 8452 §3, used by the POLYVAL/GHASH bridge formula:
 *
 *     POLYVAL(H, X_1..n) = ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
 *                                            ByteReverse(X_1..n)))
 *
 * Implemented as a single `v128.shuffle<u8>` with the inverse-byte-index
 * pattern. `srcOff` and `dstOff` may alias.
 */
export function byteReverse16(srcOff: i32, dstOff: i32): void {
	const x = v128.load(srcOff);
	v128.store(dstOff, v128.shuffle<u8>(x, x,
		15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
	));
}

/**
 * Multiply the 128-bit value at `srcOff` by x in the GHASH field, writing
 * the result to `dstOff`. `srcOff` and `dstOff` may alias.
 *
 * Implements `mulX_GHASH` from RFC 8452 §3 / Appendix A. The operation is
 * one position right-shift in the GHASH bit convention with conditional
 * reduction-byte XOR: if the LSB of input byte 15 is 1 (i.e. u^127's
 * coefficient was set), XOR the reduction byte 0xE1 into output byte 0
 * after the shift. Each byte's bits shift right by one position; the
 * carry-out from each byte populates the MSB of the next byte.
 *
 * This is the same `· u` transform that `gf128MulU` applies in place;
 * exposed here as src→dst for use during POLYVAL key-table setup, where
 * the byte-reversed authentication subkey is multiplied by x and then
 * loaded as H for the existing `gf128InitTable` builder.
 */
export function mulXGhash(srcOff: i32, dstOff: i32): void {
	const b0  = load<u8>(srcOff +  0);
	const b1  = load<u8>(srcOff +  1);
	const b2  = load<u8>(srcOff +  2);
	const b3  = load<u8>(srcOff +  3);
	const b4  = load<u8>(srcOff +  4);
	const b5  = load<u8>(srcOff +  5);
	const b6  = load<u8>(srcOff +  6);
	const b7  = load<u8>(srcOff +  7);
	const b8  = load<u8>(srcOff +  8);
	const b9  = load<u8>(srcOff +  9);
	const b10 = load<u8>(srcOff + 10);
	const b11 = load<u8>(srcOff + 11);
	const b12 = load<u8>(srcOff + 12);
	const b13 = load<u8>(srcOff + 13);
	const b14 = load<u8>(srcOff + 14);
	const b15 = load<u8>(srcOff + 15);

	const carry: u32 = (<u32>b15) & 1;
	const reduce: u8 = <u8>(carry * 0xE1);

	store<u8>(dstOff +  0, ((b0  >> 1)              ) ^ reduce);
	store<u8>(dstOff +  1, ((b1  >> 1) | ((b0  & 1) << 7)));
	store<u8>(dstOff +  2, ((b2  >> 1) | ((b1  & 1) << 7)));
	store<u8>(dstOff +  3, ((b3  >> 1) | ((b2  & 1) << 7)));
	store<u8>(dstOff +  4, ((b4  >> 1) | ((b3  & 1) << 7)));
	store<u8>(dstOff +  5, ((b5  >> 1) | ((b4  & 1) << 7)));
	store<u8>(dstOff +  6, ((b6  >> 1) | ((b5  & 1) << 7)));
	store<u8>(dstOff +  7, ((b7  >> 1) | ((b6  & 1) << 7)));
	store<u8>(dstOff +  8, ((b8  >> 1) | ((b7  & 1) << 7)));
	store<u8>(dstOff +  9, ((b9  >> 1) | ((b8  & 1) << 7)));
	store<u8>(dstOff + 10, ((b10 >> 1) | ((b9  & 1) << 7)));
	store<u8>(dstOff + 11, ((b11 >> 1) | ((b10 & 1) << 7)));
	store<u8>(dstOff + 12, ((b12 >> 1) | ((b11 & 1) << 7)));
	store<u8>(dstOff + 13, ((b13 >> 1) | ((b12 & 1) << 7)));
	store<u8>(dstOff + 14, ((b14 >> 1) | ((b13 & 1) << 7)));
	store<u8>(dstOff + 15, ((b15 >> 1) | ((b14 & 1) << 7)));
}
