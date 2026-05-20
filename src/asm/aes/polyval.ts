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
// src/asm/aes/polyval.ts
//
// POLYVAL absorber (RFC 8452 §3, Appendix A) for AES-GCM-SIV.
// Mirrors ghash.ts (start / absorbBlock / absorbWithLen / finalize).
// Reflection wrapper over gf128MulH; accumulator aliases on
// GHASH_ACC_OFFSET (POLYVAL and GHASH are runtime-exclusive).
// See docs/asm_aes.md#polyval-bridge.

import {
	GHASH_ACC_OFFSET,
	GCM_SCRATCH_OFFSET,
	H_OFFSET,
} from './buffers'

import { gf128MulH, gf128InitTable, byteReverse16, mulXGhash } from './gf128'

// ── Internal helpers ───────────────────────────────────────────────────────

@inline function xor16Into(srcOff: i32, dstOff: i32): void {
	store<u64>(dstOff,     load<u64>(dstOff)     ^ load<u64>(srcOff));
	store<u64>(dstOff + 8, load<u64>(dstOff + 8) ^ load<u64>(srcOff + 8));
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Initialise POLYVAL with a fresh authentication subkey at `authKeyOff`
 * (16 bytes, POLYVAL bit convention). Sets up the GF128 table to multiply
 * by `mulX_GHASH(ByteReverse(authKey))` and zeroes the accumulator.
 *
 * Reference: RFC 8452 Appendix A, the POLYVAL/GHASH bridge formula.
 */
export function polyvalStart(authKeyOff: i32): void {
	// 1. ByteReverse(authKey) → GCM_SCRATCH (16-byte scratch).
	byteReverse16(authKeyOff, GCM_SCRATCH_OFFSET);
	// 2. mulX_GHASH on the reversed key, written to H_OFFSET, gf128InitTable
	//    reads H from H_OFFSET.
	mulXGhash(GCM_SCRATCH_OFFSET, H_OFFSET);
	// 3. Build the 4-bit windowed multiply table from the reflected H.
	gf128InitTable();
	// 4. Reset the running accumulator to 0.
	store<u64>(GHASH_ACC_OFFSET,     0);
	store<u64>(GHASH_ACC_OFFSET + 8, 0);
	// 5. Wipe scratch, it briefly held a derivative of the auth key.
	store<u64>(GCM_SCRATCH_OFFSET,     0);
	store<u64>(GCM_SCRATCH_OFFSET + 8, 0);
}

/**
 * Absorb a single 16-byte block at `srcOff` into the POLYVAL accumulator:
 *
 *     ACC = (ACC XOR ByteReverse(src[16])) · H_reflected   (in GHASH field)
 *
 * Reference: RFC 8452 §3 POLYVAL recurrence, executed under the
 * Appendix A bridge.
 */
export function polyvalAbsorbBlock(srcOff: i32): void {
	byteReverse16(srcOff, GCM_SCRATCH_OFFSET);
	xor16Into(GCM_SCRATCH_OFFSET, GHASH_ACC_OFFSET);
	gf128MulH();
	store<u64>(GCM_SCRATCH_OFFSET,     0);
	store<u64>(GCM_SCRATCH_OFFSET + 8, 0);
}

/**
 * Absorb a partial last block: copy `len` bytes (1 ≤ len ≤ 16) from
 * `srcOff` into a zero-padded 16-byte scratch, then absorb. Per RFC 8452
 * §4 the final POLYVAL block from each of AAD and PT is zero-padded to a
 * full 128-bit block before absorption (along with the explicit length
 * block, which is always full-width).
 */
export function polyvalAbsorbWithLen(srcOff: i32, len: i32): void {
	store<u64>(GCM_SCRATCH_OFFSET,     0);
	store<u64>(GCM_SCRATCH_OFFSET + 8, 0);
	for (let k: i32 = 0; k < len; k++) {
		store<u8>(GCM_SCRATCH_OFFSET + k, load<u8>(srcOff + k));
	}
	byteReverse16(GCM_SCRATCH_OFFSET, GCM_SCRATCH_OFFSET);
	xor16Into(GCM_SCRATCH_OFFSET, GHASH_ACC_OFFSET);
	gf128MulH();
	store<u64>(GCM_SCRATCH_OFFSET,     0);
	store<u64>(GCM_SCRATCH_OFFSET + 8, 0);
}

/**
 * Write the final POLYVAL output (16 bytes, POLYVAL bit convention) to
 * `dstOff`. Byte-reverses the running accumulator and zeroes it.
 */
export function polyvalFinalize(dstOff: i32): void {
	byteReverse16(GHASH_ACC_OFFSET, dstOff);
	store<u64>(GHASH_ACC_OFFSET,     0);
	store<u64>(GHASH_ACC_OFFSET + 8, 0);
}
