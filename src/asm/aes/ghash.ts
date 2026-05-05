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
// src/asm/aes/ghash.ts
//
// GHASH function from NIST SP 800-38D §6.4. Builds on the GF(2^128)
// multiply primitive in gf128.ts.
//
//   GHASH_H(X) = Y_m
//   Y_0 = 0^128
//   Y_i = (Y_{i-1} XOR X_i) · H    for i = 1..m
//
// Each X_i is a 128-bit block. Caller is responsible for partitioning the
// input into 16-byte blocks and zero-padding any partial final block.
//
// The running accumulator lives in GHASH_ACC_BUFFER. `ghashStart` zeroes it;
// each `ghashAbsorb*` updates it; the final state is the GHASH output.

import {
	GHASH_ACC_OFFSET,
	GCM_SCRATCH_OFFSET,
} from './buffers'

import { gf128MulH } from './gf128'

// ── Internal helpers ───────────────────────────────────────────────────────

@inline function xor16Into(srcOff: i32, dstOff: i32): void {
	store<u64>(dstOff,     load<u64>(dstOff)     ^ load<u64>(srcOff));
	store<u64>(dstOff + 8, load<u64>(dstOff + 8) ^ load<u64>(srcOff + 8));
}

// ── Public API ─────────────────────────────────────────────────────────────

/** Reset the running GHASH accumulator to 0^128 (Y_0 in §6.4). */
export function ghashStart(): void {
	store<u64>(GHASH_ACC_OFFSET,     0);
	store<u64>(GHASH_ACC_OFFSET + 8, 0);
}

/**
 * Absorb a single 16-byte block at srcOff into GHASH_ACC:
 *
 *     ACC = (ACC XOR src[16]) · H
 *
 * Implements one iteration of the §6.4 recurrence.
 */
export function ghashAbsorbBlock(srcOff: i32): void {
	xor16Into(srcOff, GHASH_ACC_OFFSET);
	gf128MulH();
}

/**
 * Absorb `len` bytes from `srcOff` into GHASH_ACC. Full 16-byte blocks are
 * absorbed directly; a final partial block is zero-padded to 16 bytes
 * (using GCM_SCRATCH_OFFSET as scratch) before absorption, per the GCM
 * convention (§7.1 step 5: "0^v" / "0^u" zero-padding of A and C).
 */
export function ghashAbsorbWithLen(srcOff: i32, len: i32): void {
	const fullBlocks: i32 = len >> 4;
	const tailBytes: i32 = len & 0x0F;

	for (let i: i32 = 0; i < fullBlocks; i++) {
		xor16Into(srcOff + i * 16, GHASH_ACC_OFFSET);
		gf128MulH();
	}

	if (tailBytes != 0) {
		// Zero scratch, copy the partial-block bytes in, absorb.
		store<u64>(GCM_SCRATCH_OFFSET,     0);
		store<u64>(GCM_SCRATCH_OFFSET + 8, 0);
		const tailOff: i32 = srcOff + fullBlocks * 16;
		for (let k: i32 = 0; k < tailBytes; k++) {
			store<u8>(GCM_SCRATCH_OFFSET + k, load<u8>(tailOff + k));
		}
		xor16Into(GCM_SCRATCH_OFFSET, GHASH_ACC_OFFSET);
		gf128MulH();
	}
}

/**
 * Absorb the final 16-byte length-encoding block:
 *
 *     [|A| in bits]_64 || [|C| in bits]_64       (both big-endian)
 *
 * After this call, GHASH_ACC holds the value `S` of SP 800-38D §7.1 step 5
 * (or §7.2 step 6 for the AD direction). Inputs are bit-lengths (already
 * left-shifted by 3 by the caller from byte counts).
 *
 * AssemblyScript stores u64 little-endian; we manually byte-swap to the
 * big-endian byte order required by GCM.
 */
export function ghashFinalize(aadBits: u64, ctBits: u64): void {
	store<u64>(GCM_SCRATCH_OFFSET,     bswap<u64>(aadBits));
	store<u64>(GCM_SCRATCH_OFFSET + 8, bswap<u64>(ctBits));
	xor16Into(GCM_SCRATCH_OFFSET, GHASH_ACC_OFFSET);
	gf128MulH();
}
