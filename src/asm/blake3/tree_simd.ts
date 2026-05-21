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
// src/asm/blake3/tree_simd.ts
//
// BLAKE3 4-parent batched tree-mode pipeline, BLAKE3 §2.5 (parent node
// chaining values) driven through the v128-external `compress4` kernel
// (BLAKE3 §5.3 SIMD).
//
// Four sibling parent merges at one tree level run in parallel: lane K
// consumes pair K (left_K || right_K) and emits the 32-byte parent CV.
// Per BLAKE3 §2.5 each parent compress at one level is independent of
// the others at the same level, so batching 4 same-level merges through
// `compress4` is bit-equivalent to firing `compress` four times with
// identical inputs.
//
// Drives the COMPRESS4_* staging buffers directly (see buffers.ts), the
// same staging discipline as `chunkBatch4` in chunk_simd.ts. ROOT never
// fires here: parentBatch4 is push-time batching that emits non-root
// parent CVs only, and the §2.5 ROOT compress always lives on a single-
// pair `compress` call inside `treeFinalizeRoot`.

import {
	COMPRESS4_CV_IN_OFFSET,
	COMPRESS4_MSG_IN_OFFSET,
	COMPRESS4_CTR_IN_OFFSET,
	COMPRESS4_BLEN_IN_OFFSET,
	COMPRESS4_FLAGS_IN_OFFSET,
	COMPRESS4_OUT_OFFSET,
	MODE_CV_OFFSET,
	MODE_FLAGS_OFFSET,
} from './buffers'
import { FLAG_PARENT } from './flags'
import { compress4 } from './compress_simd'

// Held in a WASM global so wipeBuffers() does not clobber it
// (debug-grade, non-sensitive). Reset via _resetParentBatch4CallCount.
let parentBatch4CallCount: u32 = 0

/**
 * Batch 4 parent merges in parallel via `compress4` (BLAKE3 §5.3
 * SIMD, §2.5 parent node chaining values).
 *
 * Inputs: 8 contiguous 32-byte CVs at `inputCvOff`, sourced as 4 pairs:
 *   pair 0 = inputCvOff[0..31]   || inputCvOff[32..63]
 *   pair 1 = inputCvOff[64..95]  || inputCvOff[96..127]
 *   pair 2 = inputCvOff[128..159] || inputCvOff[160..191]
 *   pair 3 = inputCvOff[192..223] || inputCvOff[224..255]
 *
 * Outputs: 4 contiguous 32-byte parent CVs at `outCvOff`. Lane K's
 * parent CV is `outCvOff + K*32`.
 *
 * BLAKE3 §2.5 parent compress invariants applied per lane:
 *   - CV input  = MODE_CV (per-mode starting CV; shared across all 4 lanes)
 *   - msg input = left || right (64 bytes, per-lane distinct)
 *   - counter   = 0 (shared across lanes, §2.5)
 *   - block_len = 64 (shared, §2.5)
 *   - flags     = MODE_FLAGS | FLAG_PARENT (shared, §2.5)
 *
 * Does NOT carry the ROOT flag. parentBatch4 is push-time batching; the
 * §2.5 ROOT compress is always at finalize and always single-pair (a
 * `compress1` call) so the ROOT-flag bookkeeping stays in tree.ts.
 */
export function parentBatch4(
	inputCvOff: i32,
	outCvOff:   i32,
): void {
	parentBatch4CallCount += 1

	// Stage 4 message blocks at COMPRESS4_MSG_IN: lane K's 64-byte block
	// at +K*64, sourced from inputCvOff + K*64 (which already lays out
	// left || right consecutively as the 8 input CVs are 4 pairs of 64
	// bytes each). One 256-byte copy lands all four lanes' messages.
	memory.copy(COMPRESS4_MSG_IN_OFFSET, inputCvOff, 256)

	// All four lanes share the same per-mode CV (BLAKE3 §2.5: parent
	// compress key = chaining-mode CV, identical across siblings at one
	// level). Splat MODE_CV across the four 32-byte slots.
	memory.copy(COMPRESS4_CV_IN_OFFSET +  0, MODE_CV_OFFSET, 32)
	memory.copy(COMPRESS4_CV_IN_OFFSET + 32, MODE_CV_OFFSET, 32)
	memory.copy(COMPRESS4_CV_IN_OFFSET + 64, MODE_CV_OFFSET, 32)
	memory.copy(COMPRESS4_CV_IN_OFFSET + 96, MODE_CV_OFFSET, 32)

	// BLAKE3 §2.5: parent compress counter is 0 for all lanes. Zero the
	// 4 × 8-byte counter slots in one memory.fill.
	memory.fill(COMPRESS4_CTR_IN_OFFSET, 0, 32)

	// BLAKE3 §2.5: parent compress block_len is 64 for all lanes.
	store<u32>(COMPRESS4_BLEN_IN_OFFSET +  0, 64)
	store<u32>(COMPRESS4_BLEN_IN_OFFSET +  4, 64)
	store<u32>(COMPRESS4_BLEN_IN_OFFSET +  8, 64)
	store<u32>(COMPRESS4_BLEN_IN_OFFSET + 12, 64)

	// Shared flags across all four lanes (BLAKE3 §5.3 SIMD — the §2.2
	// `d` input is broadcast across lanes in compress4): PARENT plus
	// the per-mode bits OR'd onto every compress (BLAKE3 §2.3 Modes).
	store<u32>(COMPRESS4_FLAGS_IN_OFFSET, FLAG_PARENT | load<u32>(MODE_FLAGS_OFFSET))

	compress4()

	// Lane K's 32-byte parent CV is the first half of its 64-byte slot
	// in COMPRESS4_OUT. Deinterleave to outCvOff: K * 32 bytes packed.
	memory.copy(outCvOff +  0, COMPRESS4_OUT_OFFSET +   0, 32)
	memory.copy(outCvOff + 32, COMPRESS4_OUT_OFFSET +  64, 32)
	memory.copy(outCvOff + 64, COMPRESS4_OUT_OFFSET + 128, 32)
	memory.copy(outCvOff + 96, COMPRESS4_OUT_OFFSET + 192, 32)
}

/**
 * Test-only counter: number of `parentBatch4` invocations since the last
 * `_resetParentBatch4CallCount()` call. NOT part of the consumer-facing
 * Blake3Exports interface; wired exclusively for the
 * `blake3-parent-dispatch` unit test that asserts production
 * `treePushChunk` actually dispatches parent merges to `compress4` for
 * inputs producing ≥ 8 chunks (rather than silently falling through to
 * `compress` single-pair merges).
 *
 * Held in a WebAssembly global so `wipeBuffers()` does not clear it.
 */
export function _getParentBatch4CallCount(): u32 {
	return parentBatch4CallCount
}

/**
 * Reset the test-only parent-batch counter. Paired with
 * `_getParentBatch4CallCount`. Tests call this before each assertion to
 * isolate the count from prior dispatch activity on the same module
 * instance.
 */
export function _resetParentBatch4CallCount(): void {
	parentBatch4CallCount = 0
}
