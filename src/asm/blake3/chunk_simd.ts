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
// src/asm/blake3/chunk_simd.ts
//
// BLAKE3 4-chunk batched chunk pipeline, BLAKE3 §2.4 driven through the
// v128-external `compress4` kernel (BLAKE3 §5.3 SIMD).
//
// Four contiguous 1024-byte chunks run in parallel: for each block
// position 0..15, lane K of one `compress4` call advances chunk
// (baseChunkIndex + K)'s block-by-block CV chain. Counters stay
// constant within the batch (the §2.4 chunk counter is per chunk, not
// per block); block_len is 64 for every block (batched chunks are
// always full 1024-byte chunks, partial trailing input falls back to
// the single-chunk path in chunk.ts).
//
// Drives the COMPRESS4_* staging buffers directly (see buffers.ts)
// without going through chunk.ts's single-chunk state machine. ROOT
// never fires here: chunk-level dispatch produces chunk CVs that feed
// the §2.5 tree assembly, and §2.5 ROOT lives on the topmost parent
// compress in treeFinalizeRoot.

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
import { FLAG_CHUNK_START, FLAG_CHUNK_END } from './flags'
import { compress4 } from './compress_simd'

// Held in a WASM global so wipeBuffers() does not clobber it
// (debug-grade, non-sensitive). Reset via _resetBatch4CallCount.
let batch4CallCount: u32 = 0

/**
 * Hash 4 contiguous 1024-byte chunks in parallel via `compress4`.
 *
 * BLAKE3 §2.4 chunk state, four lanes in parallel. Each lane K
 * processes one full 1024-byte chunk starting at `inputOff + K*1024`,
 * with the chunk counter = `baseChunkIndex + K`. Lane K's 32-byte
 * chunk CV is written to `outCvOff + K*32` (a packed 128-byte region).
 *
 * Drives the COMPRESS4_* staging buffers directly. Each of the 16
 * block positions runs one `compress4` call:
 *   - Block 0:      flags = MODE_FLAGS | CHUNK_START
 *   - Blocks 1..14: flags = MODE_FLAGS
 *   - Block 15:     flags = MODE_FLAGS | CHUNK_END
 * Counters are constant per lane across all 16 blocks (BLAKE3 §2.4
 * chunk counter rule). Block_len is 64 for every block (full-chunk
 * batches only; partial last chunks fall back to the single-chunk
 * path in chunk.ts).
 *
 * Precondition: caller has populated MODE_CV (the per-mode starting
 * CV for this hash) and MODE_FLAGS, the same as the single-chunk path
 * expects. Does NOT touch ROOT_STATE_* (no ROOT compress fires here;
 * chunk-level dispatch never produces the §2.5 root).
 */
export function chunkBatch4(
	inputOff:       i32,
	baseChunkIndex: u64,
	outCvOff:       i32,
): void {
	batch4CallCount += 1

	// All four lanes start from the same MODE_CV (BLAKE3 §2.4): one
	// memory.copy per lane splats the 32 mode-CV bytes across the four
	// 32-byte slots in COMPRESS4_CV_IN.
	memory.copy(COMPRESS4_CV_IN_OFFSET +  0, MODE_CV_OFFSET, 32)
	memory.copy(COMPRESS4_CV_IN_OFFSET + 32, MODE_CV_OFFSET, 32)
	memory.copy(COMPRESS4_CV_IN_OFFSET + 64, MODE_CV_OFFSET, 32)
	memory.copy(COMPRESS4_CV_IN_OFFSET + 96, MODE_CV_OFFSET, 32)

	// Lane K's chunk counter is `baseChunkIndex + K` (BLAKE3 §2.4). The
	// counter is constant for the whole chunk; block-level updates do
	// not touch it.
	for (let k: i32 = 0; k < 4; k++) {
		const ctr:  u64 = baseChunkIndex + (k as u64)
		const slot: i32 = COMPRESS4_CTR_IN_OFFSET + (k << 3)
		store<u32>(slot + 0, ctr as u32)
		store<u32>(slot + 4, (ctr >> 32) as u32)
	}

	// Every block in a batched chunk is a full 64 bytes (BLAKE3 §2.2
	// `b` = 64); partial trailing chunks go through the single-chunk
	// path in chunk.ts, so chunkBatch4 never sees a short last block.
	store<u32>(COMPRESS4_BLEN_IN_OFFSET +  0, 64)
	store<u32>(COMPRESS4_BLEN_IN_OFFSET +  4, 64)
	store<u32>(COMPRESS4_BLEN_IN_OFFSET +  8, 64)
	store<u32>(COMPRESS4_BLEN_IN_OFFSET + 12, 64)

	const modeFlags: u32 = load<u32>(MODE_FLAGS_OFFSET)

	for (let b: i32 = 0; b < 16; b++) {
		// Stage lane K's block at COMPRESS4_MSG_IN + K*64, sourced from
		// inputOff + K*1024 + b*64. Lanes are 1024 bytes apart in the
		// caller's input region; blocks are 64 bytes apart within a chunk.
		const bOff: i32 = b << 6
		memory.copy(COMPRESS4_MSG_IN_OFFSET +   0, inputOff +    0 + bOff, 64)
		memory.copy(COMPRESS4_MSG_IN_OFFSET +  64, inputOff + 1024 + bOff, 64)
		memory.copy(COMPRESS4_MSG_IN_OFFSET + 128, inputOff + 2048 + bOff, 64)
		memory.copy(COMPRESS4_MSG_IN_OFFSET + 192, inputOff + 3072 + bOff, 64)

		// BLAKE3 §2.4: CHUNK_START on block 0 only, CHUNK_END on block 15
		// only, no structural flag on middle blocks. All four lanes share
		// the same flag value at each block position; that's what lets a
		// 4-chunk batch ride on `compress4`, which broadcasts one flags
		// word across all lanes (BLAKE3 §5.3 SIMD).
		let blockFlags: u32 = modeFlags
		if (b ==  0) blockFlags |= FLAG_CHUNK_START
		if (b == 15) blockFlags |= FLAG_CHUNK_END
		store<u32>(COMPRESS4_FLAGS_IN_OFFSET, blockFlags)

		compress4()

		// Inter-block CV chain (BLAKE3 §2.4): block b+1 consumes block
		// b's output as its input CV. Lane K's new CV is the first 32
		// bytes of its 64-byte slot in COMPRESS4_OUT; copy each lane
		// back to COMPRESS4_CV_IN so the next compress4 reads the
		// updated CV. On block 15 this also leaves the four final CVs
		// pre-packed at COMPRESS4_CV_IN ready for deinterleave below.
		memory.copy(COMPRESS4_CV_IN_OFFSET +  0, COMPRESS4_OUT_OFFSET +   0, 32)
		memory.copy(COMPRESS4_CV_IN_OFFSET + 32, COMPRESS4_OUT_OFFSET +  64, 32)
		memory.copy(COMPRESS4_CV_IN_OFFSET + 64, COMPRESS4_OUT_OFFSET + 128, 32)
		memory.copy(COMPRESS4_CV_IN_OFFSET + 96, COMPRESS4_OUT_OFFSET + 192, 32)
	}

	// Deinterleave the four 32-byte chunk CVs into the caller's packed
	// output region. After the block-15 chain-copy above, lane K's
	// final CV sits at COMPRESS4_CV_IN + K*32 already packed, so one
	// 128-byte copy lands all four lanes at outCvOff in lane-0-first
	// order. Lane ordering matters: the four CVs MUST be pushed to the
	// §2.5 tree assembly in ascending chunk-index order so the
	// queue-per-level cascade emits parents in the canonical order.
	memory.copy(outCvOff, COMPRESS4_CV_IN_OFFSET, 128)
}

/**
 * Test-only counter: number of `chunkBatch4` invocations since the last
 * `_resetBatch4CallCount()` call. NOT part of the consumer-facing
 * Blake3Exports interface; wired exclusively for the
 * `blake3-compress4-dispatch` unit test that asserts production
 * `hashCore` actually dispatches to `compress4` for multi-chunk inputs
 * (rather than silently falling through to the single-chunk path).
 *
 * Held in a WebAssembly global so `wipeBuffers()` does not clear it.
 */
export function _getBatch4CallCount(): u32 {
	return batch4CallCount
}

/**
 * Reset the test-only batch counter. Paired with `_getBatch4CallCount`.
 * Tests call this before each assertion to isolate the count from
 * prior dispatch activity on the same module instance.
 */
export function _resetBatch4CallCount(): void {
	batch4CallCount = 0
}
