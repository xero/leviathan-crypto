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
// src/asm/blake3/tree.ts
//
// BLAKE3 tree mode, queue-per-level discipline. BLAKE3 §2.5 (parent
// node chaining values; the topmost parent carries ROOT).
//
// Each of the BLAKE3 §5.1.2 54 tree levels maintains a small queue of
// pending CVs in LEVEL_QUEUES. When a level's queue reaches exactly 8
// pending entries during push, the queue's contents are batched
// through `parentBatch4` (4 parent merges in parallel via the v128-
// external `compress4` kernel from `tree_simd.ts`), and the 4
// resulting parent CVs propagate to the next level's queue. The only
// increments to a level's count are +1 at level 0 from `treePushChunk`
// and +4 at L ≥ 1 from `parentBatch4`, so the count steps 0..7 → 8 and
// never overshoots; the cascade continues as long as upper levels also
// hit 8 pending. `treeFinalizeRoot` then walks the queues bottom-up,
// pair-compressing residuals via single-pair `compress`, and marks the
// FINAL merge `PARENT | ROOT` per §2.5.
//
// Per BLAKE3 §2.5 each parent compress is independent of the others at
// the same level, so 4 same-level merges are batchable through
// `compress4` with bit-identical output to 4 sequential `compress`
// calls. The queue-per-level discipline reorganizes when merges happen
// (defer + batch in 4s) without changing what they compute.
//
// The §2.5 ROOT compress always lives on a single-pair `compress` call
// in finalize. ROOT-flag bookkeeping is simplest with single-pair
// semantics, and ROOT is exclusive: exactly one compress per `hash()`
// call carries the bit. Snapshotting the root-compress input into
// ROOT_STATE_* (consumed by `squeezeXofBlock` for §2.6 XOF squeezes)
// happens immediately before that single ROOT compress fires.

import { compress } from './compress'
import { parentBatch4 } from './tree_simd'
import {
	MODE_CV_OFFSET,
	MODE_FLAGS_OFFSET,
	TREE_PARENT_BLOCK_OFFSET,
	ROOT_STATE_CV_OFFSET,
	ROOT_STATE_MSG_OFFSET,
	ROOT_STATE_BLEN_OFFSET,
	ROOT_STATE_FLAGS_OFFSET,
	LEVEL_QUEUES_OFFSET,
	LEVEL_QUEUE_STRIDE,
	LEVEL_COUNTS_OFFSET,
	MAX_LEVEL,
} from './buffers'
import { FLAG_PARENT, FLAG_ROOT } from './flags'

@inline
function queueOff(level: i32): i32 {
	return LEVEL_QUEUES_OFFSET + level * LEVEL_QUEUE_STRIDE
}

@inline
function countOff(level: i32): i32 {
	return LEVEL_COUNTS_OFFSET + (level << 2)
}

/**
 * Reset all level queue counts for a new hashing operation.
 *
 * Queue contents themselves do not need zeroing here; unread slots
 * beyond a level's count are never consumed, and `wipeBuffers()`
 * covers the whole region on dispose.
 */
export function treeInit(): void {
	memory.fill(LEVEL_COUNTS_OFFSET, 0, MAX_LEVEL << 2)
}

/**
 * Push a chunk CV to the tree's level-0 queue and cascade batches
 * upward via `parentBatch4` (4 parent merges in parallel through
 * compress4) at every level that reaches 8 pending entries.
 *
 * Cascading is governed by per-level counts; no global chunk index is
 * needed at this layer (the chunk counter is consumed inside chunk.ts
 * for the §2.4 `t` field on each compress).
 */
export function treePushChunk(chunkCvOff: i32): void {
	// Append the new chunk CV to level-0's queue tail.
	let count0: i32 = load<i32>(countOff(0))
	memory.copy(queueOff(0) + (count0 << 5), chunkCvOff, 32)
	count0 += 1
	store<i32>(countOff(0), count0)

	// Cascade: while the current level reaches 8, batch via parentBatch4
	// (BLAKE3 §2.5 parent compression in 4-lane parallel) and propagate
	// the 4 outputs to the next level's tail. Cap at MAX_LEVEL-1 so the
	// destination level stays in bounds. With valid (≤ 2^64-byte) input
	// the cascade naturally terminates well before the cap: count[L]
	// can only reach 8 for finite chunks, see file header.
	let L: i32 = 0
	while (L < MAX_LEVEL - 1) {
		const cL: i32 = load<i32>(countOff(L))
		if (cL < 8) break

		const cLp1: i32 = load<i32>(countOff(L + 1))
		// Pass `queue[L+1] + cLp1 * 32` directly as parentBatch4's
		// outCvOff so the 4 outputs land in the destination queue
		// without an intermediate scratch + copy.
		parentBatch4(queueOff(L), queueOff(L + 1) + (cLp1 << 5))

		// queue[L] held exactly 8 entries when we entered the loop
		// (push-time batches always fire at exactly 8, never higher),
		// so a count reset suffices: unread tail slots are not consumed.
		store<i32>(countOff(L), 0)
		store<i32>(countOff(L + 1), cLp1 + 4)
		L += 1
	}
}

/**
 * Drain the level queues and produce the BLAKE3 §2.5 root compression
 * output.
 *
 * Walks levels bottom-up, pair-compressing pending CVs via the single-
 * pair `compress` (BLAKE3 §2.2). Each pair emit lands in the next
 * level's queue tail; a level's odd residual carries up unchanged to
 * the next level (no merge consumed). Bookkeeping tracks how many
 * merges remain; the FINAL merge (when `remainingMerges` drops to 1)
 * carries the §2.5 ROOT flag and writes its full 64-byte output to
 * `outOff` rather than back to a queue. The ROOT compress's input is
 * snapshotted into ROOT_STATE_* so the §2.6 XOF squeeze path
 * (`squeezeXofBlock` in index.ts) can re-fire with an incremented
 * counter.
 *
 * Precondition: at least two chunks pushed (the single-chunk path
 * applies ROOT in `chunkFinalize` per BLAKE3 §2.4 "last block of root
 * chunk sets ROOT", never reaching this function).
 */
export function treeFinalizeRoot(outOff: i32): void {
	// Total CVs across all levels at the start of finalize. Each merge
	// consumes 2 CVs and emits 1, so the total number of merges to
	// reach a single root CV is totalCvs - 1.
	let totalCvs: i32 = 0
	for (let L: i32 = 0; L < MAX_LEVEL; L++) {
		totalCvs += load<i32>(countOff(L))
	}

	let remainingMerges: i32 = totalCvs - 1
	const modeFlags: u32 = load<u32>(MODE_FLAGS_OFFSET)

	for (let L: i32 = 0; L < MAX_LEVEL - 1; L++) {
		let cL: i32 = load<i32>(countOff(L))

		while (cL >= 2) {
			const isRoot: bool = remainingMerges == 1
			const rootBit: u32 = isRoot ? FLAG_ROOT : 0
			const flags:   u32 = FLAG_PARENT | rootBit | modeFlags

			const qL: i32 = queueOff(L)
			memory.copy(TREE_PARENT_BLOCK_OFFSET +  0, qL +  0, 32)
			memory.copy(TREE_PARENT_BLOCK_OFFSET + 32, qL + 32, 32)

			let cLp1: i32 = 0
			let dst:  i32 = outOff
			if (!isRoot) {
				cLp1 = load<i32>(countOff(L + 1))
				dst  = queueOff(L + 1) + (cLp1 << 5)
			}

			// Snapshot the root-compress input (CV / msg / blockLen /
			// flags) into ROOT_STATE_* (BLAKE3 §2.6 XOF) so subsequent
			// `squeezeXofBlock` calls can re-fire the compress with an
			// incremented counter. Fires only for the final merge.
			if (isRoot) {
				memory.copy(ROOT_STATE_CV_OFFSET,  MODE_CV_OFFSET,           32)
				memory.copy(ROOT_STATE_MSG_OFFSET, TREE_PARENT_BLOCK_OFFSET, 64)
				store<u32>(ROOT_STATE_BLEN_OFFSET,  64)
				store<u32>(ROOT_STATE_FLAGS_OFFSET, flags)
			}

			compress(
				MODE_CV_OFFSET,
				TREE_PARENT_BLOCK_OFFSET,
				0, 0,
				64,
				flags,
				dst,
			)

			if (!isRoot) store<i32>(countOff(L + 1), cLp1 + 1)

			cL -= 2
			// Shift remaining entries in queue[L] left by 2 (16 lo-CV
			// halves shift back into the first 8 slots).
			if (cL > 0) memory.copy(qL, qL + 64, cL << 5)

			remainingMerges -= 1
			if (remainingMerges == 0) {
				// Root compressed; outOff now holds 64 bytes of §2.5 output.
				// Reset every level count so a follow-up hash on the same
				// module instance starts clean (the dispose-time
				// wipeBuffers() is the broader sweep).
				memory.fill(LEVEL_COUNTS_OFFSET, 0, MAX_LEVEL << 2)
				return
			}
		}

		// Single residual carries up unchanged (no merge consumed).
		if (cL == 1) {
			const cLp1: i32 = load<i32>(countOff(L + 1))
			memory.copy(queueOff(L + 1) + (cLp1 << 5), queueOff(L), 32)
			store<i32>(countOff(L + 1), cLp1 + 1)
			cL = 0
		}
		store<i32>(countOff(L), cL)
	}

	// Unreachable on valid inputs: every multi-chunk hash terminates
	// inside the loop above at the final merge (when remainingMerges
	// drops to 0). Reaching here means remainingMerges did not
	// decrement to 0, which indicates a queue-bookkeeping bug. Trap
	// rather than fall through silently, otherwise the caller would
	// emit pre-existing ROOT_OUT_SCRATCH contents (in production: a
	// prior hash output for the same module instance) as the "result".
	unreachable()
}
