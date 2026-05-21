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
// src/asm/blake3/chunk.ts
//
// BLAKE3 chunk state machine, BLAKE3 §2.4 (Chunk Chaining Values).
// A chunk processes up to 16 blocks (1024 bytes) into a single chunk
// CV. The chunk counter t (a u64) is the same for every compression
// within the chunk. CHUNK_START is set on the first block; CHUNK_END
// is set on the last; for single-chunk inputs the last compression
// additionally carries ROOT (BLAKE3 §2.4, "If a chunk is the root of
// its tree, the last block of that chunk also sets the ROOT flag.").
//
// The chunk machine keeps a one-block lookahead in CHUNK_PENDING_BLOCK
// so each compress can carry the correct flag without the caller
// having to identify "the last block" in advance. chunkUpdate compresses
// the previously buffered block (non-final), then stashes the new one;
// chunkFinalize compresses the still-buffered block with CHUNK_END (and
// ROOT when isRootSoloChunk is true).

import { compress } from './compress'
import {
	CV_OFFSET,
	COMPRESS_OUT_OFFSET,
	MODE_CV_OFFSET,
	MODE_FLAGS_OFFSET,
	CHUNK_INDEX_OFFSET,
	CHUNK_BLOCKS_OFFSET,
	CHUNK_PENDING_LEN_OFFSET,
	CHUNK_PENDING_BLOCK_OFFSET,
	ROOT_STATE_CV_OFFSET,
	ROOT_STATE_MSG_OFFSET,
	ROOT_STATE_BLEN_OFFSET,
	ROOT_STATE_FLAGS_OFFSET,
} from './buffers'
import { FLAG_CHUNK_START, FLAG_CHUNK_END, FLAG_ROOT } from './flags'

/**
 * Reset chunk state for a new chunk identified by `chunkIndex`.
 *
 * BLAKE3 §2.4: every compression within a chunk shares the same chunk
 * counter t = chunkIndex. The chunk's running CV starts as the mode's
 * key (BLAKE3 IV for hash mode, the keyed-hash key for keyed mode, or
 * the derived context CV for derive_key mode); the caller is expected
 * to have written that 32-byte value to MODE_CV before invoking the
 * hash entry point.
 *
 * Zeroes the pending-block lookahead so that an empty-input chunk
 * (no chunkUpdate calls before chunkFinalize) compresses the canonical
 * 64-zero block with block_len = 0 (BLAKE3 §2.4 single-chunk root case).
 */
export function chunkInit(chunkIndex: u64): void {
	memory.copy(CV_OFFSET, MODE_CV_OFFSET, 32)
	store<u64>(CHUNK_INDEX_OFFSET, chunkIndex)
	store<i32>(CHUNK_BLOCKS_OFFSET, 0)
	store<i32>(CHUNK_PENDING_LEN_OFFSET, 0)
	memory.fill(CHUNK_PENDING_BLOCK_OFFSET, 0, 64)
}

/**
 * Absorb one block (1..64 bytes) into the current chunk.
 *
 * BLAKE3 §2.4 distinguishes "first" / "middle" / "last" blocks of a
 * chunk only by flag set. The chunk machine here can't yet know which
 * is last, so the previously buffered block is compressed as a non-final
 * block (CHUNK_START set only when CHUNK_BLOCKS is still 0) and the new
 * block is stashed in CHUNK_PENDING_BLOCK for the next call or for
 * chunkFinalize to consume.
 *
 * Within a chunk all blocks except the last are full 64 bytes per §2.4,
 * so callers that pass blockLen < 64 are implicitly indicating the last
 * block; that final byte count is preserved in the lookahead and applied
 * when chunkFinalize fires the compress with CHUNK_END.
 */
export function chunkUpdate(blockOff: i32, blockLen: i32): void {
	const pendingLen = load<i32>(CHUNK_PENDING_LEN_OFFSET)
	if (pendingLen > 0) compressPending(false, false)
	memory.copy(CHUNK_PENDING_BLOCK_OFFSET, blockOff, blockLen)
	if (blockLen < 64) memory.fill(CHUNK_PENDING_BLOCK_OFFSET + blockLen, 0, 64 - blockLen)
	store<i32>(CHUNK_PENDING_LEN_OFFSET, blockLen)
}

/**
 * Compress the buffered final block of the chunk and emit its 32-byte CV.
 *
 * BLAKE3 §2.4: the final compress carries CHUNK_END. When the entire
 * input fits in one chunk, the same compress additionally carries
 * ROOT (per BLAKE3 §2.4 "If a chunk is the root of its tree, the last
 * block of that chunk also sets the ROOT flag.") and its 32-byte first
 * half becomes the default-length digest.
 *
 * For chunks whose only block is also the first (single-block chunk or
 * empty input), CHUNK_START is still active on this compress because the
 * pre-compress chunk block counter is 0. Empty input lands here with a
 * zero pending block and block_len = 0, matching the gate KAT.
 */
export function chunkFinalize(outCvOff: i32, isRootSoloChunk: bool): void {
	compressPending(true, isRootSoloChunk)
	memory.copy(outCvOff, COMPRESS_OUT_OFFSET, 32)
}

// Compress the buffered block, advance the chunk CV, and clear pendingLen.
// BLAKE3 §2.4: counter is the chunk index throughout; CHUNK_START is set
// on the first compress only; CHUNK_END / ROOT come from the caller. The
// mode-flag bits captured in MODE_FLAGS are OR'd in unconditionally so
// every compress in keyed_hash / derive_key modes carries its flag
// (BLAKE3 §2.3 Modes); hash mode leaves MODE_FLAGS = 0.
//
// When `isRootSoloChunk` is set, the §2.4 single-chunk root compress is
// about to fire. Snapshot its input (CV / msg / blockLen / flags) into
// ROOT_STATE_* so the §2.6 XOF squeeze path can re-fire the compress
// with an incremented counter to produce additional 64-byte output blocks.
@inline
function compressPending(isLast: bool, isRootSoloChunk: bool): void {
	const blocks     = load<i32>(CHUNK_BLOCKS_OFFSET)
	const pendingLen = load<i32>(CHUNK_PENDING_LEN_OFFSET)

	let flags: u32 = load<u32>(MODE_FLAGS_OFFSET)
	if (blocks == 0)     flags |= FLAG_CHUNK_START
	if (isLast)          flags |= FLAG_CHUNK_END
	if (isRootSoloChunk) flags |= FLAG_ROOT

	const idx: u64       = load<u64>(CHUNK_INDEX_OFFSET)
	const counterLo: u32 = idx as u32
	const counterHi: u32 = (idx >> 32) as u32

	if (isRootSoloChunk) {
		memory.copy(ROOT_STATE_CV_OFFSET,  CV_OFFSET,                  32)
		memory.copy(ROOT_STATE_MSG_OFFSET, CHUNK_PENDING_BLOCK_OFFSET, 64)
		store<u32>(ROOT_STATE_BLEN_OFFSET,  pendingLen as u32)
		store<u32>(ROOT_STATE_FLAGS_OFFSET, flags)
	}

	compress(
		CV_OFFSET,
		CHUNK_PENDING_BLOCK_OFFSET,
		counterLo,
		counterHi,
		pendingLen as u32,
		flags,
		COMPRESS_OUT_OFFSET,
	)

	memory.copy(CV_OFFSET, COMPRESS_OUT_OFFSET, 32)
	store<i32>(CHUNK_BLOCKS_OFFSET, blocks + 1)
	store<i32>(CHUNK_PENDING_LEN_OFFSET, 0)
}
