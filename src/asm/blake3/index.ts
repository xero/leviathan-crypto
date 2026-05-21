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
// src/asm/blake3/index.ts
//
// BLAKE3 WASM module, public exports.
// BLAKE3 specification §2.1-2.6 (tree structure, compression, modes,
// chunk CVs, parent CVs, extendable output).
//
// The module exposes compress + buffers, the §2.4 chunk state machine,
// §2.5 tree assembly, §5.3 lane-parallel compress4, and three top-level
// entry points (hash, hashKeyed, deriveKey). The chunk / tree internals
// consult MODE_FLAGS at every compress site so the hash / keyed_hash /
// derive_key modes (§2.3) all share the same machinery; only the
// starting CV and mode-flag bits differ.
//
// XOF output past the first root compression (BLAKE3 §2.6) is produced
// by re-firing the root compress with an incremented counter. The
// chunk / tree paths snapshot the root-compress input into ROOT_STATE_*
// (see buffers.ts) immediately before the root compress fires; hashCore
// loops to fill arbitrary outLen by squeezing 64-byte blocks at a time,
// and the `squeezeXofBlock` export exposes the same squeeze step to the
// TS OutputReader for incremental reads.

import {
	BUFFER_END, MUTABLE_START,
	MODE_CV_OFFSET, MODE_FLAGS_OFFSET, CONTEXT_CV_OFFSET,
	CHUNK_CV_SCRATCH_OFFSET, ROOT_OUT_SCRATCH_OFFSET,
	COMPRESS_OUT_OFFSET, COMPRESS4_OUT_OFFSET, TREE_PARENT_BLOCK_OFFSET,
	ROOT_STATE_CV_OFFSET, ROOT_STATE_MSG_OFFSET,
	ROOT_STATE_BLEN_OFFSET, ROOT_STATE_FLAGS_OFFSET,
} from './buffers'
import {
	compress,
	BLAKE3_IV0, BLAKE3_IV1, BLAKE3_IV2, BLAKE3_IV3,
	BLAKE3_IV4, BLAKE3_IV5, BLAKE3_IV6, BLAKE3_IV7,
} from './compress'
import {
	FLAG_PARENT, FLAG_ROOT,
	FLAG_KEYED_HASH, FLAG_DERIVE_KEY_CONTEXT, FLAG_DERIVE_KEY_MATERIAL,
} from './flags'
import { chunkInit, chunkUpdate, chunkFinalize } from './chunk'
import { chunkBatch4 } from './chunk_simd'
import { treeInit, treePushChunk, treeFinalizeRoot } from './tree'

// ── Buffer layout + module identity ─────────────────────────────────────────

export {
	getModuleId, getMemoryPages,
	getInputStagingOffset, getOutputStagingOffset,
	getCvOffset, getMsgOffset, getCounterOffset, getBlockLenOffset,
	getFlagsOffset, getCompressOutOffset,
	getKeyedKeyOffset, getDeriveCvOffset,
	getCompress4CvInOffset, getCompress4MsgInOffset,
	getCompress4CtrInOffset, getCompress4OutOffset,
	getCompress4BlenInOffset, getCompress4FlagsInOffset,
	getModeCvOffset,
} from './buffers'

// ── Compression primitives (§2.2 internal-SIMD, §5.3 lane-parallel) ─────────

export { compress } from './compress'
export { compress4 } from './compress_simd'

// ── Chunk + tree surfaces (§2.4 chunk CVs, §2.5 parent CVs) ─────────────────

export { chunkInit, chunkUpdate, chunkFinalize } from './chunk'
export { treeInit, treePushChunk, treeFinalizeRoot } from './tree'

// Test-only batch counter for the compress4-dispatch unit test. NOT
// part of the consumer-facing Blake3Exports interface; see types.ts
// (Blake3TestExports) and helpers.ts.
export { _getBatch4CallCount, _resetBatch4CallCount } from './chunk_simd'

// Test-only parent-batch counter for the parent-level compress4
// dispatch unit test. Same not-consumer-facing posture as the chunk
// counter above.
export { _getParentBatch4CallCount, _resetParentBatch4CallCount } from './tree_simd'

// ── Domain-separation flags, BLAKE3 §2.2 Table 3 ────────────────────────────

export {
	FLAG_CHUNK_START, FLAG_CHUNK_END, FLAG_PARENT, FLAG_ROOT,
	FLAG_KEYED_HASH, FLAG_DERIVE_KEY_CONTEXT, FLAG_DERIVE_KEY_MATERIAL,
} from './flags'

// ── BLAKE3 IV exports, §2.2 Table 1 ─────────────────────────────────────────

export {
	BLAKE3_IV0, BLAKE3_IV1, BLAKE3_IV2, BLAKE3_IV3,
	BLAKE3_IV4, BLAKE3_IV5, BLAKE3_IV6, BLAKE3_IV7,
} from './compress'

// ── Top-level hash entry points ─────────────────────────────────────────────

// Seed MODE_CV with the BLAKE3 IV, §2.2 Table 1.
@inline
function loadIvIntoModeCv(): void {
	store<u32>(MODE_CV_OFFSET +  0, BLAKE3_IV0)
	store<u32>(MODE_CV_OFFSET +  4, BLAKE3_IV1)
	store<u32>(MODE_CV_OFFSET +  8, BLAKE3_IV2)
	store<u32>(MODE_CV_OFFSET + 12, BLAKE3_IV3)
	store<u32>(MODE_CV_OFFSET + 16, BLAKE3_IV4)
	store<u32>(MODE_CV_OFFSET + 20, BLAKE3_IV5)
	store<u32>(MODE_CV_OFFSET + 24, BLAKE3_IV6)
	store<u32>(MODE_CV_OFFSET + 28, BLAKE3_IV7)
}

// Re-fire the root compress from ROOT_STATE_* with the supplied counter
// (BLAKE3 §2.6 XOF squeeze). Writes 64 bytes to `outOff`. Used internally
// by hashCore to fill `writeLen > 64` requests and exposed as the
// `squeezeXofBlock` WASM export for the TS OutputReader.
@inline
function squeezeRootBlock(counterLo: u32, counterHi: u32, outOff: i32): void {
	compress(
		ROOT_STATE_CV_OFFSET,
		ROOT_STATE_MSG_OFFSET,
		counterLo,
		counterHi,
		load<u32>(ROOT_STATE_BLEN_OFFSET),
		load<u32>(ROOT_STATE_FLAGS_OFFSET),
		outOff,
	)
}

// Run a full BLAKE3 hashing pass over the input. Assumes the caller has
// pre-populated MODE_CV (starting CV) and MODE_FLAGS (the per-mode flag
// bit OR'd onto every compress). For inputLen ≤ 1024 a single chunk
// applies ROOT on its final compress (§2.4 single-chunk root case);
// larger inputs walk the §2.4 chunk machine into the §2.5 tree assembly
// and finalize via treeFinalizeRoot which marks the topmost parent ROOT.
//
// The root compress writes its full 64-byte output to ROOT_OUT_SCRATCH
// (single-chunk path lands in COMPRESS_OUT and is copied here, multi-
// chunk path writes there directly). For `writeLen > 64` the loop
// squeezes additional 64-byte blocks via `squeezeRootBlock`, with a
// TS-style counter starting at 1 (counter 0 is the implicit first
// compress); BLAKE3 §2.6 specifies the counter is incremented for each
// additional output block.
function hashCore(inputOff: i32, inputLen: i32, outOff: i32, writeLen: i32): void {
	// Single-chunk path, §2.4 single-chunk root: ROOT lives on the
	// chunk's final compress.
	if (inputLen <= 1024) {
		chunkInit(0)
		let off: i32 = 0
		while (off < inputLen) {
			const remain   = inputLen - off
			const blockLen = remain < 64 ? remain : 64
			chunkUpdate(inputOff + off, blockLen)
			off += blockLen
		}
		chunkFinalize(CHUNK_CV_SCRATCH_OFFSET, true)
		// chunkFinalize copies the first 32 bytes of COMPRESS_OUT into
		// CHUNK_CV_SCRATCH but leaves the full 64-byte root compress
		// output at COMPRESS_OUT. Mirror it into ROOT_OUT_SCRATCH so the
		// first-block emit below is the same regardless of which path
		// landed us here.
		memory.copy(ROOT_OUT_SCRATCH_OFFSET, COMPRESS_OUT_OFFSET, 64)
	} else {
		// Multi-chunk path, §2.4 chunks + §2.5 parents.
		//
		// Dispatch shape: 4-chunk batches via compress4 (BLAKE3 §5.3
		// SIMD is the canonical 128-bit SIMD parallelism level for
		// BLAKE3 tree mode) drain the largest multiple of 4 full
		// chunks first; the trailing 0-3 full chunks and the partial
		// last chunk fall back to the single-chunk chunkInit /
		// chunkUpdate / chunkFinalize path in chunk.ts. Both paths feed
		// chunk CVs to the §2.5 tree assembly in ascending chunk-index
		// order so the queue-per-level cascade emits parents in the
		// canonical order.
		treeInit()
		let chunkIdx: u64 = 0
		let off:      i32 = 0

		// A chunk is "full" (and therefore batchable) iff its 1024 bytes
		// fit entirely within inputLen. The partial last chunk always
		// falls through to chunk.ts; chunkBatch4 assumes every lane has
		// 16 full blocks and batching a short last block would corrupt
		// the output.
		const fullChunkBytes: i32 = (inputLen / 1024) * 1024
		// Largest multiple of 4 KiB ≤ fullChunkBytes. chunkBatch4 handles
		// 4 chunks at a time, so anything past this multiple drops to
		// the trailing single-chunk loop below.
		const batchableBytes: i32 = (fullChunkBytes / 4096) * 4096

		// 4-chunk batches via compress4. Lane K's chunk CV lands at the
		// first 32 bytes of its 64-byte slot in COMPRESS4_OUT; using
		// that slot directly as the deinterleaved scratch keeps the
		// dispatch lean, no separate scratch region needed in
		// buffers.ts. The four CVs sit packed at lane offsets 0, 32,
		// 64, 96 within COMPRESS4_OUT after chunkBatch4 returns.
		while (off < batchableBytes) {
			chunkBatch4(inputOff + off, chunkIdx, COMPRESS4_OUT_OFFSET)
			for (let k: i32 = 0; k < 4; k++) {
				chunkIdx += 1
				treePushChunk(COMPRESS4_OUT_OFFSET + (k << 5))
			}
			off += 4096
		}

		// Trailing 0-3 full chunks, single-chunk path.
		while (off + 1024 <= inputLen) {
			chunkInit(chunkIdx)
			let bOff: i32 = 0
			while (bOff < 1024) {
				chunkUpdate(inputOff + off + bOff, 64)
				bOff += 64
			}
			chunkFinalize(CHUNK_CV_SCRATCH_OFFSET, false)
			chunkIdx += 1
			treePushChunk(CHUNK_CV_SCRATCH_OFFSET)
			off += 1024
		}

		// Partial last chunk, if any (1..1023 trailing bytes).
		if (off < inputLen) {
			const chunkLen: i32 = inputLen - off
			chunkInit(chunkIdx)
			let bOff: i32 = 0
			while (bOff < chunkLen) {
				const remain   = chunkLen - bOff
				const blockLen = remain < 64 ? remain : 64
				chunkUpdate(inputOff + off + bOff, blockLen)
				bOff += blockLen
			}
			chunkFinalize(CHUNK_CV_SCRATCH_OFFSET, false)
			chunkIdx += 1
			treePushChunk(CHUNK_CV_SCRATCH_OFFSET)
		}

		treeFinalizeRoot(ROOT_OUT_SCRATCH_OFFSET)
	}

	// First 64-byte XOF block (counter = 0) lives at ROOT_OUT_SCRATCH;
	// emit up to writeLen bytes from it. Squeeze additional blocks from
	// ROOT_STATE_* for any remaining bytes (§2.6).
	const firstLen: i32 = writeLen < 64 ? writeLen : 64
	memory.copy(outOff, ROOT_OUT_SCRATCH_OFFSET, firstLen)

	let copied: i32 = firstLen
	let counter: u64 = 1
	while (copied < writeLen) {
		const ctrLo: u32 = counter as u32
		const ctrHi: u32 = (counter >> 32) as u32
		squeezeRootBlock(ctrLo, ctrHi, ROOT_OUT_SCRATCH_OFFSET)
		const remain: i32 = writeLen - copied
		const blkLen: i32 = remain < 64 ? remain : 64
		memory.copy(outOff + copied, ROOT_OUT_SCRATCH_OFFSET, blkLen)
		copied  += blkLen
		counter += 1
	}
}

/**
 * BLAKE3 hash, default mode (BLAKE3 §2.1 tree, §2.3 modes, §2.4 chunks,
 * §2.5 parents, §2.6 XOF).
 *
 * Reads `inputLen` bytes from `inputOff` and writes `outLen` bytes of
 * BLAKE3 XOF output to `outOff`. The root compress is fired once; for
 * `outLen > 64` hashCore squeezes additional 64-byte blocks from the
 * snapshotted root state (§2.6).
 *
 * Starting CV: BLAKE3 IV (§2.2 Table 1). Mode flag: none.
 */
export function hash(inputOff: i32, inputLen: i32, outOff: i32, outLen: i32): void {
	loadIvIntoModeCv()
	store<u32>(MODE_FLAGS_OFFSET, 0)
	hashCore(inputOff, inputLen, outOff, outLen)
}

/**
 * BLAKE3 keyed_hash, BLAKE3 §2.3 Modes.
 *
 * The starting CV is the 32-byte caller-supplied key loaded as 8 u32
 * little-endian words. Every compress in the operation (chunk + parent
 * + root) carries the KEYED_HASH flag. The chunk / tree machinery is
 * identical to the hash mode; only the starting CV and the mode-flag
 * bit differ.
 *
 * `keyOff` must point at 32 bytes. WASM trusts its caller for buffer
 * sizes per the existing slhdsa / mldsa pattern; the TS layer validates
 * key length.
 */
export function hashKeyed(
	keyOff:    i32,
	inputOff:  i32,
	inputLen:  i32,
	outOff:    i32,
	outLen:    i32,
): void {
	// §2.3: starting CV = the 32 key bytes, read as 8 u32 LE words. WASM
	// is little-endian, so the byte-for-byte copy from keyOff to MODE_CV
	// produces the same in-memory layout that a u32 LE load would build.
	memory.copy(MODE_CV_OFFSET, keyOff, 32)
	store<u32>(MODE_FLAGS_OFFSET, FLAG_KEYED_HASH)
	hashCore(inputOff, inputLen, outOff, outLen)
}

/**
 * BLAKE3 derive_key, BLAKE3 §2.3 Modes.
 *
 * Two-pass construction:
 *   Pass 1: hash `context` with starting CV = IV and mode flag =
 *     DERIVE_KEY_CONTEXT, writing 32 bytes to CONTEXT_CV.
 *   Pass 2: hash `material` with starting CV = CONTEXT_CV and mode flag
 *     = DERIVE_KEY_MATERIAL, writing the requested prefix to outOff.
 *
 * Per §2.3 the context string is conventionally a UTF-8 hardcoded
 * compile-time constant per application, not a runtime value; the
 * TS-layer surface and the audit doc document this nuance.
 *
 * CONTEXT_CV is wiped after pass 2 in addition to the dispose-time
 * wipeBuffers() sweep: it is a derived intermediate, treated as
 * sensitive even though §2.3 does not strictly classify it as key
 * material.
 */
export function deriveKey(
	contextOff:  i32,
	contextLen:  i32,
	materialOff: i32,
	materialLen: i32,
	outOff:      i32,
	outLen:      i32,
): void {
	// Pass 1: hash(context) with IV and DERIVE_KEY_CONTEXT, 32 bytes out.
	loadIvIntoModeCv()
	store<u32>(MODE_FLAGS_OFFSET, FLAG_DERIVE_KEY_CONTEXT)
	hashCore(contextOff, contextLen, CONTEXT_CV_OFFSET, 32)

	// Pass 2: hash(material) starting from the context_chain_value with
	// DERIVE_KEY_MATERIAL, writing the requested prefix to outOff.
	memory.copy(MODE_CV_OFFSET, CONTEXT_CV_OFFSET, 32)
	store<u32>(MODE_FLAGS_OFFSET, FLAG_DERIVE_KEY_MATERIAL)
	hashCore(materialOff, materialLen, outOff, outLen)

	// Pass-2 done: scrub the derived intermediate. dispose-time
	// wipeBuffers() also covers this slot; the explicit wipe here means
	// the intermediate does not linger between successive deriveKey
	// invocations on the same module instance.
	memory.fill(CONTEXT_CV_OFFSET, 0, 32)
}

// ── Test-only WASM exports ──────────────────────────────────────────────────
//
// Substrate hooks for the tree-internals unit suite and the
// `src/ts/merkle/blake3-tree.ts` Merkle-tree module. NOT part of the
// consumer-facing Blake3Exports interface; consumers compute chunk /
// parent CVs only via hash / hashKeyed / deriveKey. Underscore prefix
// follows the codebase convention for module-internal exports
// (e.g. `_acquireModule` on the TS side, `_test*` on the slhdsa WASM).
//
// `src/ts/merkle/blake3-tree.ts` casts
// `Blake3Exports & Blake3TestExports` inside the merkle module the same
// way slhdsa unit tests cast for `_test*` access today.

/**
 * Compute the chunk CV for the chunk at `chunkIndex` containing `inputLen`
 * bytes at `inputOff`, using `startCvOff` as the chunk's starting CV and
 * `modeFlags` as the mode-flag bits OR'd onto every compress in the
 * chunk pipeline. BLAKE3 §2.4.
 *
 * Output: 32 bytes at `outCvOff`. Does NOT run ROOT, the chunk CV here
 * is the value that would be pushed to the §2.5 tree assembly for a
 * multi-chunk input. The §2.4 single-chunk shortcut (ROOT on the last
 * compress) is NOT applied; callers that need the single-chunk root
 * use BLAKE3.hash directly or recompute via the exported `compress`
 * with ROOT set explicitly.
 */
export function _testChunkCV(
	inputOff:   i32,
	inputLen:   i32,
	chunkIndex: u64,
	startCvOff: i32,
	modeFlags:  u32,
	outCvOff:   i32,
): void {
	memory.copy(MODE_CV_OFFSET, startCvOff, 32)
	store<u32>(MODE_FLAGS_OFFSET, modeFlags)
	chunkInit(chunkIndex)
	let off: i32 = 0
	while (off < inputLen) {
		const remain   = inputLen - off
		const blockLen = remain < 64 ? remain : 64
		chunkUpdate(inputOff + off, blockLen)
		off += blockLen
	}
	chunkFinalize(outCvOff, false)
}

/**
 * Compute the parent CV from two 32-byte child CVs (left || right).
 * BLAKE3 §2.5 (parent node chaining values; the topmost parent of a
 * multi-chunk tree also carries ROOT).
 *
 * `startCvOff` is the mode CV (IV for hash, key for keyed_hash,
 * context_chain_value for derive_key pass 2); `modeFlags` carries
 * KEYED_HASH / DERIVE_KEY_* bits as required. When `isRoot` is true the
 * compress carries PARENT|ROOT, the root snapshot (ROOT_STATE_*) is
 * populated so `squeezeXofBlock` works for the test caller, and the
 * first 32 bytes of the §2.5 root output are written to `outCvOff`.
 * When `isRoot` is false a plain PARENT compress emits the 32-byte
 * parent CV.
 */
export function _testParentCV(
	leftCvOff:  i32,
	rightCvOff: i32,
	startCvOff: i32,
	modeFlags:  u32,
	isRoot:     bool,
	outCvOff:   i32,
): void {
	memory.copy(MODE_CV_OFFSET, startCvOff, 32)
	store<u32>(MODE_FLAGS_OFFSET, modeFlags)
	memory.copy(TREE_PARENT_BLOCK_OFFSET +  0, leftCvOff,  32)
	memory.copy(TREE_PARENT_BLOCK_OFFSET + 32, rightCvOff, 32)
	const rootBit: u32 = isRoot ? FLAG_ROOT : 0
	const flags:   u32 = FLAG_PARENT | rootBit | modeFlags

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
		COMPRESS_OUT_OFFSET,
	)
	memory.copy(outCvOff, COMPRESS_OUT_OFFSET, 32)
}

/**
 * Run BLAKE3 derive_key pass 1 in isolation (BLAKE3 §2.3 Modes).
 * Hashes `contextOff[..contextLen]` with starting CV = BLAKE3 IV and
 * DERIVE_KEY_CONTEXT flag on every compress, writing the 32-byte
 * context_chain_value (CCV) to `outCcvOff`.
 *
 * Test-only: exposes the substrate the §2.3 two-pass derive_key would
 * normally consume internally so the tree-internals tests can drive
 * pass 2 (chunk / parent over material) with the correct starting CV
 * for the derive mode.
 */
export function _testDeriveContextCV(
	contextOff:  i32,
	contextLen:  i32,
	outCcvOff:   i32,
): void {
	loadIvIntoModeCv()
	store<u32>(MODE_FLAGS_OFFSET, FLAG_DERIVE_KEY_CONTEXT)
	hashCore(contextOff, contextLen, outCcvOff, 32)
}

// ── XOF squeeze entry (BLAKE3 §2.6) ─────────────────────────────────────────

/**
 * Re-fire the root compress with the supplied counter and write the
 * full 64-byte output to `outOff`. BLAKE3 §2.6 specifies the root
 * counter increments for each additional output block; counter 0 was
 * consumed by the initial root compress fired inside hash / hashKeyed /
 * deriveKey, so the first squeeze call should pass counter = 1.
 *
 * The caller must have completed a hash / hashKeyed / deriveKey on the
 * current module instance (which populates ROOT_STATE_* in the chunk /
 * tree paths). Calling without a prior hash, or after wipeBuffers(),
 * yields meaningless bytes; the TS OutputReader enforces the contract
 * by running the hash itself in its constructor and squeezing
 * incrementally from this entry.
 */
export function squeezeXofBlock(counterLo: u32, counterHi: u32, outOff: i32): void {
	squeezeRootBlock(counterLo, counterHi, outOff)
}

// ── Buffer wipe ─────────────────────────────────────────────────────────────

/**
 * Zero the BLAKE3 module's mutable buffer region.
 * Skips the data segment at offsets 0..MUTABLE_START-1 so that the SIGMA
 * permutation table stays intact across dispose / re-use cycles.
 * Must be called by the TypeScript wrapper's dispose() so key material,
 * intermediate CVs, message blocks, chunk state, subtree stack entries,
 * and compress4 staging buffers do not persist in WASM memory.
 */
export function wipeBuffers(): void {
	memory.fill(MUTABLE_START, 0, BUFFER_END - MUTABLE_START)
}
