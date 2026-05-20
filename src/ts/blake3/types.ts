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
// src/ts/blake3/types.ts
//
// BLAKE3 WASM exports interface. Mirrors the AssemblyScript surface in
// `src/asm/blake3/index.ts`. The consumer-facing TS surface (BLAKE3,
// BLAKE3Stream and the keyed_hash / derive_key variants) calls the
// top-level `hash` / `hashKeyed` / `deriveKey` entry points. Lower-level
// primitives (`compress`, flag constants, buffer accessors) are typed
// here for completeness and so test code can drive each layer in
// isolation if needed.

/** BLAKE3 WASM exports. */
export interface Blake3Exports {
	memory: WebAssembly.Memory

	// Buffer layout + module identity (src/asm/blake3/buffers.ts)
	getModuleId:                () => number
	getMemoryPages:             () => number
	getInputStagingOffset:      () => number
	getOutputStagingOffset:     () => number
	getCvOffset:                () => number
	getMsgOffset:               () => number
	getCounterOffset:           () => number
	getBlockLenOffset:          () => number
	getFlagsOffset:             () => number
	getCompressOutOffset:       () => number
	getKeyedKeyOffset:          () => number
	getDeriveCvOffset:          () => number
	getCompress4CvInOffset:     () => number
	getCompress4MsgInOffset:    () => number
	getCompress4CtrInOffset:    () => number
	getCompress4OutOffset:      () => number
	getCompress4BlenInOffset:   () => number
	getCompress4FlagsInOffset:  () => number
	getModeCvOffset:            () => number

	// Domain-separation flag constants, BLAKE3 §2.2 Table 3.
	FLAG_CHUNK_START:           { value: number }
	FLAG_CHUNK_END:             { value: number }
	FLAG_PARENT:                { value: number }
	FLAG_ROOT:                  { value: number }
	FLAG_KEYED_HASH:            { value: number }
	FLAG_DERIVE_KEY_CONTEXT:    { value: number }
	FLAG_DERIVE_KEY_MATERIAL:   { value: number }

	// BLAKE3 IV constants (§2.2 Table 1, identical to FIPS 180-4 SHA-256 IV).
	BLAKE3_IV0:                 { value: number }
	BLAKE3_IV1:                 { value: number }
	BLAKE3_IV2:                 { value: number }
	BLAKE3_IV3:                 { value: number }
	BLAKE3_IV4:                 { value: number }
	BLAKE3_IV5:                 { value: number }
	BLAKE3_IV6:                 { value: number }
	BLAKE3_IV7:                 { value: number }

	// Compression primitives (BLAKE3 §2.2 single block, §5.3 lane-parallel).
	compress: (
		cvOff: number, blockOff: number,
		counterLo: number, counterHi: number,
		blockLen: number, flags: number,
		outOff: number,
	) => void
	// compress4 is zero-arg: callers stage 4 lanes' inputs at the
	// COMPRESS4_* offsets (see src/asm/blake3/buffers.ts) and read the
	// 4 × 64-byte outputs back from COMPRESS4_OUT after the call.
	compress4: () => void

	// Chunk + tree primitives (BLAKE3 §2.4 / §2.5). The chunk index
	// counter is u64 in the AS source; AssemblyScript exports u64 as
	// JS BigInt at the WASM boundary.
	chunkInit:        (chunkIndex: bigint) => void
	chunkUpdate:      (blockOff: number, blockLen: number) => void
	chunkFinalize:    (outCvOff: number, isRootSoloChunk: number) => void
	treeInit:         () => void
	treePushChunk:    (chunkCvOff: number) => void
	treeFinalizeRoot: (outOff: number) => void

	// Top-level hash entry points (§2.3 Modes + §2.6 XOF). outLen is written
	// in full: the §2.6 root squeeze fires inside hashCore for outLen > 64.
	hash:      (inputOff: number, inputLen: number, outOff: number, outLen: number) => void
	hashKeyed: (
		keyOff:   number,
		inputOff: number, inputLen: number,
		outOff:   number, outLen: number,
	) => void
	deriveKey: (
		contextOff:  number, contextLen:  number,
		materialOff: number, materialLen: number,
		outOff:      number, outLen:      number,
	) => void

	// XOF squeeze entry (§2.6). Re-fires the root compress from the
	// snapshot captured during the most recent hash / hashKeyed / deriveKey
	// on this module instance, writing 64 bytes to `outOff`. Counter 0 is
	// the initial root compress (already emitted by the hash entry); the
	// OutputReader passes counter = 1, 2, ... for subsequent blocks.
	squeezeXofBlock: (counterLo: number, counterHi: number, outOff: number) => void

	// Buffer hygiene
	wipeBuffers:                () => void
}

/**
 * BLAKE3 WASM internal test exports. NOT part of the consumer surface,
 * NOT re-exported from `src/ts/blake3/index.ts`. Wired exclusively for
 * the tree-internals test suite (`test/unit/blake3/blake3-tree-internals
 * .test.ts`) and the Merkle-tree substrate
 * (`src/ts/merkle/blake3-tree.ts`) which casts
 * `Blake3Exports & Blake3TestExports` inside the merkle module.
 *
 * Tests obtain these via `test/unit/blake3/helpers.ts`, which casts the
 * public `Blake3Exports` to `Blake3Exports & Blake3TestExports`. Consumer
 * code never sees the `_test*` surface.
 */
export interface Blake3TestExports {
	// Chunk CV (BLAKE3 §2.4). Drives the chunk pipeline for the chunk at
	// `chunkIndex` using `startCvOff` (32 bytes) as the starting CV and
	// `modeFlags` as the mode-flag bits OR'd onto every compress; writes
	// 32 bytes to `outCvOff`. Does NOT apply ROOT — the chunk CV here is
	// what the §2.5 tree assembly would absorb for a multi-chunk input.
	_testChunkCV: (
		inputOff:   number,
		inputLen:   number,
		chunkIndex: bigint,
		startCvOff: number,
		modeFlags:  number,
		outCvOff:   number,
	) => void

	// Parent CV (BLAKE3 §2.5). Composes a parent compress over the
	// left || right 32-byte child CVs with `startCvOff` as the mode CV
	// and `modeFlags` for KEYED_HASH / DERIVE_KEY_* bits. When `isRoot`
	// is true the compress carries PARENT|ROOT and ROOT_STATE_* is
	// populated for follow-up `squeezeXofBlock` calls. Writes the first
	// 32 bytes of the §2.5 output to `outCvOff`.
	_testParentCV: (
		leftCvOff:  number,
		rightCvOff: number,
		startCvOff: number,
		modeFlags:  number,
		isRoot:     number,
		outCvOff:   number,
	) => void

	// BLAKE3 §2.3 derive_key pass 1, isolated. Hashes the context bytes
	// with starting CV = IV and DERIVE_KEY_CONTEXT flag, writes the
	// 32-byte context_chain_value to `outCcvOff`. Used by tree-internals
	// tests to obtain the pass-2 starting CV for the derive_key mode.
	_testDeriveContextCV: (
		contextOff: number,
		contextLen: number,
		outCcvOff:  number,
	) => void

	_getBatch4CallCount:         () => number
	_resetBatch4CallCount:       () => void
	_getParentBatch4CallCount:   () => number
	_resetParentBatch4CallCount: () => void
}
