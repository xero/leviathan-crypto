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
// test/unit/blake3/helpers.ts
//
// Shared test harness for the BLAKE3 tree-internals suite. Loads the
// blake3 WASM module via the public init() pathway and exposes
// `Blake3TestExports` so tests can drive `_testChunkCV` /
// `_testParentCV` / `_testDeriveContextCV` in isolation.
//
// The `Blake3TestExports` cast is contained inside this helper file.
// The public consumer surface (`src/ts/blake3/index.ts`) does not
// surface the `_test*` names; consumer code is shielded from the test
// fixtures.

import { blake3Init } from '../../../src/ts/blake3/index.js';
import { blake3Wasm } from '../../../src/ts/blake3/embedded.js';
import { getInstance, _resetForTesting } from '../../../src/ts/init.js';
import type { Blake3Exports, Blake3TestExports } from '../../../src/ts/blake3/types.js';

export type Blake3FullExports = Blake3Exports & Blake3TestExports;

let _x:   Blake3FullExports | null = null;
let _mem: Uint8Array | null        = null;

export async function loadBlake3(): Promise<Blake3FullExports> {
	if (_x) return _x;
	_resetForTesting();
	await blake3Init(blake3Wasm);
	_x   = getInstance('blake3').exports as unknown as Blake3FullExports;
	_mem = new Uint8Array(_x.memory.buffer);
	return _x;
}

export function exports_(): Blake3FullExports {
	if (!_x) throw new Error('blake3 not loaded; call loadBlake3() in beforeAll');
	return _x;
}

export function mem(): Uint8Array {
	if (!_mem) throw new Error('blake3 not loaded; call loadBlake3() in beforeAll');
	return _mem;
}

export function toHex(b: Uint8Array): string {
	return Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
}

export function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

// Read n bytes from WASM linear memory as a fresh slice.
export function readMem(offset: number, len: number): Uint8Array {
	return mem().slice(offset, offset + len);
}

// Write bytes into WASM linear memory at the given offset.
export function writeMem(offset: number, data: Uint8Array): void {
	mem().set(data, offset);
}

// ── Scratch layout for the tree-internals tests ─────────────────────────────
//
// The blake3 WASM module's mutable buffer region runs through
// `BUFFER_END` (26328 bytes from src/asm/blake3/buffers.ts, after the
// TASK-J LEVEL_QUEUES expansion). Helpers stage their _test* inputs at
// 16384 (which lies inside LEVEL_QUEUES) and read outputs from CV_BUF_*
// past BUFFER_END at 81920+. This is safe because the `_test*` entries
// (`_testChunkCV` / `_testParentCV` / `_testDeriveContextCV`) never
// touch LEVEL_QUEUES — they drive the chunk and single-pair parent
// paths directly. Mixing these with full `BLAKE3.hash` calls is fine
// too: BLAKE3.hash stages its inputs at INPUT_SCRATCH_OFF = 28672, and
// any LEVEL_QUEUES writes from that path may overwrite helper bytes at
// 16384 — but no helper call re-reads those bytes after a full hash.

export const INPUT_OFF = 16384;
export const CV_BUF_0  = INPUT_OFF + 65536;       // 81920
export const CV_BUF_1  = CV_BUF_0 + 64;           // 81984
export const CV_BUF_2  = CV_BUF_1 + 64;           // 82048
export const CV_BUF_3  = CV_BUF_2 + 64;           // 82112
export const CV_BUF_4  = CV_BUF_3 + 64;           // 82176
export const CV_BUF_5  = CV_BUF_4 + 64;           // 82240
export const CV_BUF_6  = CV_BUF_5 + 64;           // 82304
export const CV_BUF_7  = CV_BUF_6 + 64;           // 82368
export const START_CV  = CV_BUF_7 + 64;           // 82432, 32-byte buffer for startCv

// BLAKE3 IV bytes (§2.2 Table 1) packed as 8 u32 little-endian words,
// emitted as 32 bytes for use as `startCvOff` in hash-mode `_chunkCV`
// and `_parentCV` calls. Sourced directly from the spec.
export const BLAKE3_IV_BYTES: Uint8Array = (() => {
	const iv32 = new Uint32Array([
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	]);
	return new Uint8Array(iv32.buffer);
})();

// ── Ergonomic test wrappers ─────────────────────────────────────────────────
//
// These hide the staging dance (write CV / input → call `_test*` →
// read CV out) behind a small Uint8Array-only surface for the test
// suite. Each call uses a deterministic scratch slot so multiple
// concurrent calls within the same test would clash; tests serialize.

/**
 * Compute the chunk CV for `input` at `chunkIndex` with `startCv` as the
 * starting CV and `modeFlags` as the per-mode bit. Returns 32 bytes.
 * Stages `input` at INPUT_OFF, `startCv` at START_CV, calls the WASM
 * `_testChunkCV` with output landing in CV_BUF_0.
 */
export function _chunkCV(
	input:      Uint8Array,
	chunkIndex: bigint,
	startCv:    Uint8Array,
	modeFlags:  number,
): Uint8Array {
	const x = exports_();
	const m = mem();
	if (startCv.length !== 32) throw new Error(`_chunkCV: startCv must be 32 bytes, got ${startCv.length}`);
	m.set(input,   INPUT_OFF);
	m.set(startCv, START_CV);
	x._testChunkCV(INPUT_OFF, input.length, chunkIndex, START_CV, modeFlags, CV_BUF_0);
	return readMem(CV_BUF_0, 32);
}

/**
 * Compose a parent CV from `left` || `right` 32-byte child CVs with
 * `startCv` and `modeFlags` as the mode parameters. When `isRoot` is
 * true the underlying compress carries PARENT|ROOT and the XOF
 * squeeze state is populated. Returns 32 bytes.
 */
export function _parentCV(
	left:      Uint8Array,
	right:     Uint8Array,
	startCv:   Uint8Array,
	modeFlags: number,
	isRoot:    boolean,
): Uint8Array {
	const x = exports_();
	const m = mem();
	if (left.length !== 32)    throw new Error(`_parentCV: left must be 32 bytes, got ${left.length}`);
	if (right.length !== 32)   throw new Error(`_parentCV: right must be 32 bytes, got ${right.length}`);
	if (startCv.length !== 32) throw new Error(`_parentCV: startCv must be 32 bytes, got ${startCv.length}`);
	m.set(left,    CV_BUF_1);
	m.set(right,   CV_BUF_2);
	m.set(startCv, START_CV);
	x._testParentCV(CV_BUF_1, CV_BUF_2, START_CV, modeFlags, isRoot ? 1 : 0, CV_BUF_0);
	return readMem(CV_BUF_0, 32);
}

/**
 * Run BLAKE3 derive_key pass 1 in isolation (§2.3 Modes). Returns the 32-byte
 * context_chain_value (CCV), suitable as `startCv` for a follow-up
 * pass-2 call to `_chunkCV` / `_parentCV` with `modeFlags` =
 * FLAG_DERIVE_KEY_MATERIAL.
 */
export function _deriveContextCV(context: Uint8Array): Uint8Array {
	const x = exports_();
	const m = mem();
	m.set(context, INPUT_OFF);
	x._testDeriveContextCV(INPUT_OFF, context.length, CV_BUF_0);
	return readMem(CV_BUF_0, 32);
}

/**
 * Number of `chunkBatch4` (compress4 4-chunk batch) invocations the
 * WASM module has executed since the last `resetBatch4CallCount()`.
 * Test-grade instrumentation; the compress4-dispatch suite resets,
 * runs a hash, and asserts this count matches the expected number of
 * 4-chunk batches dispatched by `hashCore` for the input size.
 */
export function getBatch4CallCount(): number {
	return exports_()._getBatch4CallCount();
}

/**
 * Reset the WASM-side compress4 batch counter. Call once before each
 * dispatch assertion to isolate the count from prior activity on the
 * same module instance.
 */
export function resetBatch4CallCount(): void {
	exports_()._resetBatch4CallCount();
}

/**
 * Number of `parentBatch4` (compress4 4-parent batch) invocations the
 * WASM module has executed since the last `resetParentBatch4CallCount()`.
 * Test-grade instrumentation for the parent-level dispatch suite,
 * parallel to `getBatch4CallCount` / `resetBatch4CallCount` (TASK-I).
 * The parent-dispatch test resets, runs a hash, and asserts this count
 * matches the predicted cascade for the input size.
 */
export function getParentBatch4CallCount(): number {
	return exports_()._getParentBatch4CallCount();
}

/**
 * Reset the WASM-side parent-batch counter. Pair with
 * `getParentBatch4CallCount`. Tests call this before each assertion to
 * isolate the count from prior activity on the same module instance.
 */
export function resetParentBatch4CallCount(): void {
	exports_()._resetParentBatch4CallCount();
}
