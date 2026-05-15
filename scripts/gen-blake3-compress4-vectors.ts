#!/usr/bin/env node
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
/**
 * Generate BLAKE3 compress4 KAT vectors.
 *
 * SELF-GENERATED. Each record's `expectedOut` is the concatenation of
 * four BLAKE3 §2.2 compress1 calls against the per-lane inputs in the
 * same record. compress1 is gated against the upstream BLAKE3 KAT corpus
 * by test/unit/blake3/blake3-compress.test.ts (empty-input record from
 * test/vectors/blake3.ts[0]); these vectors inherit that gate's
 * authority. Not sourced from any third-party BLAKE3 implementation.
 *
 * During generation, compress4 is also run against the same staged
 * inputs and the result is asserted byte-equal to the compress1
 * concatenation, so the script is a generator and an in-line
 * cross-check.
 *
 * usage:  bunx tsx scripts/gen-blake3-compress4-vectors.ts
 * output: test/vectors/blake3_compress4.ts
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname }            from 'node:path';
import { fileURLToPath }                from 'node:url';
import { blake3Vectors }                from '../test/vectors/blake3.js';

interface Blake3Exports {
	memory:                      WebAssembly.Memory;
	compress:                    (
		cvOff:     number,
		blockOff:  number,
		counterLo: number,
		counterHi: number,
		blockLen:  number,
		flags:     number,
		outOff:    number,
	) => void;
	compress4:                   () => void;
	wipeBuffers:                 () => void;
	getCvOffset:                 () => number;
	getMsgOffset:                () => number;
	getCompressOutOffset:        () => number;
	getCompress4CvInOffset:      () => number;
	getCompress4MsgInOffset:     () => number;
	getCompress4CtrInOffset:     () => number;
	getCompress4OutOffset:       () => number;
	getCompress4BlenInOffset:    () => number;
	getCompress4FlagsInOffset:   () => number;
	BLAKE3_IV0:                  WebAssembly.Global;
	BLAKE3_IV1:                  WebAssembly.Global;
	BLAKE3_IV2:                  WebAssembly.Global;
	BLAKE3_IV3:                  WebAssembly.Global;
	BLAKE3_IV4:                  WebAssembly.Global;
	BLAKE3_IV5:                  WebAssembly.Global;
	BLAKE3_IV6:                  WebAssembly.Global;
	BLAKE3_IV7:                  WebAssembly.Global;
	FLAG_CHUNK_START:            WebAssembly.Global;
	FLAG_CHUNK_END:              WebAssembly.Global;
	FLAG_PARENT:                 WebAssembly.Global;
	FLAG_ROOT:                   WebAssembly.Global;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../build/blake3.wasm');
const OUT_PATH   = resolve(__dirname, '../test/vectors/blake3_compress4.ts');

const bytes = readFileSync(WASM_PATH);
const { instance } = await WebAssembly.instantiate(bytes, {
	env: { abort: () => { throw new Error('blake3 wasm abort'); } },
});
const wasm = instance.exports as unknown as Blake3Exports;
const mem  = new Uint8Array(wasm.memory.buffer);
const dv   = new DataView(wasm.memory.buffer);

function toHex(b: Uint8Array): string {
	let s = '';
	for (const x of b) s += x.toString(16).padStart(2, '0');
	return s;
}

function ivBytes(): Uint8Array {
	const out = new Uint8Array(32);
	const dvL = new DataView(out.buffer);
	dvL.setUint32( 0, wasm.BLAKE3_IV0.value as number, true);
	dvL.setUint32( 4, wasm.BLAKE3_IV1.value as number, true);
	dvL.setUint32( 8, wasm.BLAKE3_IV2.value as number, true);
	dvL.setUint32(12, wasm.BLAKE3_IV3.value as number, true);
	dvL.setUint32(16, wasm.BLAKE3_IV4.value as number, true);
	dvL.setUint32(20, wasm.BLAKE3_IV5.value as number, true);
	dvL.setUint32(24, wasm.BLAKE3_IV6.value as number, true);
	dvL.setUint32(28, wasm.BLAKE3_IV7.value as number, true);
	return out;
}

// Deterministic fill: lane K byte i = (seed + K*offset + i) mod 251.
// 251 mirrors the upstream BLAKE3 input-expansion convention.
function patternBytes(seed: number, lane: number, len: number): Uint8Array {
	const out = new Uint8Array(len);
	for (let i = 0; i < len; i++) out[i] = (seed + lane * 37 + i) % 251;
	return out;
}

interface RecordInput {
	name:      string;
	cv:        [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
	msg:       [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
	counterLo: [number, number, number, number];
	counterHi: [number, number, number, number];
	blockLen:  [number, number, number, number];
	flags:     number;
}

const iv = ivBytes();

const FLAG_CHUNK_START = wasm.FLAG_CHUNK_START.value as number;
const FLAG_CHUNK_END   = wasm.FLAG_CHUNK_END.value   as number;
const FLAG_PARENT      = wasm.FLAG_PARENT.value      as number;
const FLAG_ROOT        = wasm.FLAG_ROOT.value        as number;

// CV variants for records 3 and 4: same length as IV, distinct per lane.
// Bytewise-fixed so the vector file is fully reproducible across runs.
function cvVariant(seed: number, lane: number): Uint8Array {
	return patternBytes(seed, lane, 32);
}

const records: RecordInput[] = [
	{
		// 1) All-zero shape: IV across all lanes, zero message, zero counter,
		// zero blockLen, full ROOT flag set. Lane 0's first 32 bytes equal
		// blake3Vectors[0].hashHex.slice(0, 64), tying the corpus back to
		// the externally-authoritative §2.2 KAT.
		name:      'all-zero-iv-root',
		cv:        [iv, iv, iv, iv],
		msg:       [new Uint8Array(64), new Uint8Array(64), new Uint8Array(64), new Uint8Array(64)],
		counterLo: [0, 0, 0, 0],
		counterHi: [0, 0, 0, 0],
		blockLen:  [0, 0, 0, 0],
		flags:     FLAG_CHUNK_START | FLAG_CHUNK_END | FLAG_ROOT,
	},
	{
		// 2) Shared CV (IV) across all four lanes, distinct everything else.
		// The lanes diverge through the rounds purely from msg/counter/blockLen.
		// Counters cover (0,0), (1,0), (0xffffffff,0), (0,1) so the lo→hi
		// boundary, a common compress1↔compress4 trip wire, is exercised.
		name:      'shared-iv-distinct-counters',
		cv:        [iv, iv, iv, iv],
		msg:       [
			patternBytes(0xA0, 0, 64),
			patternBytes(0xA0, 1, 64),
			patternBytes(0xA0, 2, 64),
			patternBytes(0xA0, 3, 64),
		],
		counterLo: [0, 1, 0xffffffff, 0],
		counterHi: [0, 0, 0, 1],
		blockLen:  [64, 32, 16, 1],
		flags:     0,
	},
	{
		// 3) Distinct per-lane CVs, FLAG_PARENT, counter zero per §2.4 (parent
		// counter is always zero), blockLen 64. Exercises the parent-node
		// compression shape that the multi-chunk-parallel call path will use.
		name:      'distinct-cv-flag-parent',
		cv: [
			cvVariant(0x31, 0),
			cvVariant(0x31, 1),
			cvVariant(0x31, 2),
			cvVariant(0x31, 3),
		],
		msg: [
			patternBytes(0xB0, 0, 64),
			patternBytes(0xB0, 1, 64),
			patternBytes(0xB0, 2, 64),
			patternBytes(0xB0, 3, 64),
		],
		counterLo: [0, 0, 0, 0],
		counterHi: [0, 0, 0, 0],
		blockLen:  [64, 64, 64, 64],
		flags:     FLAG_PARENT,
	},
	{
		// 4) Distinct per-lane CVs, non-zero counter high half varying across
		// lanes. Specifically exercises the v12/v13 register pair in
		// compress_simd.ts. flags = 0 keeps this distinct from record 3.
		name:      'distinct-cv-high-counter',
		cv: [
			cvVariant(0x41, 0),
			cvVariant(0x41, 1),
			cvVariant(0x41, 2),
			cvVariant(0x41, 3),
		],
		msg: [
			patternBytes(0xC0, 0, 64),
			patternBytes(0xC0, 1, 64),
			patternBytes(0xC0, 2, 64),
			patternBytes(0xC0, 3, 64),
		],
		counterLo: [0, 1, 2, 3],
		counterHi: [0x100, 0x101, 0x102, 0x103],
		blockLen:  [64, 64, 64, 64],
		flags:     0,
	},
];

interface ResolvedRecord {
	name:        string;
	cv:          string[];
	msg:         string[];
	counterLo:   number[];
	counterHi:   number[];
	blockLen:    number[];
	flags:       number;
	expectedOut: string;
}

const cv1Off    = wasm.getCvOffset();
const msg1Off   = wasm.getMsgOffset();
const out1Off   = wasm.getCompressOutOffset();
const c4CvOff   = wasm.getCompress4CvInOffset();
const c4MsgOff  = wasm.getCompress4MsgInOffset();
const c4CtrOff  = wasm.getCompress4CtrInOffset();
const c4BlenOff = wasm.getCompress4BlenInOffset();
const c4FlagOff = wasm.getCompress4FlagsInOffset();
const c4OutOff  = wasm.getCompress4OutOffset();

const resolved: ResolvedRecord[] = [];

for (const rec of records) {
	wasm.wipeBuffers();

	// Stage per-lane inputs into the COMPRESS4_* buffers for the
	// compress4 cross-check.
	for (let k = 0; k < 4; k++) {
		mem.set(rec.cv[k],  c4CvOff  + k * 32);
		mem.set(rec.msg[k], c4MsgOff + k * 64);
		dv.setUint32(c4CtrOff  + k * 8,     rec.counterLo[k] >>> 0, true);
		dv.setUint32(c4CtrOff  + k * 8 + 4, rec.counterHi[k] >>> 0, true);
		dv.setUint32(c4BlenOff + k * 4,     rec.blockLen[k]  >>> 0, true);
	}
	dv.setUint32(c4FlagOff, rec.flags >>> 0, true);

	// Build the expectedOut by running compress1 four times against the
	// same per-lane inputs.
	const expected = new Uint8Array(4 * 64);
	for (let k = 0; k < 4; k++) {
		mem.set(rec.cv[k],  cv1Off);
		mem.set(rec.msg[k], msg1Off);
		wasm.compress(cv1Off, msg1Off, rec.counterLo[k] >>> 0, rec.counterHi[k] >>> 0, rec.blockLen[k] >>> 0, rec.flags >>> 0, out1Off);
		expected.set(mem.slice(out1Off, out1Off + 64), k * 64);
	}

	// Run compress4 and assert byte-equality. compress1's staging above
	// scribbles over CV_OFFSET and MSG_OFFSET, but the COMPRESS4_*
	// staging is in disjoint memory and survives untouched.
	wasm.compress4();
	const out4 = mem.slice(c4OutOff, c4OutOff + 256);
	for (let i = 0; i < 256; i++) {
		if (out4[i] !== expected[i]) {
			throw new Error(`${rec.name}: compress4 disagrees with compress1 at byte ${i} (${out4[i]} vs ${expected[i]})`);
		}
	}

	resolved.push({
		name:        rec.name,
		cv:          rec.cv.map(toHex),
		msg:         rec.msg.map(toHex),
		counterLo:   [...rec.counterLo],
		counterHi:   [...rec.counterHi],
		blockLen:    [...rec.blockLen],
		flags:       rec.flags,
		expectedOut: toHex(expected),
	});

	console.log(`${rec.name}: cross-verified compress4 == compress1×4 ✓`);
}

// Sanity assert: record 1's lane-0 first 32 bytes equal blake3Vectors[0].
const rec0Lane0First32 = resolved[0].expectedOut.slice(0, 64);
const upstreamFirst32  = blake3Vectors[0].hashHex.slice(0, 64);
if (rec0Lane0First32 !== upstreamFirst32) {
	throw new Error(
		`record 0 lane 0 first 32 bytes (${rec0Lane0First32}) do not match `
		+ `blake3Vectors[0].hashHex first 64 hex chars (${upstreamFirst32}). `
		+ `compress1 wiring is wrong or the IV/flag values drifted.`,
	);
}
console.log('record 0 lane 0 first 32 bytes match blake3Vectors[0] ✓');

// Emit the vector file. Match the existing test/vectors/*.ts style:
// ASCII art header, leading comment block describing provenance and
// audit status, exported interface, exported const array.
const asciiHeader = `//                  ▄▄▄▄▄▄▄▄▄▄
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

// test/vectors/blake3_compress4.ts
//
// BLAKE3 compress4 (v128-external SIMD) direct KAT corpus, BLAKE3 §2.1
// lane-parallel form. Four records exercising distinct input shapes:
//   1) all-zero / IV with ROOT flag (lane 0 ties to blake3Vectors[0])
//   2) shared IV across lanes, distinct counters / messages / blockLens
//   3) distinct per-lane CVs under FLAG_PARENT (multi-chunk parent shape)
//   4) distinct per-lane CVs with non-zero counter high half (v12/v13 pair)
//
// SELF-GENERATED via scripts/gen-blake3-compress4-vectors.ts. Each
// expectedOut is the concatenation of four BLAKE3 §2.2 compress1 calls
// against the per-lane inputs in the same record. compress1 is gated
// against the upstream BLAKE3 KAT corpus at
// test/unit/blake3/blake3-compress.test.ts (empty-input record from
// test/vectors/blake3.ts[0]), so these vectors inherit that gate's
// authority. Not sourced from any third-party BLAKE3 implementation.
//
// The generator also re-runs compress4 against the same staged inputs
// and asserts byte-equality against the compress1 concatenation, so
// generation doubles as a self-consistency check. The corpus is the
// primary regression gate on compress4, independent of hash() and
// later TASK-E XOF / TASK-F multi-chunk-parallel transitive paths.
//
// All hex strings are lowercase, no separators.
// Audit status: SELF-GENERATED (gate: BLAKE3 compress4)`;

const interfaceBlock = `export interface Blake3Compress4KatVector {
	name:        string;                            // human label, used in test reporter messages
	cv:          [string, string, string, string];  // 4 × 64 hex chars (32 bytes per lane)
	msg:         [string, string, string, string];  // 4 × 128 hex chars (64 bytes per lane)
	counterLo:   [number, number, number, number];  // u32 per lane
	counterHi:   [number, number, number, number];  // u32 per lane
	blockLen:    [number, number, number, number];  // u32 per lane
	flags:       number;                            // shared across lanes (compress4 contract, §2.1 "d")
	expectedOut: string;                            // 4 × 128 hex chars; lane-K bytes at K*64
}`;

function emitTuple(items: (string | number)[]): string {
	return '[' + items.map(x => typeof x === 'number' ? x.toString() : `'${x}'`).join(', ') + ']';
}

const recordsBlock = resolved.map(r => `	{
		name: '${r.name}',
		cv: ${emitTuple(r.cv)},
		msg: ${emitTuple(r.msg)},
		counterLo: ${emitTuple(r.counterLo)},
		counterHi: ${emitTuple(r.counterHi)},
		blockLen: ${emitTuple(r.blockLen)},
		flags: ${r.flags},
		expectedOut: '${r.expectedOut}',
	},`).join('\n');

const file = `${asciiHeader}

${interfaceBlock}

export const blake3Compress4Kat: readonly Blake3Compress4KatVector[] = [
${recordsBlock}
];
`;

writeFileSync(OUT_PATH, file);
console.log(`Written ${OUT_PATH}`);
