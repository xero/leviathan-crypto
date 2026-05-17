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
 * BLAKE3 compress4 vs compress1 bit-equivalence gate, BLAKE3 §2.2 / §5.3.
 *
 * compress4 (v128-external SIMD, lane K = compress operation K) must be
 * bit-identical to four sequential compress1 calls on the same inputs.
 * Equivalence is checked across deterministic randomized inputs from a
 * fixed seed across 64 iterations, exercising independently distributed
 * CV, message, counter, block_len, and flag values.
 *
 * If compress1 has already passed its §2.2 gate against the BLAKE3 KAT
 * (test/unit/blake3/blake3-compress.test.ts), then matching compress4
 * to it under random inputs establishes compress4's correctness without
 * embedding additional cryptographic values in this file.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';
import { blake3Compress4Kat } from '../../vectors/blake3_compress4.js';

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
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../../../build/blake3.wasm');

let wasm: Blake3Exports;

beforeAll(async () => {
	const bytes = readFileSync(WASM_PATH);
	const { instance } = await WebAssembly.instantiate(bytes, {
		env: { abort: () => {
			throw new Error('blake3 wasm abort');
		} },
	});
	wasm = instance.exports as unknown as Blake3Exports;
});

// xorshift32 PRNG, seeded per iteration so failures are reproducible.
function mkRng(seed: number): () => number {
	let s = seed | 0;
	if (s === 0) s = 0x12345678;
	return () => {
		s ^= s << 13; s |= 0;
		s ^= s >>> 17;
		s ^= s << 5;  s |= 0;
		return s >>> 0;
	};
}

function fillRandom(rng: () => number, mem: Uint8Array, off: number, len: number): void {
	for (let i = 0; i < len; i += 4) {
		const w = rng();
		mem[off + i    ] =  w        & 0xff;
		mem[off + i + 1] = (w >>>  8) & 0xff;
		mem[off + i + 2] = (w >>> 16) & 0xff;
		mem[off + i + 3] = (w >>> 24) & 0xff;
	}
}

function toHex(b: Uint8Array): string {
	let s = '';
	for (const x of b) s += x.toString(16).padStart(2, '0');
	return s;
}

function fromHex(h: string): Uint8Array {
	const out = new Uint8Array(h.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
	return out;
}

describe('BLAKE3 compress4 vs compress1, §5.3 lane-parallel equivalence', () => {
	// GATE: compress4 (v128-external SIMD) must be bit-equivalent to four
	// sequential compress1 calls on the same inputs. compress1's own §2.2
	// gate in blake3-compress.test.ts is the authority for compression
	// correctness; this test gates the SIMD form.
	// Sourced inputs: deterministic PRNG, no embedded cryptographic values.
	it('compress4 = 4 × compress1 across 64 randomized iterations', () => {
		const mem = new Uint8Array(wasm.memory.buffer);
		const dv  = new DataView(wasm.memory.buffer);

		const c4Cv    = wasm.getCompress4CvInOffset();
		const c4Msg   = wasm.getCompress4MsgInOffset();
		const c4Ctr   = wasm.getCompress4CtrInOffset();
		const c4Blen  = wasm.getCompress4BlenInOffset();
		const c4Flags = wasm.getCompress4FlagsInOffset();
		const c4Out   = wasm.getCompress4OutOffset();

		const cv1     = wasm.getCvOffset();
		const msg1    = wasm.getMsgOffset();
		const out1    = wasm.getCompressOutOffset();

		for (let iter = 0; iter < 64; iter++) {
			wasm.wipeBuffers();
			const rng = mkRng(0xb1a3e000 + iter);

			// Stage four independent input sets in the COMPRESS4_* buffers.
			fillRandom(rng, mem, c4Cv,  4 * 32);
			fillRandom(rng, mem, c4Msg, 4 * 64);
			fillRandom(rng, mem, c4Ctr, 4 *  8);

			// block_len per lane (any u32; runtime accepts arbitrary values).
			const blens: number[] = [];
			for (let k = 0; k < 4; k++) {
				const b = rng();
				dv.setUint32(c4Blen + k * 4, b, true);
				blens.push(b);
			}
			// Single shared flags value across all lanes.
			const flags = rng();
			dv.setUint32(c4Flags, flags, true);

			// Snapshot per-lane inputs before running compress4 so the
			// compress1 sweep below sees the same bytes.
			const cvCopy   = mem.slice(c4Cv,  c4Cv  + 4 * 32);
			const msgCopy  = mem.slice(c4Msg, c4Msg + 4 * 64);
			const ctrCopy  = mem.slice(c4Ctr, c4Ctr + 4 *  8);

			wasm.compress4();
			const out4 = mem.slice(c4Out, c4Out + 4 * 64);

			for (let k = 0; k < 4; k++) {
				// Stage lane K's CV at CV_OFFSET and message at MSG_OFFSET
				// for compress1; counter and block_len pass via function args.
				mem.set(cvCopy.slice (k * 32, k * 32 + 32), cv1);
				mem.set(msgCopy.slice(k * 64, k * 64 + 64), msg1);
				const counterLo = ctrCopy[k * 8    ]
				                | (ctrCopy[k * 8 + 1] <<  8)
				                | (ctrCopy[k * 8 + 2] << 16)
				                | (ctrCopy[k * 8 + 3] << 24);
				const counterHi = ctrCopy[k * 8 + 4]
				                | (ctrCopy[k * 8 + 5] <<  8)
				                | (ctrCopy[k * 8 + 6] << 16)
				                | (ctrCopy[k * 8 + 7] << 24);

				wasm.compress(cv1, msg1, counterLo >>> 0, counterHi >>> 0, blens[k] >>> 0, flags >>> 0, out1);
				const out1Bytes = mem.slice(out1, out1 + 64);
				const out4Lane  = out4.slice(k * 64, k * 64 + 64);

				expect(
					Array.from(out4Lane),
					`iter=${iter} lane=${k}`,
				).toEqual(Array.from(out1Bytes));
			}
		}
	});

	// Cross-lane register leaks (e.g. a wrong `extract_lane` index in the
	// compress4 deinterleave block) hide under the random-distinct sweep
	// above: with fully distinct per-lane inputs, the "right" and "leaked"
	// answers both differ from each other AND from compress1's per-lane
	// output, so a leak still trips the equality check. But the specific
	// shape where the same CV feeds every lane is the one that *would*
	// hide it if the leak happened to share a register that carried the
	// CV portion of state. Staging an identical CV across all four lanes
	// (with distinct msg/counter/blockLen so the lanes still diverge
	// through the rounds) gives the equality check a clean signal on this
	// case specifically. 16 iterations vary the shared CV across seeds.
	it('compress4 lane K = compress1 with shared CV across lanes, distinct msg/counter/blockLen', () => {
		const mem = new Uint8Array(wasm.memory.buffer);
		const dv  = new DataView(wasm.memory.buffer);

		const c4Cv    = wasm.getCompress4CvInOffset();
		const c4Msg   = wasm.getCompress4MsgInOffset();
		const c4Ctr   = wasm.getCompress4CtrInOffset();
		const c4Blen  = wasm.getCompress4BlenInOffset();
		const c4Flags = wasm.getCompress4FlagsInOffset();
		const c4Out   = wasm.getCompress4OutOffset();

		const cv1     = wasm.getCvOffset();
		const msg1    = wasm.getMsgOffset();
		const out1    = wasm.getCompressOutOffset();

		for (let iter = 0; iter < 16; iter++) {
			wasm.wipeBuffers();
			const rng = mkRng(0xb1a3e100 + iter);

			// Draw one 32-byte CV and copy it into all four lane slots.
			const sharedCv = new Uint8Array(32);
			fillRandom(rng, sharedCv, 0, 32);
			for (let k = 0; k < 4; k++) mem.set(sharedCv, c4Cv + k * 32);

			fillRandom(rng, mem, c4Msg, 4 * 64);
			fillRandom(rng, mem, c4Ctr, 4 *  8);

			const blens: number[] = [];
			for (let k = 0; k < 4; k++) {
				const b = rng();
				dv.setUint32(c4Blen + k * 4, b, true);
				blens.push(b);
			}
			const flags = rng();
			dv.setUint32(c4Flags, flags, true);

			const msgCopy = mem.slice(c4Msg, c4Msg + 4 * 64);
			const ctrCopy = mem.slice(c4Ctr, c4Ctr + 4 *  8);

			wasm.compress4();
			const out4 = mem.slice(c4Out, c4Out + 4 * 64);

			for (let k = 0; k < 4; k++) {
				mem.set(sharedCv,                                       cv1);
				mem.set(msgCopy.slice(k * 64, k * 64 + 64),             msg1);
				const counterLo = ctrCopy[k * 8    ]
				                | (ctrCopy[k * 8 + 1] <<  8)
				                | (ctrCopy[k * 8 + 2] << 16)
				                | (ctrCopy[k * 8 + 3] << 24);
				const counterHi = ctrCopy[k * 8 + 4]
				                | (ctrCopy[k * 8 + 5] <<  8)
				                | (ctrCopy[k * 8 + 6] << 16)
				                | (ctrCopy[k * 8 + 7] << 24);

				wasm.compress(cv1, msg1, counterLo >>> 0, counterHi >>> 0, blens[k] >>> 0, flags >>> 0, out1);
				const out1Bytes = mem.slice(out1, out1 + 64);
				const out4Lane  = out4.slice(k * 64, k * 64 + 64);

				expect(
					Array.from(out4Lane),
					`iter=${iter} lane=${k} (shared CV)`,
				).toEqual(Array.from(out1Bytes));
			}
		}
	});

	// Direct KAT gate on compress4: four fixed input sets staged from
	// test/vectors/blake3_compress4.ts. Each record's expectedOut was
	// derived by running compress1 (BLAKE3 §2.2, gated against the
	// upstream KAT corpus in blake3-compress.test.ts) four times against
	// the per-lane inputs and concatenating the outputs. The generator
	// (scripts/gen-blake3-compress4-vectors.ts) re-runs compress4 against
	// the same inputs at generation time and asserts byte-equality, so
	// the vector file is self-consistent. This test is the primary
	// regression gate on compress4 independent of hash() and the later
	// XOF / multi-chunk-parallel transitive paths.
	it('compress4 KAT: 4 fixed input sets, expected outputs derived from compress1', () => {
		const mem = new Uint8Array(wasm.memory.buffer);
		const dv  = new DataView(wasm.memory.buffer);

		const c4Cv    = wasm.getCompress4CvInOffset();
		const c4Msg   = wasm.getCompress4MsgInOffset();
		const c4Ctr   = wasm.getCompress4CtrInOffset();
		const c4Blen  = wasm.getCompress4BlenInOffset();
		const c4Flags = wasm.getCompress4FlagsInOffset();
		const c4Out   = wasm.getCompress4OutOffset();

		expect(blake3Compress4Kat.length).toBe(4);

		for (const vec of blake3Compress4Kat) {
			wasm.wipeBuffers();

			for (let k = 0; k < 4; k++) {
				mem.set(fromHex(vec.cv[k]),  c4Cv  + k * 32);
				mem.set(fromHex(vec.msg[k]), c4Msg + k * 64);
				dv.setUint32(c4Ctr  + k * 8,     vec.counterLo[k] >>> 0, true);
				dv.setUint32(c4Ctr  + k * 8 + 4, vec.counterHi[k] >>> 0, true);
				dv.setUint32(c4Blen + k * 4,     vec.blockLen[k]  >>> 0, true);
			}
			dv.setUint32(c4Flags, vec.flags >>> 0, true);

			wasm.compress4();
			const out = mem.slice(c4Out, c4Out + 4 * 64);

			expect(toHex(out), `KAT ${vec.name}`).toBe(vec.expectedOut);
		}
	});
});
