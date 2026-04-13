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
 * SIMD gate test — encryptBlock_simd_4x must produce byte-identical output
 * to 4 sequential scalar encryptBlock calls.
 *
 * GATE — must pass before any SIMD CTR or benchmark work.
 * Do NOT adjust test inputs or expected values if this fails.
 * Fix the implementation (generator or serpent_simd.ts).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';

interface SerpentSimdExports {
	memory:                WebAssembly.Memory
	getKeyOffset:          () => number
	getBlockPtOffset:      () => number
	getBlockCtOffset:      () => number
	getSimdWorkOffset:     () => number
	loadKey:               (n: number) => number
	encryptBlock:          () => void
	encryptBlock_simd_4x:  () => void
	wipeBuffers:           () => void
}

function getWasm(): SerpentSimdExports {
	return getInstance('serpent').exports as unknown as SerpentSimdExports;
}

// Convert 16-byte block to 4 Serpent-internal words (byte-reversed LE)
// Matches the load order in serpent.ts encryptBlock:
//   r[0] = bytes[15..12], r[1] = bytes[11..8], r[2] = bytes[7..4], r[3] = bytes[3..0]
function blockToWords(block: Uint8Array): [number, number, number, number] {
	const w = (o: number) =>
		block[o + 3] | (block[o + 2] << 8) | (block[o + 1] << 16) | (block[o] << 24);
	return [w(12), w(8), w(4), w(0)];
}

// Convert 4 Serpent-internal words back to 16-byte block
// Matches the store order in serpent.ts encryptBlock:
//   ct[0..3] = r[3], ct[4..7] = r[2], ct[8..11] = r[1], ct[12..15] = r[0]
function wordsToBlock(w0: number, w1: number, w2: number, w3: number): Uint8Array {
	const out = new Uint8Array(16);
	const put = (o: number, v: number) => {
		out[o] = (v >>> 24) & 0xFF;
		out[o + 1] = (v >>> 16) & 0xFF;
		out[o + 2] = (v >>> 8) & 0xFF;
		out[o + 3] = v & 0xFF;
	};
	put(0, w3); put(4, w2); put(8, w1); put(12, w0);
	return out;
}

// 4 test blocks — distinct values to exercise all register slots
const TEST_BLOCKS: Uint8Array[] = [
	new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	                0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
	new Uint8Array([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
	                0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]),
	new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
	                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
	new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
	                0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01]),
];

// 256-bit test key
const TEST_KEY = new Uint8Array([
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
]);

beforeAll(async () => {
	await init({ serpent: serpentWasm });
});

describe('SIMD gate — encryptBlock_simd_4x vs scalar encryptBlock', () => {
	// GATE — Serpent SIMD 4-wide ECB: byte-identical to scalar
	it('4 blocks: SIMD output matches scalar output byte-for-byte', () => {
		const wasm = getWasm();
		const mem = new Uint8Array(wasm.memory.buffer);

		// Load key
		mem.set(TEST_KEY, wasm.getKeyOffset());
		wasm.loadKey(TEST_KEY.length);

		// Step 1: Encrypt each block with scalar encryptBlock
		const scalarResults: Uint8Array[] = [];
		for (const block of TEST_BLOCKS) {
			mem.set(block, wasm.getBlockPtOffset());
			wasm.encryptBlock();
			scalarResults.push(mem.slice(wasm.getBlockCtOffset(), wasm.getBlockCtOffset() + 16));
		}

		// Step 2: Encrypt all 4 blocks with encryptBlock_simd_4x
		// Interleave: v128 register w holds word w of all 4 blocks
		// In memory: SIMD_WORK_OFFSET + w*16 + b*4 = word w of block b (LE i32)
		const simdBase = wasm.getSimdWorkOffset();
		const dv = new DataView(wasm.memory.buffer);

		for (let b = 0; b < 4; b++) {
			const [w0, w1, w2, w3] = blockToWords(TEST_BLOCKS[b]);
			dv.setInt32(simdBase + 0 * 16 + b * 4, w0, true);
			dv.setInt32(simdBase + 1 * 16 + b * 4, w1, true);
			dv.setInt32(simdBase + 2 * 16 + b * 4, w2, true);
			dv.setInt32(simdBase + 3 * 16 + b * 4, w3, true);
		}

		wasm.encryptBlock_simd_4x();

		// Step 3: Deinterleave SIMD result and compare
		for (let b = 0; b < 4; b++) {
			const w0 = dv.getInt32(simdBase + 0 * 16 + b * 4, true);
			const w1 = dv.getInt32(simdBase + 1 * 16 + b * 4, true);
			const w2 = dv.getInt32(simdBase + 2 * 16 + b * 4, true);
			const w3 = dv.getInt32(simdBase + 3 * 16 + b * 4, true);
			const simdBlock = wordsToBlock(w0, w1, w2, w3);
			expect(
				Array.from(simdBlock),
				`block ${b} mismatch`,
			).toEqual(Array.from(scalarResults[b]));
		}
	});

	it('different key: SIMD still matches scalar', () => {
		const wasm = getWasm();
		const mem = new Uint8Array(wasm.memory.buffer);

		// Different 128-bit key
		const key128 = new Uint8Array([
			0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		]);
		mem.set(key128, wasm.getKeyOffset());
		wasm.loadKey(key128.length);

		// Scalar
		const scalarResults: Uint8Array[] = [];
		for (const block of TEST_BLOCKS) {
			mem.set(block, wasm.getBlockPtOffset());
			wasm.encryptBlock();
			scalarResults.push(mem.slice(wasm.getBlockCtOffset(), wasm.getBlockCtOffset() + 16));
		}

		// SIMD
		const simdBase = wasm.getSimdWorkOffset();
		const dv = new DataView(wasm.memory.buffer);

		for (let b = 0; b < 4; b++) {
			const [w0, w1, w2, w3] = blockToWords(TEST_BLOCKS[b]);
			dv.setInt32(simdBase + 0 * 16 + b * 4, w0, true);
			dv.setInt32(simdBase + 1 * 16 + b * 4, w1, true);
			dv.setInt32(simdBase + 2 * 16 + b * 4, w2, true);
			dv.setInt32(simdBase + 3 * 16 + b * 4, w3, true);
		}

		wasm.encryptBlock_simd_4x();

		for (let b = 0; b < 4; b++) {
			const w0 = dv.getInt32(simdBase + 0 * 16 + b * 4, true);
			const w1 = dv.getInt32(simdBase + 1 * 16 + b * 4, true);
			const w2 = dv.getInt32(simdBase + 2 * 16 + b * 4, true);
			const w3 = dv.getInt32(simdBase + 3 * 16 + b * 4, true);
			const simdBlock = wordsToBlock(w0, w1, w2, w3);
			expect(
				Array.from(simdBlock),
				`block ${b} mismatch (128-bit key)`,
			).toEqual(Array.from(scalarResults[b]));
		}
	});
});
