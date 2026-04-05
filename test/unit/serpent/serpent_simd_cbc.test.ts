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
 * SIMD CBC decrypt cross-check — scalar vs SIMD for a broad range of sizes.
 * Exercises the SIMD inner loop, scalar tail, and chaining across chunk boundaries.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';

interface CbcExports {
	memory:                 WebAssembly.Memory
	getKeyOffset:           () => number
	getCbcIvOffset:         () => number
	getChunkPtOffset:       () => number
	getChunkCtOffset:       () => number
	getChunkSize:           () => number
	loadKey:                (n: number) => number
	cbcEncryptChunk:        (n: number) => number
	cbcDecryptChunk:        (n: number) => number
	cbcDecryptChunk_simd:   (n: number) => number
}

function getWasm(): CbcExports {
	return getInstance('serpent').exports as unknown as CbcExports;
}

// 128-bit key for variety (different from gate test's 256-bit key)
const KEY_128 = new Uint8Array([
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
	0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
]);

const IV = new Uint8Array([
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
]);

function setup(wasm: CbcExports): void {
	const mem = new Uint8Array(wasm.memory.buffer);
	mem.set(KEY_128, wasm.getKeyOffset());
	wasm.loadKey(KEY_128.length);
	mem.set(IV, wasm.getCbcIvOffset());
}

// Encrypt → decrypt with both paths, compare
function crossCheck(ptLen: number): void {
	const wasm = getWasm();
	const mem = new Uint8Array(wasm.memory.buffer);
	const ptOff = wasm.getChunkPtOffset();
	const ctOff = wasm.getChunkCtOffset();

	const pt = new Uint8Array(ptLen);
	for (let i = 0; i < ptLen; i++) pt[i] = (i * 13 + 7) & 0xFF;

	// Encrypt
	setup(wasm);
	mem.set(pt, ptOff);
	wasm.cbcEncryptChunk(ptLen);
	const ct = mem.slice(ctOff, ctOff + ptLen);

	// Scalar decrypt
	setup(wasm);
	mem.set(ct, ctOff);
	wasm.cbcDecryptChunk(ptLen);
	const scalarPt = mem.slice(ptOff, ptOff + ptLen);

	// SIMD decrypt
	setup(wasm);
	mem.set(ct, ctOff);
	wasm.cbcDecryptChunk_simd(ptLen);
	const simdPt = mem.slice(ptOff, ptOff + ptLen);

	expect(Array.from(simdPt), `SIMD vs scalar (${ptLen} bytes)`).toEqual(Array.from(scalarPt));
	expect(Array.from(simdPt), `SIMD vs original (${ptLen} bytes)`).toEqual(Array.from(pt));
}

beforeAll(async () => {
	await init({ serpent: serpentWasm });
});

describe('SIMD CBC decrypt cross-check — broad size coverage', () => {
	// Every block count from 1 to 12 (exercises all SIMD/tail combinations)
	for (let blocks = 1; blocks <= 12; blocks++) {
		const len = blocks * 16;
		it(`${blocks} block(s) = ${len} bytes`, () => crossCheck(len));
	}

	// Larger sizes
	it('256 blocks = 4096 bytes', () => crossCheck(4096));
	it('1024 blocks = 16384 bytes', () => crossCheck(16384));
	it('CHUNK_SIZE = 65536 bytes', () => crossCheck(65536));
});
