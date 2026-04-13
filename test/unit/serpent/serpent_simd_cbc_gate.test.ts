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
 * SIMD CBC decrypt gate test.
 *
 * GATE — must pass before any CBC cross-check or benchmark work.
 * Do NOT adjust test data if this fails. Fix the implementation.
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
	wipeBuffers:            () => void
}

function getWasm(): CbcExports {
	return getInstance('serpent').exports as unknown as CbcExports;
}

const TEST_KEY = new Uint8Array([
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
]);

const TEST_IV = new Uint8Array([
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
]);

function loadKeyAndIv(wasm: CbcExports): void {
	const mem = new Uint8Array(wasm.memory.buffer);
	mem.set(TEST_KEY, wasm.getKeyOffset());
	wasm.loadKey(TEST_KEY.length);
	mem.set(TEST_IV, wasm.getCbcIvOffset());
}

// Helper: encrypt plaintext, then decrypt with both scalar and SIMD, compare
function roundTrip(ptLen: number): void {
	const wasm = getWasm();
	const mem = new Uint8Array(wasm.memory.buffer);
	const ptOff = wasm.getChunkPtOffset();
	const ctOff = wasm.getChunkCtOffset();

	// Build deterministic plaintext
	const pt = new Uint8Array(ptLen);
	for (let i = 0; i < ptLen; i++) pt[i] = (i * 7 + 13) & 0xFF;

	// Encrypt (scalar — no SIMD encrypt exists)
	loadKeyAndIv(wasm);
	mem.set(pt, ptOff);
	wasm.cbcEncryptChunk(ptLen);
	const ct = mem.slice(ctOff, ctOff + ptLen);

	// Scalar decrypt
	loadKeyAndIv(wasm);
	mem.set(ct, ctOff);
	wasm.cbcDecryptChunk(ptLen);
	const scalarPt = mem.slice(ptOff, ptOff + ptLen);

	// SIMD decrypt
	loadKeyAndIv(wasm);
	mem.set(ct, ctOff);
	wasm.cbcDecryptChunk_simd(ptLen);
	const simdPt = mem.slice(ptOff, ptOff + ptLen);

	// Both must match original plaintext
	expect(Array.from(scalarPt), 'scalar decrypt matches original').toEqual(Array.from(pt));
	expect(Array.from(simdPt), 'SIMD decrypt matches original').toEqual(Array.from(pt));
	expect(Array.from(simdPt), 'SIMD matches scalar').toEqual(Array.from(scalarPt));
}

beforeAll(async () => {
	await init({ serpent: serpentWasm });
});

describe('SIMD CBC decrypt gate', () => {
	// GATE — Serpent SIMD CBC decrypt: byte-identical to scalar
	it('4 blocks (64 bytes) — exercises SIMD inner loop only', () => {
		roundTrip(64);
	});

	it('5 blocks (80 bytes) — exercises SIMD loop + scalar tail', () => {
		roundTrip(80);
	});

	it('1 block (16 bytes) — scalar tail only', () => {
		roundTrip(16);
	});

	it('8 blocks (128 bytes) — two SIMD iterations', () => {
		roundTrip(128);
	});

	it('7 blocks (112 bytes) — one SIMD iteration + 3-block tail', () => {
		roundTrip(112);
	});
});

describe('SIMD CBC decrypt chaining continuity — multi-call', () => {
	it('3 × CHUNK_SIZE decrypt: SIMD matches scalar across chunk boundaries', () => {
		const wasm = getWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		const ptOff = wasm.getChunkPtOffset();
		const ctOff = wasm.getChunkCtOffset();
		const chunkSize = wasm.getChunkSize();
		const totalLen = 3 * chunkSize;

		// Build large plaintext
		const fullPt = new Uint8Array(totalLen);
		for (let i = 0; i < totalLen; i++) fullPt[i] = (i * 11 + 37) & 0xFF;

		// Encrypt in chunks (scalar)
		loadKeyAndIv(wasm);
		const fullCt = new Uint8Array(totalLen);
		for (let off = 0; off < totalLen; off += chunkSize) {
			const chunk = fullPt.subarray(off, off + chunkSize);
			mem.set(chunk, ptOff);
			wasm.cbcEncryptChunk(chunkSize);
			fullCt.set(new Uint8Array(wasm.memory.buffer).subarray(ctOff, ctOff + chunkSize), off);
		}

		// Scalar decrypt in chunks
		loadKeyAndIv(wasm);
		const scalarResult = new Uint8Array(totalLen);
		for (let off = 0; off < totalLen; off += chunkSize) {
			mem.set(fullCt.subarray(off, off + chunkSize), ctOff);
			wasm.cbcDecryptChunk(chunkSize);
			scalarResult.set(new Uint8Array(wasm.memory.buffer).subarray(ptOff, ptOff + chunkSize), off);
		}

		// SIMD decrypt in chunks
		loadKeyAndIv(wasm);
		const simdResult = new Uint8Array(totalLen);
		for (let off = 0; off < totalLen; off += chunkSize) {
			mem.set(fullCt.subarray(off, off + chunkSize), ctOff);
			wasm.cbcDecryptChunk_simd(chunkSize);
			simdResult.set(new Uint8Array(wasm.memory.buffer).subarray(ptOff, ptOff + chunkSize), off);
		}

		expect(Array.from(scalarResult), 'scalar matches original').toEqual(Array.from(fullPt));
		expect(Array.from(simdResult), 'SIMD matches scalar').toEqual(Array.from(scalarResult));
	});
});
