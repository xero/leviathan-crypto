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
 * BLAKE3 compression-function gate test, BLAKE3 §2.2.
 *
 * Drives the WASM `compress` primitive against the BLAKE3 known-answer
 * vectors corpus pinned at `test/vectors/blake3.ts`. The empty-input
 * record (`blake3Vectors[0]`) reduces to a single compression call:
 *   CV       = BLAKE3 IV (§2.2 Table 1)
 *   block    = 64 zero bytes
 *   counter  = 0
 *   blockLen = 0
 *   flags    = CHUNK_START | CHUNK_END | ROOT
 *
 * The first 32 bytes of the compression output are the chunk's chaining
 * value, and for the empty input this is also the default-length BLAKE3
 * hash per §2.1. The test asserts those 32 bytes match the first 64 hex
 * chars of `blake3Vectors[0].hashHex`.
 *
 * The expected value is sourced from `test/vectors/blake3.ts` (the
 * BLAKE3 upstream KAT JSON), not embedded in this file, per AGENTS.md
 * §Ground Rules #5.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';
import { blake3Vectors } from '../../vectors/blake3.js';

interface Blake3Exports {
	memory:                  WebAssembly.Memory;
	getCvOffset:             () => number;
	getMsgOffset:            () => number;
	getCompressOutOffset:    () => number;
	getModuleId:             () => number;
	compress:                (
		cvOff:     number,
		blockOff:  number,
		counterLo: number,
		counterHi: number,
		blockLen:  number,
		flags:     number,
		outOff:    number,
	) => void;
	wipeBuffers:             () => void;
	BLAKE3_IV0:              WebAssembly.Global;
	BLAKE3_IV1:              WebAssembly.Global;
	BLAKE3_IV2:              WebAssembly.Global;
	BLAKE3_IV3:              WebAssembly.Global;
	BLAKE3_IV4:              WebAssembly.Global;
	BLAKE3_IV5:              WebAssembly.Global;
	BLAKE3_IV6:              WebAssembly.Global;
	BLAKE3_IV7:              WebAssembly.Global;
	FLAG_CHUNK_START:        WebAssembly.Global;
	FLAG_CHUNK_END:          WebAssembly.Global;
	FLAG_ROOT:               WebAssembly.Global;
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

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

describe('BLAKE3 compress, §2.2 single-block gate', () => {
	// GATE: BLAKE3 §2.2 compression on the empty-input KAT.
	// Vector: test/vectors/blake3.ts[blake3Vectors[0]] (inputLen=0).
	// Do NOT modify this test or the source vector if it fails; fix the
	// implementation per AGENTS.md §Ground Rules #2 and §Gate discipline.
	it('empty input: compress(IV, 0, 0, 0, CHUNK_START|CHUNK_END|ROOT) matches KAT', () => {
		const mem = new Uint8Array(wasm.memory.buffer);
		const dv  = new DataView(wasm.memory.buffer);

		wasm.wipeBuffers();

		const cvOff  = wasm.getCvOffset();
		const msgOff = wasm.getMsgOffset();
		const outOff = wasm.getCompressOutOffset();

		// CV = BLAKE3 IV per §2.2 Table 1. Read the constants from the
		// module's exported globals rather than re-encoding them here, so
		// the test sources the cryptographic values from the implementation
		// surface and not from a planning document.
		dv.setUint32(cvOff +  0, wasm.BLAKE3_IV0.value as number, true);
		dv.setUint32(cvOff +  4, wasm.BLAKE3_IV1.value as number, true);
		dv.setUint32(cvOff +  8, wasm.BLAKE3_IV2.value as number, true);
		dv.setUint32(cvOff + 12, wasm.BLAKE3_IV3.value as number, true);
		dv.setUint32(cvOff + 16, wasm.BLAKE3_IV4.value as number, true);
		dv.setUint32(cvOff + 20, wasm.BLAKE3_IV5.value as number, true);
		dv.setUint32(cvOff + 24, wasm.BLAKE3_IV6.value as number, true);
		dv.setUint32(cvOff + 28, wasm.BLAKE3_IV7.value as number, true);

		// Empty message: 64 zero bytes already in place after wipeBuffers().
		mem.fill(0, msgOff, msgOff + 64);

		const flags =
			(wasm.FLAG_CHUNK_START.value as number) |
			(wasm.FLAG_CHUNK_END.value   as number) |
			(wasm.FLAG_ROOT.value        as number);

		wasm.compress(cvOff, msgOff, 0, 0, 0, flags, outOff);

		const digest = mem.slice(outOff, outOff + 32);
		const expected = blake3Vectors[0].hashHex.slice(0, 64);
		expect(blake3Vectors[0].inputLen).toBe(0);
		expect(toHex(digest)).toBe(expected);
	});
});
