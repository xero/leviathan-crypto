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
 * BLAKE3 hash KAT, BLAKE3 §2.4 / §2.5 / §2.6.
 *
 * Drives the WASM `hash` entry point against all 35 records of the
 * upstream BLAKE3 KAT corpus (`test/vectors/blake3.ts`). For each
 * record, regenerates the input via `expandBlake3Input(inputLen)`
 * (byte i = i mod 251), runs `hash()` for a 32-byte output, and asserts
 * the bytes match the first 64 hex characters of the record's
 * `hashHex` (the default-length BLAKE3 hash). XOF output past 32 bytes
 * is not exercised here.
 *
 * Expected values are sourced from `test/vectors/blake3.ts` (which
 * sources from the upstream JSON); per AGENTS.md §Ground Rules #2, do
 * not modify the vectors to make a failing test pass.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';
import { blake3Vectors, expandBlake3Input } from '../../vectors/blake3.js';

interface Blake3Exports {
	memory:                  WebAssembly.Memory;
	hash:                    (
		inputOff: number,
		inputLen: number,
		outOff:   number,
		outLen:   number,
	) => void;
	wipeBuffers:             () => void;
	getOutputStagingOffset:  () => number;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../../../build/blake3.wasm');

// Input is staged past the BLAKE3 buffer region (BUFFER_END = 26328,
// which includes the LEVEL_QUEUES region). The largest KAT input is
// 102400 bytes; placing it at 28672 leaves exactly 102400 bytes through
// the 2-page (131072 byte) module memory end.
const INPUT_OFF = 28672;

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

describe('BLAKE3 hash KAT, §2.4 / §2.5 / §2.6', () => {
	// GATE: the `hash()` entry point must reproduce the upstream BLAKE3 KAT
	// corpus across every input length in `blake3Vectors` (35 records,
	// inputLen 0..102400). Exercises the §2.4 chunk machine, §2.5 tree
	// assembly, and §2.5 root finalization at every chunk and CV-stack
	// boundary the design touches.
	for (const v of blake3Vectors) {
		it(`inputLen = ${v.inputLen} → first 32 bytes of hashHex`, () => {
			const mem = new Uint8Array(wasm.memory.buffer);
			wasm.wipeBuffers();

			const input = expandBlake3Input(v.inputLen);
			mem.set(input, INPUT_OFF);

			const outOff = wasm.getOutputStagingOffset();
			mem.fill(0, outOff, outOff + 32);

			wasm.hash(INPUT_OFF, v.inputLen, outOff, 32);

			const digest   = mem.slice(outOff, outOff + 32);
			const expected = v.hashHex.slice(0, 64);
			expect(toHex(digest)).toBe(expected);
		});
	}
});
