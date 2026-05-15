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
 * BLAKE3 keyed_hash KAT, BLAKE3 §2.3 Modes.
 *
 * Drives the WASM `hashKeyed` entry point against all 35 records of the
 * upstream BLAKE3 KAT corpus (`test/vectors/blake3.ts`). For each
 * record, regenerates the input via `expandBlake3Input(inputLen)`, runs
 * `hashKeyed()` with the corpus-pinned `blake3Key` (the 32-byte ASCII
 * key from the upstream JSON) for a 32-byte output, and asserts the
 * bytes match the first 64 hex characters of the record's
 * `keyedHashHex`. XOF output past 32 bytes is a TASK-E deliverable and
 * not exercised here.
 *
 * §2.3: keyed_hash uses the 32 key bytes as the starting CV (loaded as
 * 8 u32 LE words, identical to a memcpy on a LE host), and every
 * compress in the operation carries the KEYED_HASH flag in addition to
 * the structural CHUNK_START / CHUNK_END / PARENT / ROOT bits.
 *
 * Expected values are sourced from `test/vectors/blake3.ts` (which
 * sources from the upstream JSON pinned in TASK-A); per AGENTS.md
 * §Ground Rules #2, do not modify the vectors to make a failing test
 * pass.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';
import { blake3Vectors, blake3Key, expandBlake3Input } from '../../vectors/blake3.js';

interface Blake3Exports {
	memory:                  WebAssembly.Memory;
	hashKeyed:               (
		keyOff:   number,
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

// Same staging layout as blake3-kat.test.ts: key, then input, then
// output, all placed past the BLAKE3 buffer region (BUFFER_END = 26328
// after the TASK-J LEVEL_QUEUES expansion). The largest KAT input is
// 102400 bytes; placing input at 28672 fills the remainder of the
// 2-page (131072 byte) module memory, with the 32-byte key tucked in
// immediately before at 28640.
const KEY_OFF   = 28640;  // 32 bytes
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

describe('BLAKE3 keyed_hash KAT, §2.3', () => {
	// GATE: BLAKE3 keyed_hash empty input matches blake3Vectors[0].keyedHashHex.
	// The empty-input keyed-hash digest reduces to a single compress with
	// CV = blake3Key bytes (LE u32 reinterpretation), block = 64 zero
	// bytes, counter = 0, blockLen = 0, flags = CHUNK_START | CHUNK_END
	// | ROOT | KEYED_HASH. Asserting this first localizes any breakage in
	// the starting-CV or mode-flag plumbing before the larger inputs
	// exercise the chunk / tree assembly.
	for (const v of blake3Vectors) {
		it(`inputLen = ${v.inputLen} → first 32 bytes of keyedHashHex`, () => {
			const mem = new Uint8Array(wasm.memory.buffer);
			wasm.wipeBuffers();

			// blake3Key is the upstream-fixed 32-byte ASCII key; encode as
			// UTF-8 (identical to ASCII bytes for this all-ASCII string).
			const keyBytes = new TextEncoder().encode(blake3Key);
			expect(keyBytes.length).toBe(32);
			mem.set(keyBytes, KEY_OFF);

			const input = expandBlake3Input(v.inputLen);
			mem.set(input, INPUT_OFF);

			const outOff = wasm.getOutputStagingOffset();
			mem.fill(0, outOff, outOff + 32);

			wasm.hashKeyed(KEY_OFF, INPUT_OFF, v.inputLen, outOff, 32);

			const digest   = mem.slice(outOff, outOff + 32);
			const expected = v.keyedHashHex.slice(0, 64);
			expect(toHex(digest)).toBe(expected);
		});
	}
});
