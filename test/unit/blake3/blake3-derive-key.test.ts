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
 * BLAKE3 derive_key KAT, BLAKE3 §2.3 Modes.
 *
 * Drives the WASM `deriveKey` entry point against all 35 records of the
 * upstream BLAKE3 KAT corpus (`test/vectors/blake3.ts`). For each
 * record, regenerates the input via `expandBlake3Input(inputLen)` and
 * feeds it as the key material, with the corpus-pinned
 * `blake3ContextString` (the UTF-8 context string from the upstream
 * JSON) as the context. The first 32 bytes of the derived output are
 * compared against the first 64 hex characters of the record's
 * `deriveKeyHex`. XOF output past 32 bytes is a TASK-E deliverable and
 * not exercised here.
 *
 * §2.3: derive_key is a two-pass construction. Pass 1 hashes the
 * context string with starting CV = IV and DERIVE_KEY_CONTEXT flag on
 * every compress, producing a 32-byte context_chain_value. Pass 2
 * hashes the key material with starting CV = context_chain_value and
 * DERIVE_KEY_MATERIAL flag on every compress, producing the derived
 * output.
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
import { blake3Vectors, blake3ContextString, expandBlake3Input } from '../../vectors/blake3.js';

interface Blake3Exports {
	memory:                  WebAssembly.Memory;
	deriveKey:               (
		contextOff:  number,
		contextLen:  number,
		materialOff: number,
		materialLen: number,
		outOff:      number,
		outLen:      number,
	) => void;
	wipeBuffers:             () => void;
	getOutputStagingOffset:  () => number;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../../../build/blake3.wasm');

// Stage context, material, and output past the BLAKE3 buffer region
// (BUFFER_END = 26328 after the TASK-J LEVEL_QUEUES expansion) inside
// the 2-page (131072 byte) module memory. blake3ContextString is 48
// ASCII bytes; the largest material input is 102400 bytes. Place
// material at 28672 (fills the remainder of the page) and context at
// 28624 (48 bytes before material).
const CONTEXT_OFF  = 28624;
const MATERIAL_OFF = 28672;

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

describe('BLAKE3 derive_key KAT, §2.3', () => {
	// GATE: BLAKE3 derive_key empty material matches blake3Vectors[0].deriveKeyHex.
	// The empty-material case exercises both passes: pass 1 hashes the
	// 48-byte context string with DERIVE_KEY_CONTEXT (multi-block, single
	// chunk per §2.4), pass 2 hashes 0 bytes of material starting from
	// the context_chain_value with DERIVE_KEY_MATERIAL. A pass-1
	// regression (wrong starting CV or wrong mode flag) shows here before
	// the larger inputs exercise the §2.5 tree assembly in pass 2.
	for (const v of blake3Vectors) {
		it(`inputLen = ${v.inputLen} → first 32 bytes of deriveKeyHex`, () => {
			const mem = new Uint8Array(wasm.memory.buffer);
			wasm.wipeBuffers();

			const contextBytes = new TextEncoder().encode(blake3ContextString);
			mem.set(contextBytes, CONTEXT_OFF);

			const material = expandBlake3Input(v.inputLen);
			mem.set(material, MATERIAL_OFF);

			const outOff = wasm.getOutputStagingOffset();
			mem.fill(0, outOff, outOff + 32);

			wasm.deriveKey(
				CONTEXT_OFF, contextBytes.length,
				MATERIAL_OFF, v.inputLen,
				outOff, 32,
			);

			const digest   = mem.slice(outOff, outOff + 32);
			const expected = v.deriveKeyHex.slice(0, 64);
			expect(toHex(digest)).toBe(expected);
		});
	}
});
