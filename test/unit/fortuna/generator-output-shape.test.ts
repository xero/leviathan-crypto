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
// Output-shape contract for the pluggable Generator wrappers.
//
// Background: an early SerpentGenerator returned `output.subarray(0, n)`
// over a `blocks*16`-sized backing buffer, leaking up to 15 bytes of extra
// keystream to any caller that read `result.buffer`. The fix allocates
// `Uint8Array(n)` and only writes the bytes the caller asked for; the
// unused tail of the last block stays in WASM memory and is wiped before
// return. ChaCha20Generator already had the exact-size shape.
//
// This test locks both generators to: result.length === n,
// result.byteOffset === 0, result.buffer.byteLength === n.
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { SerpentGenerator }  from '../../../src/ts/serpent/index.js';
import { ChaCha20Generator } from '../../../src/ts/chacha20/index.js';
import { serpentWasm }       from '../../../src/ts/serpent/embedded.js';
import { chacha20Wasm }      from '../../../src/ts/chacha20/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, chacha20: chacha20Wasm });
});

// Sizes spanning: empty, sub-block, on-block, just-past-block, mid-block,
// just-before-block, multi-block, large.
const SIZES = [0, 1, 15, 16, 17, 30, 31, 32, 33, 64, 100, 256, 1024];

describe('SerpentGenerator output shape — exact-size buffer, no extra keystream', () => {
	const key = new Uint8Array(32).fill(0xab);
	const counter = new Uint8Array(16).fill(0xcd);

	for (const n of SIZES) {
		it(`n=${n}: result.length === buffer.byteLength === ${n}`, () => {
			const out = SerpentGenerator.generate(key, counter, n);
			expect(out.length).toBe(n);
			expect(out.byteOffset).toBe(0);
			expect((out.buffer as ArrayBuffer).byteLength).toBe(n);
		});
	}
});

describe('ChaCha20Generator output shape — exact-size buffer, no extra keystream', () => {
	const key = new Uint8Array(32).fill(0xab);
	const counter = new Uint8Array(4).fill(0xcd);

	for (const n of SIZES) {
		it(`n=${n}: result.length === buffer.byteLength === ${n}`, () => {
			const out = ChaCha20Generator.generate(key, counter, n);
			expect(out.length).toBe(n);
			expect(out.byteOffset).toBe(0);
			expect((out.buffer as ArrayBuffer).byteLength).toBe(n);
		});
	}
});
