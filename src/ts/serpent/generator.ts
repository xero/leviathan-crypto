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
// src/ts/serpent/generator.ts
//
// Practical Cryptography (Ferguson & Schneier, 2003) §9.4 — generator
// Serpent-256 ECB counter-mode PRF for Fortuna's generator slot.

import { _assertNotOwned, getInstance } from '../init.js';
import type { Generator } from '../types.js';
import { wipe } from '../utils.js';

/** Minimal subset of serpent WASM exports needed for ECB block generation. @internal */
interface SerpentMin {
	memory:           WebAssembly.Memory;
	getKeyOffset:     () => number;
	getBlockPtOffset: () => number;
	getBlockCtOffset: () => number;
	loadKey:          (n: number) => number;
	encryptBlock:     () => void;
	wipeBuffers:      () => void;
}

/**
 * Serpent-256 ECB counter-mode PRF for Fortuna's generator slot.
 *
 * Each 16-byte counter value is encrypted as a plaintext block to produce
 * one block of pseudorandom output. Practical Cryptography (Ferguson &
 * Schneier, 2003) §9.4.
 *
 * Pass to `Fortuna.create({ generator: SerpentGenerator, ... })` — do not
 * call `generate()` directly outside of Fortuna.
 */
export const SerpentGenerator: Generator = {
	keySize: 32,
	blockSize: 16,
	counterSize: 16,
	wasmModules: ['serpent'],

	/**
	 * Generate `n` pseudorandom bytes by encrypting successive 16-byte counter
	 * values in ECB mode. The counter is incremented as a 128-bit little-endian
	 * integer after each block.
	 * @param key      32-byte Serpent-256 key
	 * @param counter  16-byte initial counter value (little-endian)
	 * @param n        Number of bytes to generate (0 ≤ n ≤ 2^30)
	 * @returns        `n` pseudorandom bytes
	 */
	generate(key: Uint8Array, counter: Uint8Array, n: number): Uint8Array {
		_assertNotOwned('serpent');
		if (key.length !== 32)
			throw new RangeError(`SerpentGenerator: key must be 32 bytes (got ${key.length})`);
		if (counter.length !== 16)
			throw new RangeError(`SerpentGenerator: counter must be 16 bytes (got ${counter.length})`);
		if (!Number.isSafeInteger(n) || n < 0 || n > 2 ** 30)
			throw new RangeError(`SerpentGenerator: n must be a non-negative safe integer <= 2^30 (got ${n})`);

		const x = getInstance('serpent').exports as unknown as SerpentMin;
		const mem = new Uint8Array(x.memory.buffer);
		const c = counter.slice();
		try {
			mem.set(key, x.getKeyOffset());
			if (x.loadKey(32) !== 0) throw new Error('SerpentGenerator: loadKey failed');

			const blocks = Math.ceil(n / 16);
			const output = new Uint8Array(n);
			const ptOff  = x.getBlockPtOffset();
			const ctOff  = x.getBlockCtOffset();

			for (let i = 0; i < blocks; i++) {
				mem.set(c, ptOff);
				x.encryptBlock();
				// Last-block trim: copy only what the caller asked for. The
				// unused tail stays in WASM memory (wiped in finally) instead
				// of landing on the JS heap where callers could reach it via
				// `result.buffer`. Mirrors ChaCha20Generator's exact-size output.
				const offset   = i * 16;
				const writeLen = Math.min(16, n - offset);
				output.set(mem.subarray(ctOff, ctOff + writeLen), offset);
				// Increment c as a 16-byte little-endian integer
				for (let j = 0; j < 16; j++) {
					if (++c[j] !== 0) break;
				}
			}

			return output;
		} finally {
			// Wipe WASM key/key-schedule/last-block scratch and the JS-heap
			// counter copy so secret-derived state does not outlive this call
			// in either the WASM linear memory or the JS heap.
			x.wipeBuffers();
			wipe(c);
		}
	},
};
