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

interface SerpentMin {
	memory:           WebAssembly.Memory;
	getKeyOffset:     () => number;
	getBlockPtOffset: () => number;
	getBlockCtOffset: () => number;
	loadKey:          (n: number) => number;
	encryptBlock:     () => void;
	wipeBuffers:      () => void;
}

export const SerpentGenerator: Generator = {
	keySize: 32,
	blockSize: 16,
	counterSize: 16,
	wasmModules: ['serpent'],

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
			const output = new Uint8Array(blocks * 16);
			const ptOff  = x.getBlockPtOffset();
			const ctOff  = x.getBlockCtOffset();

			for (let i = 0; i < blocks; i++) {
				mem.set(c, ptOff);
				x.encryptBlock();
				output.set(mem.subarray(ctOff, ctOff + 16), i * 16);
				// Increment c as a 16-byte little-endian integer
				for (let j = 0; j < 16; j++) {
					if (++c[j] !== 0) break;
				}
			}

			return output.subarray(0, n);
		} finally {
			// Wipe WASM key/key-schedule/last-block scratch and the JS-heap
			// counter copy so secret-derived state does not outlive this call
			// in either the WASM linear memory or the JS heap.
			x.wipeBuffers();
			wipe(c);
		}
	},
};
