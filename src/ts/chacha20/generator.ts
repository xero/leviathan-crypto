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
// src/ts/chacha20/generator.ts
//
// RFC 8439 §2.3 — ChaCha20 block function as PRF
// ChaCha20 counter-mode PRF for Fortuna's generator slot.
//
// Counter is treated as a 32-bit LE integer. Fortuna's 4-byte genCnt provides
// 2^32 blocks × 64 bytes = 256 GiB of output between reseeds.

import { _assertNotOwned, getInstance } from '../init.js';
import type { Generator } from '../types.js';
import type { ChaChaExports } from './types.js';

/**
 * ChaCha20 counter-mode PRF for Fortuna's generator slot.
 *
 * The 32-bit counter is read from `counter` as a little-endian u32. Each call
 * to `generate()` encrypts zero blocks to produce keystream output (RFC 8439 §2.3).
 * The nonce is fixed to zero — Fortuna's counter is the only varying input.
 *
 * Pass to `Fortuna.create({ generator: ChaCha20Generator, ... })` — do not
 * call `generate()` directly outside of Fortuna.
 */
export const ChaCha20Generator: Generator = {
	keySize: 32,
	blockSize: 64,
	counterSize: 4,
	wasmModules: ['chacha20'],

	/**
	 * Generate `n` pseudorandom bytes using ChaCha20 with a zero nonce.
	 * @param key      32-byte ChaCha20 key
	 * @param counter  4-byte counter (little-endian u32)
	 * @param n        Number of bytes to generate (0 ≤ n ≤ 2^30)
	 * @returns        `n` pseudorandom bytes
	 */
	generate(key: Uint8Array, counter: Uint8Array, n: number): Uint8Array {
		_assertNotOwned('chacha20');
		if (key.length !== 32)
			throw new RangeError(`ChaCha20Generator: key must be 32 bytes (got ${key.length})`);
		if (counter.length !== 4)
			throw new RangeError(`ChaCha20Generator: counter must be 4 bytes (got ${counter.length})`);
		if (!Number.isSafeInteger(n) || n < 0 || n > 2 ** 30)
			throw new RangeError(`ChaCha20Generator: n must be a non-negative safe integer <= 2^30 (got ${n})`);

		const x = getInstance('chacha20').exports as unknown as ChaChaExports;
		const c = new DataView(counter.buffer, counter.byteOffset, 4).getUint32(0, true);
		const mem = new Uint8Array(x.memory.buffer);
		try {
			mem.set(key, x.getKeyOffset());
			// Fixed zero nonce — Fortuna's counter is the only varying input
			mem.fill(0, x.getChachaNonceOffset(), x.getChachaNonceOffset() + 12);
			x.chachaSetCounter(c);
			x.chachaLoadKey();

			const output = new Uint8Array(n);
			let remaining = n;
			let outPos = 0;
			const maxChunk = x.getChunkSize();
			const ptOff    = x.getChunkPtOffset();
			const ctOff    = x.getChunkCtOffset();

			while (remaining > 0) {
				const chunkLen = Math.min(remaining, maxChunk);
				mem.fill(0, ptOff, ptOff + chunkLen);
				x.chachaEncryptChunk_simd(chunkLen);
				output.set(mem.subarray(ctOff, ctOff + chunkLen), outPos);
				outPos    += chunkLen;
				remaining -= chunkLen;
			}

			return output;
		} finally {
			// Wipe the WASM key/state/keystream scratch so secret-derived bytes
			// do not outlive this call in the shared chacha20 linear memory.
			x.wipeBuffers();
		}
	},
};
