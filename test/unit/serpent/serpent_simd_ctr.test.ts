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
 * SIMD CTR cross-check — encryptChunk_simd must produce byte-identical
 * output to scalar encryptChunk for all 5 existing CTR test vectors.
 *
 * Forces both paths explicitly, independent of hasSIMD() runtime detection.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { CTR_VECTORS } from './ctr_vectors';

interface CtrExports {
	memory:             WebAssembly.Memory
	getKeyOffset:       () => number
	getNonceOffset:     () => number
	getChunkPtOffset:   () => number
	getChunkCtOffset:   () => number
	getChunkSize:       () => number
	loadKey:            (n: number) => number
	resetCounter:       () => void
	encryptChunk:       (n: number) => number
	encryptChunk_simd:  (n: number) => number
}

function getWasm(): CtrExports {
	return getInstance('serpent').exports as unknown as CtrExports;
}

function fromHex(hex: string): Uint8Array {
	return Uint8Array.from(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

beforeAll(async () => {
	await init('serpent');
});

describe('SIMD CTR cross-check — scalar vs encryptChunk_simd', () => {
	for (const { label, key, nonce, pt, ct } of CTR_VECTORS) {
		it(`Case ${label}: SIMD matches scalar`, () => {
			const wasm = getWasm();
			const mem = new Uint8Array(wasm.memory.buffer);
			const ptBytes = fromHex(pt);
			const nonceBytes = fromHex(nonce);
			const keyBytes = fromHex(key);

			// Scalar path
			mem.set(keyBytes, wasm.getKeyOffset());
			wasm.loadKey(keyBytes.length);
			mem.set(nonceBytes, wasm.getNonceOffset());
			wasm.resetCounter();
			mem.set(ptBytes, wasm.getChunkPtOffset());
			wasm.encryptChunk(ptBytes.length);
			const scalarResult = new Uint8Array(wasm.memory.buffer).slice(
				wasm.getChunkCtOffset(),
				wasm.getChunkCtOffset() + ptBytes.length,
			);

			// SIMD path (same key already loaded)
			mem.set(nonceBytes, wasm.getNonceOffset());
			wasm.resetCounter();
			mem.set(ptBytes, wasm.getChunkPtOffset());
			wasm.encryptChunk_simd(ptBytes.length);
			const simdResult = new Uint8Array(wasm.memory.buffer).slice(
				wasm.getChunkCtOffset(),
				wasm.getChunkCtOffset() + ptBytes.length,
			);

			// Both must match scalar result and known vector
			expect(toHex(simdResult), 'SIMD vs scalar').toBe(toHex(scalarResult));
			expect(toHex(simdResult), 'SIMD vs known vector').toBe(ct.toLowerCase());
		});
	}
});
