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
 * ChaCha20 SIMD cross-check — chachaEncryptChunk_simd vs RFC 8439 vectors
 *
 * Exercises the 4-wide inter-block SIMD path with the RFC 8439 §2.4.2
 * encryption vector (114 bytes, scalar tail only) and a size sweep covering
 * both SIMD inner-loop and tail combinations.
 *
 * Source: RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols", May 2018
 * URL: https://www.rfc-editor.org/rfc/rfc8439
 * Sections: §2.4.2 (encryption test vector)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { chacha20EncryptionVectors } from '../../vectors/chacha20.js';

interface ChachaSIMDExports {
	memory:                  WebAssembly.Memory
	getKeyOffset:            () => number
	getChachaNonceOffset:    () => number
	getChunkPtOffset:        () => number
	getChunkCtOffset:        () => number
	getChunkSize:            () => number
	chachaSetCounter:        (n: number) => void
	chachaLoadKey:           () => void
	chachaEncryptChunk:      (n: number) => number
	chachaEncryptChunk_simd: (n: number) => number
}

function getWasm(): ChachaSIMDExports {
	return getInstance('chacha20').exports as unknown as ChachaSIMDExports;
}

function fromHex(h: string): Uint8Array {
	return Uint8Array.from(h.match(/.{2}/g)!.map(b => parseInt(b, 16)));
}
function toHex(b: Uint8Array): string {
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

beforeAll(async () => {
	await init('chacha20');
});

describe('ChaCha20 SIMD cross-check — RFC vectors via chachaEncryptChunk_simd', () => {

	// RFC 8439 §2.4.2: 114-byte plaintext, counter=1. Fits entirely in scalar
	// tail since 114 < 256. Confirms tail path alone is correct.
	it('RFC 8439 §2.4.2 — 114 bytes (scalar tail only)', () => {
		const v   = chacha20EncryptionVectors[0];
		const wasm = getWasm();
		const mem  = new Uint8Array(wasm.memory.buffer);
		const pt   = new TextEncoder().encode(v.ptText!);

		mem.set(fromHex(v.key),   wasm.getKeyOffset());
		mem.set(fromHex(v.nonce), wasm.getChachaNonceOffset());
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		mem.set(pt, wasm.getChunkPtOffset());
		wasm.chachaEncryptChunk_simd(pt.length);

		const ct = new Uint8Array(wasm.memory.buffer).slice(
			wasm.getChunkCtOffset(),
			wasm.getChunkCtOffset() + pt.length,
		);
		expect(toHex(ct)).toBe(v.ct);
	});

	// Size sweep: verify SIMD matches scalar for several input lengths
	// spanning different combinations of SIMD groups and tail blocks.
	const SWEEP_KEY   = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
	const SWEEP_NONCE = '000000090000004a00000000';

	const SWEEP_SIZES = [64, 128, 200, 256, 300, 384, 512, 600, 65536];

	for (const size of SWEEP_SIZES) {
		it(`size sweep — ${size} bytes: SIMD === scalar`, () => {
			const wasm = getWasm();
			const mem  = new Uint8Array(wasm.memory.buffer);
			const pt   = new Uint8Array(size).fill(0x5a);

			const key   = fromHex(SWEEP_KEY);
			const nonce = fromHex(SWEEP_NONCE);

			// Scalar
			mem.set(key,   wasm.getKeyOffset());
			mem.set(nonce, wasm.getChachaNonceOffset());
			wasm.chachaSetCounter(1);
			wasm.chachaLoadKey();
			mem.set(pt, wasm.getChunkPtOffset());
			wasm.chachaEncryptChunk(size);
			const scalarCT = new Uint8Array(wasm.memory.buffer).slice(
				wasm.getChunkCtOffset(),
				wasm.getChunkCtOffset() + size,
			).slice();

			// SIMD
			mem.set(key,   wasm.getKeyOffset());
			mem.set(nonce, wasm.getChachaNonceOffset());
			wasm.chachaSetCounter(1);
			wasm.chachaLoadKey();
			mem.set(pt, wasm.getChunkPtOffset());
			wasm.chachaEncryptChunk_simd(size);
			const simdCT = new Uint8Array(wasm.memory.buffer).slice(
				wasm.getChunkCtOffset(),
				wasm.getChunkCtOffset() + size,
			);

			expect(toHex(simdCT)).toBe(toHex(scalarCT));
		});
	}

	// Round-trip: encrypt with SIMD, decrypt with SIMD
	it('round-trip: 512 bytes encrypt+decrypt via SIMD', () => {
		const wasm  = getWasm();
		const mem   = new Uint8Array(wasm.memory.buffer);
		const key   = fromHex(SWEEP_KEY);
		const nonce = fromHex(SWEEP_NONCE);
		const pt    = crypto.getRandomValues(new Uint8Array(512));

		// Encrypt
		mem.set(key,   wasm.getKeyOffset());
		mem.set(nonce, wasm.getChachaNonceOffset());
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		mem.set(pt, wasm.getChunkPtOffset());
		wasm.chachaEncryptChunk_simd(512);
		const ct = new Uint8Array(wasm.memory.buffer).slice(
			wasm.getChunkCtOffset(),
			wasm.getChunkCtOffset() + 512,
		).slice();

		// Decrypt (ChaCha20 is symmetric — re-encrypt the ciphertext)
		mem.set(key,   wasm.getKeyOffset());
		mem.set(nonce, wasm.getChachaNonceOffset());
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		mem.set(ct, wasm.getChunkPtOffset());
		wasm.chachaEncryptChunk_simd(512);
		const recovered = new Uint8Array(wasm.memory.buffer).slice(
			wasm.getChunkCtOffset(),
			wasm.getChunkCtOffset() + 512,
		);

		expect(toHex(recovered)).toBe(toHex(pt));
	});
});
