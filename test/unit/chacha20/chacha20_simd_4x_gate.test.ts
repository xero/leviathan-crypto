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
 * ChaCha20 4-wide inter-block SIMD — gate test
 *
 * The gate uses the RFC 8439 §2.4.2 key and nonce, matching the scalar
 * implementation's known-answer tests elsewhere in the suite. Here we only
 * assert that the SIMD and scalar implementations produce byte-identical
 * output for the same key/nonce/counter/plaintext for both 256-byte (4 full
 * SIMD blocks) and 320-byte (4 SIMD blocks + 1 scalar tail block) inputs.
 *
 * If either test fails, the SIMD implementation is not bit-for-bit identical
 * to the already-gated scalar reference and must be investigated.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';

interface ChachaSIMDExports {
	memory:                WebAssembly.Memory
	getKeyOffset:          () => number
	getChachaNonceOffset:  () => number
	getChunkPtOffset:      () => number
	getChunkCtOffset:      () => number
	getChunkSize:          () => number
	chachaSetCounter:      (n: number) => void
	chachaLoadKey:         () => void
	chachaEncryptChunk:    (n: number) => number
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

// RFC 8439 §2.4.2 key and nonce (independently verifiable against the spec)
const KEY   = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const NONCE = '000000000000004a00000000';

beforeAll(async () => {
	await init('chacha20');
});

describe('ChaCha20 4-wide SIMD gate — scalar vs chachaEncryptChunk_simd', () => {

	function setup(wasm: ChachaSIMDExports, pt: Uint8Array): void {
		const mem = new Uint8Array(wasm.memory.buffer);
		mem.set(fromHex(KEY),   wasm.getKeyOffset());
		mem.set(fromHex(NONCE), wasm.getChachaNonceOffset());
		wasm.chachaSetCounter(1);
		wasm.chachaLoadKey();
		mem.set(pt, wasm.getChunkPtOffset());
	}

	function readCT(wasm: ChachaSIMDExports, len: number): Uint8Array {
		const ctOff = wasm.getChunkCtOffset();
		return new Uint8Array(wasm.memory.buffer).slice(ctOff, ctOff + len);
	}

	// GATE — 256 bytes: exactly 4 SIMD blocks, no scalar tail
	it('GATE — 256 bytes (4 full blocks): SIMD === scalar', () => {
		const wasm = getWasm();
		const pt   = new Uint8Array(256);  // all-zero plaintext → output is keystream

		// Scalar
		setup(wasm, pt);
		wasm.chachaEncryptChunk(256);
		const scalarCT = readCT(wasm, 256);

		// SIMD
		setup(wasm, pt);
		wasm.chachaEncryptChunk_simd(256);
		const simdCT = readCT(wasm, 256);

		expect(toHex(simdCT)).toBe(toHex(scalarCT));
	});

	// 320 bytes: 4 SIMD blocks + 1 scalar tail block (64 bytes)
	it('320 bytes (4 SIMD + 1 scalar tail): SIMD === scalar', () => {
		const wasm = getWasm();
		const pt   = new Uint8Array(320);

		// Scalar
		setup(wasm, pt);
		wasm.chachaEncryptChunk(320);
		const scalarCT = readCT(wasm, 320);

		// SIMD
		setup(wasm, pt);
		wasm.chachaEncryptChunk_simd(320);
		const simdCT = readCT(wasm, 320);

		expect(toHex(simdCT)).toBe(toHex(scalarCT));
	});

	// 192 bytes: exactly 3 scalar tail blocks, SIMD loop skipped
	it('192 bytes (3 scalar tail blocks only): SIMD === scalar', () => {
		const wasm = getWasm();
		const pt   = new Uint8Array(192);

		setup(wasm, pt);
		wasm.chachaEncryptChunk(192);
		const scalarCT = readCT(wasm, 192);

		setup(wasm, pt);
		wasm.chachaEncryptChunk_simd(192);
		const simdCT = readCT(wasm, 192);

		expect(toHex(simdCT)).toBe(toHex(scalarCT));
	});

	// 512 bytes: 2 SIMD groups, no tail
	it('512 bytes (2 SIMD groups): SIMD === scalar', () => {
		const wasm = getWasm();
		const pt   = new Uint8Array(512);

		setup(wasm, pt);
		wasm.chachaEncryptChunk(512);
		const scalarCT = readCT(wasm, 512);

		setup(wasm, pt);
		wasm.chachaEncryptChunk_simd(512);
		const simdCT = readCT(wasm, 512);

		expect(toHex(simdCT)).toBe(toHex(scalarCT));
	});

	// 337 bytes: 1 SIMD group + partial last block
	it('337 bytes (1 SIMD + partial tail): SIMD === scalar', () => {
		const wasm = getWasm();
		const pt   = new Uint8Array(337).fill(0xab);

		setup(wasm, pt);
		wasm.chachaEncryptChunk(337);
		const scalarCT = readCT(wasm, 337);

		setup(wasm, pt);
		wasm.chachaEncryptChunk_simd(337);
		const simdCT = readCT(wasm, 337);

		expect(toHex(simdCT)).toBe(toHex(scalarCT));
	});
});
