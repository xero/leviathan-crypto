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
 * Scalar arithmetic mod L invariants (RFC 8032 §5.1 curve order, RFC
 * 7748 §5 clamp).
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';

interface Curve25519Exports {
	memory:               WebAssembly.Memory;
	getFieldTmpOffset:    () => number;
	scalarClamp:          (out: number, src: number) => void;
	scalarReduce:         (out: number, src: number) => void;
	scalarReduce64:       (out: number, src: number) => void;
	scalarAdd:            (out: number, a: number, b: number) => void;
	scalarMulAdd:         (out: number, a: number, b: number, c: number) => void;
	scalarIsCanonical:    (s: number) => number;
	wipeBuffers:          () => void;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../../../build/curve25519.wasm');

let wasm: Curve25519Exports;
let mem: Uint8Array;

beforeAll(async () => {
	const bytes = readFileSync(WASM_PATH);
	const { instance } = await WebAssembly.instantiate(bytes, {
		env: { abort: () => {
			throw new Error('curve25519 wasm abort');
		} },
	});
	wasm = instance.exports as unknown as Curve25519Exports;
	mem  = new Uint8Array(wasm.memory.buffer);
});

// L per RFC 8032 §5.1, 32-byte LE.
const L_HEX = 'edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010';

function hexToBytes(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	return out;
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function slot(idx: number): number {
	// FIELD_TMP region; each slot here is 64 bytes apart so 32/33-byte
	// scalars don't collide. We use offsets well past those internally
	// used by the WASM scalar functions.
	return wasm.getFieldTmpOffset() + 320 + idx * 64;
}

describe('curve25519 scalar arithmetic invariants', () => {
	it('clamp produces RFC 7748 §5 / RFC 8032 §5.1.5 shape', () => {
		const src = slot(0), out = slot(1);
		// All-ones input to make the clamp effects visible.
		mem.fill(0xFF, src, src + 32);
		wasm.scalarClamp(out, src);
		const b = new Uint8Array(wasm.memory.buffer, out, 32).slice();
		// Low 3 bits of byte 0 must be zero.
		expect(b[0] & 0x07).toBe(0);
		// Bit 7 of byte 31 (= bit 255) must be zero.
		expect(b[31] & 0x80).toBe(0);
		// Bit 6 of byte 31 (= bit 254) must be set.
		expect(b[31] & 0x40).toBe(0x40);
	});

	it('clamp leaves middle bits untouched (only modifies bytes 0 and 31)', () => {
		const src = slot(0), out = slot(1);
		// Pseudo-random pattern.
		for (let i = 0; i < 32; i++) mem[src + i] = ((i * 37) ^ 0xA5) & 0xFF;
		const srcCopy = new Uint8Array(wasm.memory.buffer, src, 32).slice();
		wasm.scalarClamp(out, src);
		const b = new Uint8Array(wasm.memory.buffer, out, 32).slice();
		// Bytes 1..30 unchanged.
		for (let i = 1; i < 31; i++) {
			expect(b[i]).toBe(srcCopy[i]);
		}
		// Byte 0: low 3 bits cleared, rest unchanged.
		expect(b[0]).toBe(srcCopy[0] & 0xF8);
		// Byte 31: bit 7 cleared, bit 6 set, rest unchanged.
		expect(b[31]).toBe((srcCopy[31] & 0x7F) | 0x40);
	});

	it('scalarIsCanonical(L-1) = 1', () => {
		const s = slot(0);
		const lm1 = hexToBytes(L_HEX);
		lm1[0] -= 1;
		mem.set(lm1, s);
		expect(wasm.scalarIsCanonical(s)).toBe(1);
	});

	it('scalarIsCanonical(L) = 0', () => {
		const s = slot(0);
		mem.set(hexToBytes(L_HEX), s);
		expect(wasm.scalarIsCanonical(s)).toBe(0);
	});

	it('scalarIsCanonical(0) = 1', () => {
		const s = slot(0);
		mem.fill(0, s, s + 32);
		expect(wasm.scalarIsCanonical(s)).toBe(1);
	});

	it('reduce of zero is zero', () => {
		const z = slot(0), out = slot(1);
		mem.fill(0, z, z + 32);
		wasm.scalarReduce(out, z);
		const b = new Uint8Array(wasm.memory.buffer, out, 32).slice();
		expect(bytesToHex(b)).toBe('00'.repeat(32));
	});

	it('reduce(L) = 0', () => {
		const s = slot(0), out = slot(1);
		mem.set(hexToBytes(L_HEX), s);
		wasm.scalarReduce(out, s);
		const b = new Uint8Array(wasm.memory.buffer, out, 32).slice();
		expect(bytesToHex(b)).toBe('00'.repeat(32));
	});

	it('reduce64 of zero is zero', () => {
		const z = slot(0), out = slot(2);
		mem.fill(0, z, z + 64);
		wasm.scalarReduce64(out, z);
		const b = new Uint8Array(wasm.memory.buffer, out, 32).slice();
		expect(bytesToHex(b)).toBe('00'.repeat(32));
	});

	it('mulAdd(0, 0, c) = c (after reduction)', () => {
		const a = slot(0), b = slot(1), c = slot(2), out = slot(3);
		mem.fill(0, a, a + 32);
		mem.fill(0, b, b + 32);
		// c is a small value < L so reduction is no-op.
		mem.fill(0, c, c + 32);
		mem[c] = 42;
		wasm.scalarMulAdd(out, a, b, c);
		const v = new Uint8Array(wasm.memory.buffer, out, 32).slice();
		expect(v[0]).toBe(42);
		for (let i = 1; i < 32; i++) expect(v[i]).toBe(0);
	});

	it('mulAdd(a, 1, 0) = a (when a < L)', () => {
		const a = slot(0), b = slot(1), c = slot(2), out = slot(3);
		mem.fill(0, a, a + 32);
		// a = small value < L
		mem[a] = 0x42; mem[a + 1] = 0x07;
		mem.fill(0, b, b + 32);
		mem[b] = 1;
		mem.fill(0, c, c + 32);
		wasm.scalarMulAdd(out, a, b, c);
		const v = new Uint8Array(wasm.memory.buffer, out, 32).slice();
		expect(v[0]).toBe(0x42);
		expect(v[1]).toBe(0x07);
		for (let i = 2; i < 32; i++) expect(v[i]).toBe(0);
	});
});
