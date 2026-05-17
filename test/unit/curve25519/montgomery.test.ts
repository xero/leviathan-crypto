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
 * X25519 Montgomery ladder invariants (RFC 7748 §5).
 *
 * The gate corpus vector lives in gate.test.ts; this file covers the
 * iter=1 sanity record from `test/vectors/x25519.ts` plus the
 * constant-time cswap property test.
 *
 * The iter=1000 record is part of `test/vectors/x25519.ts` but takes
 * 1000 ladder calls (~30 s in this implementation's slow-path scalar
 * arithmetic), so it is deferred to the e2e / heavier test surface
 * rather than run inside the 5-minute unit budget here.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';
import { x25519Vectors } from '../../vectors/x25519.js';

interface Curve25519Exports {
	memory:               WebAssembly.Memory;
	getFieldTmpOffset:    () => number;
	feCondSwap:           (a: number, b: number, swap: number) => void;
	feFromBytes:          (out: number, src: number) => void;
	feToBytes:            (out: number, src: number) => void;
	scalarClamp:          (out: number, src: number) => void;
	x25519Ladder:         (out: number, scalar: number, u: number) => void;
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

function hexToBytes(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	return out;
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

describe('curve25519 X25519 ladder invariants', () => {
	// RFC 7748 §5 iter=1 record: initial k = u = 0x09 || 31 zero bytes
	// (the encoded u-coordinate of the X25519 basepoint), one X25519 call
	// produces the next k = 0x422c... per the corpus.
	it('iter=1 (RFC 7748 §5)', () => {
		const vec = x25519Vectors.find(v => v.kind === 'iterated' && v.iter === 1);
		expect(vec).toBeDefined();
		if (vec === undefined || vec.kind !== 'iterated') return;

		const base = wasm.getFieldTmpOffset();
		const rawScalar = base +  0;
		const u         = base + 32;
		const clamped   = base + 64;
		const out       = base + 96;

		// RFC 7748 §5: initial k = u = 0x09 || 31 zero bytes. The X25519
		// spec function clamps internally; my substrate ladder requires
		// pre-clamped input, so clamp here to match the §5 contract.
		mem.fill(0, rawScalar, rawScalar + 32);
		mem[rawScalar] = 0x09;
		mem.fill(0, u, u + 32);
		mem[u] = 0x09;
		wasm.scalarClamp(clamped, rawScalar);

		wasm.x25519Ladder(out, clamped, u);
		const result = new Uint8Array(wasm.memory.buffer, out, 32).slice();
		expect(bytesToHex(result)).toBe(vec.kHex);
	});

	it('cswap on field elements with swap=0 preserves both', () => {
		const base = wasm.getFieldTmpOffset();
		const aBytes = base, bBytes = base + 32;
		const aFe = base + 64, bFe = base + 64 + 40;
		hexToBytes('1122334455667788aabbccddeeff00112233445566778899aabbccddeeff0011').forEach((v, i) => mem[aBytes + i] = v);
		hexToBytes('ffeeddccbbaa998877665544332211009988776655443322110099887766554403').forEach((v, i) => mem[bBytes + i] = v);
		wasm.feFromBytes(aFe, aBytes);
		wasm.feFromBytes(bFe, bBytes);

		// Snapshot a, b limbs before
		const aBefore = new Uint8Array(wasm.memory.buffer, aFe, 40).slice();
		const bBefore = new Uint8Array(wasm.memory.buffer, bFe, 40).slice();

		wasm.feCondSwap(aFe, bFe, 0);
		const aAfter = new Uint8Array(wasm.memory.buffer, aFe, 40).slice();
		const bAfter = new Uint8Array(wasm.memory.buffer, bFe, 40).slice();
		expect(Array.from(aAfter)).toEqual(Array.from(aBefore));
		expect(Array.from(bAfter)).toEqual(Array.from(bBefore));
	});
});
