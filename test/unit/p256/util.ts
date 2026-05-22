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
 * Shared helpers for p256 substrate tests. Not a *.test.ts file;
 * vitest will not pick this up directly.
 *
 * Provides deterministic xorshift32 RNG (per AGENTS.md curve25519 test
 * guidance: never use crypto.getRandomValues in unit tests), a WASM
 * loader that instantiates build/p256.wasm once per test file, memory
 * I/O helpers, and a scratch slot allocator. Mirrors the curve25519
 * test util.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface P256Exports {
	memory:              WebAssembly.Memory;
	getModuleId:         () => number;
	getMemoryPages:      () => number;
	getFieldTmpOffset:   () => number;
	getFieldTmpStride:   () => number;
	getPointTmpOffset:   () => number;
	getPointTmpStride:   () => number;
	getScalarTmpOffset:  () => number;
	getScalarTmpStride:  () => number;
	getMulIntOffset:     () => number;
	// Field
	feAdd:               (out: number, a: number, b: number) => void;
	feSub:               (out: number, a: number, b: number) => void;
	feNeg:               (out: number, a: number) => void;
	feMul:               (out: number, a: number, b: number) => void;
	feSqr:               (out: number, a: number) => void;
	feInv:               (out: number, a: number) => void;
	feSqrt:              (out: number, a: number) => void;
	feFromBytes:         (out: number, src: number) => void;
	feToBytes:           (out: number, src: number) => void;
	feIsZero:            (a: number) => number;
	feIsEqual:           (a: number, b: number) => number;
	feIsOdd:             (a: number) => number;
	feIsCanonical:       (a: number) => number;
	feCondSwap:          (a: number, b: number, swap: number) => void;
	feCondNeg:           (out: number, a: number, neg: number) => void;
	// Scalar (mod n)
	scalarFromBytes:     (out: number, src: number) => void;
	scalarToBytes:       (out: number, src: number) => void;
	scalarIsCanonical:   (s: number) => number;
	scalarIsZero:        (s: number) => number;
	scalarIsHighS:       (s: number) => number;
	scalarReduce:        (out: number, src: number) => void;
	scalarReduce64:      (out: number, src: number) => void;
	scalarAdd:           (out: number, a: number, b: number) => void;
	scalarSub:           (out: number, a: number, b: number) => void;
	scalarMul:           (out: number, a: number, b: number) => void;
	scalarNegate:        (out: number, a: number) => void;
	scalarInv:           (out: number, a: number) => void;
	// Point
	pointZero:           (out: number) => void;
	pointBasepoint:      (out: number) => void;
	pointAdd:            (out: number, p: number, q: number) => void;
	pointDouble:         (out: number, p: number) => void;
	pointSub:            (out: number, p: number, q: number) => void;
	pointNegate:         (out: number, p: number) => void;
	pointEqual:          (p: number, q: number) => number;
	pointOnCurve:        (p: number) => number;
	pointAffinify:       (p: number, outX: number, outY: number) => void;
	pointCompress:       (out: number, p: number) => void;
	pointDecompress:     (out: number, src: number) => number;
	// Scalar multiplication
	pointMul:            (scalar: number, p: number, out: number) => void;
	pointMulBase:        (scalar: number, out: number) => void;
	// RFC 6979
	deriveKDeterministic:(d: number, msgHash: number, kOut: number) => void;
	deriveKHedged:       (d: number, msgHash: number, rnd: number, kOut: number) => void;
	// ECDSA
	ecdsaKeygen:         (seedOff: number, pkOff: number) => void;
	ecdsaSign:           (skOff: number, pkOff: number, msgHashOff: number, rndOff: number, sigOff: number) => void;
	ecdsaSignInternalPk: (skOff: number, msgHashOff: number, rndOff: number, sigOff: number) => void;
	ecdsaVerify:         (pkOff: number, msgHashOff: number, sigOff: number) => number;
	// Misc
	wipeBuffers:         () => void;
	// Test-only field hooks
	_testFeReduce:       (out: number) => void;
	_testGetMulIntOffset:() => number;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../../../build/p256.wasm');

export async function loadP256(): Promise<P256Exports> {
	const bytes = readFileSync(WASM_PATH);
	const { instance } = await WebAssembly.instantiate(bytes, {
		env: { abort: () => {
			throw new Error('p256 wasm abort');
		} },
	});
	return instance.exports as unknown as P256Exports;
}

// xorshift32 deterministic RNG. Not crypto-safe; intended only for
// reproducible-input invariant tests.
export class RNG {
	private state: number;
	constructor(seed: number) {
		this.state = seed | 1;
	}
	next(): number {
		let x = this.state;
		x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
		this.state = x;
		return x >>> 0;
	}
	bytes(n: number): Uint8Array {
		const out = new Uint8Array(n);
		for (let i = 0; i < n; i++) out[i] = this.next() & 0xFF;
		return out;
	}
}

export function hexToBytes(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	return out;
}

export function bytesToHex(b: Uint8Array): string {
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

// Tests live in a fixed scratch region that avoids the substrate's
// own buffer use. The substrate's BUFFER_END is 7054 (per
// src/asm/p256/buffers.ts); tests allocate scratch above 8192 to leave
// a wide safety margin and stay clear of the 3-page module's
// substrate region. 3 pages = 196608 bytes, so test scratch from
// 8192..196608 is ~184 KB of free space.
export const TEST_SCRATCH_BASE = 8192;
export function testSlot(offsetBytes: number): number {
	return TEST_SCRATCH_BASE + offsetBytes;
}

export function readBytes(mem: WebAssembly.Memory, off: number, len: number): Uint8Array {
	return new Uint8Array(mem.buffer, off, len).slice();
}

export function writeBytes(mem: WebAssembly.Memory, off: number, bytes: Uint8Array): void {
	const view = new Uint8Array(mem.buffer);
	view.set(bytes, off);
}

// 32-byte BE representation of (n-1) for tests that need to drive the
// scalar arithmetic at the edge of the canonical range.
//
//   n   = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
//   n-1 = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550
//
// SP 800-186 §3.2.1.3; per AGENTS.md §5 not derived from any planning
// document.
export const N_MINUS_1_HEX =
	'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550';

// n (BE), useful as a non-canonical scalar input for scalarIsCanonical
// negative tests.
export const N_HEX =
	'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';
