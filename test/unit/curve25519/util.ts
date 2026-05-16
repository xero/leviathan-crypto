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
 * Shared helpers for curve25519 substrate tests. Not a *.test.ts file;
 * vitest will not pick this up directly.
 *
 * Provides deterministic xorshift32 RNG (per AGENTS.md curve25519 test
 * guidance: never use crypto.getRandomValues in unit tests), a WASM
 * loader that instantiates build/curve25519.wasm once per test file,
 * memory I/O helpers, and a scalar-mult-friendly scratch slot allocator.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface Curve25519Exports {
	memory:              WebAssembly.Memory;
	getModuleId:         () => number;
	getMemoryPages:      () => number;
	getFieldTmpOffset:   () => number;
	getPointTmpOffset:   () => number;
	getLadderTmpOffset:  () => number;
	// Field
	feAdd:               (out: number, a: number, b: number) => void;
	feSub:               (out: number, a: number, b: number) => void;
	feNeg:               (out: number, a: number) => void;
	feMul:               (out: number, a: number, b: number) => void;
	feSqr:               (out: number, a: number) => void;
	feInv:               (out: number, a: number) => void;
	feFromBytes:         (out: number, src: number) => void;
	feToBytes:           (out: number, src: number) => void;
	feIsZero:            (a: number) => number;
	feIsNegative:        (a: number) => number;
	feCondSwap:          (a: number, b: number, swap: number) => void;
	feCondNeg:           (out: number, a: number, neg: number) => void;
	// Edwards
	edPointZero:         (out: number) => void;
	edPointBasepoint:    (out: number) => void;
	edPointDouble:       (out: number, a: number) => void;
	edPointAdd:          (out: number, a: number, b: number) => void;
	edPointSub:          (out: number, a: number, b: number) => void;
	edPointEqual:        (a: number, b: number) => number;
	edPointMul:          (out: number, scalar: number, p: number) => void;
	edPointMulBase:      (out: number, scalar: number) => void;
	edPointOnCurve:      (p: number) => number;
	edPointCompress:     (out: number, p: number) => void;
	edPointDecompress:   (out: number, src: number) => number;
	// X25519
	x25519Ladder:        (out: number, scalar: number, u: number) => void;
	// Scalar
	scalarClamp:         (out: number, src: number) => void;
	scalarReduce:        (out: number, src: number) => void;
	scalarReduce64:      (out: number, src: number) => void;
	scalarAdd:           (out: number, a: number, b: number) => void;
	scalarMulAdd:        (out: number, a: number, b: number, c: number) => void;
	scalarIsCanonical:   (s: number) => number;
	// Ed25519 (RFC 8032, TASK-C)
	ed25519Keygen:           (seedOff: number, pkOff: number) => void;
	ed25519Sign:             (seedOff: number, pkOff: number, msgOff: number, msgLen: number, sigOff: number) => void;
	ed25519Verify:           (pkOff: number, msgOff: number, msgLen: number, sigOff: number) => number;
	ed25519SignPrehashed:    (seedOff: number, pkOff: number, digestOff: number, ctxOff: number, ctxLen: number, sigOff: number) => void;
	ed25519VerifyPrehashed:  (pkOff: number, digestOff: number, ctxOff: number, ctxLen: number, sigOff: number) => number;
	wipeBuffers:         () => void;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const WASM_PATH  = resolve(__dirname, '../../../build/curve25519.wasm');

export async function loadCurve25519(): Promise<Curve25519Exports> {
	const bytes = readFileSync(WASM_PATH);
	const { instance } = await WebAssembly.instantiate(bytes, {
		env: { abort: () => {
			throw new Error('curve25519 wasm abort');
		} },
	});
	return instance.exports as unknown as Curve25519Exports;
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
	// 32-byte LE scalar, clamped to [0, 2^255) by masking byte 31's top bit.
	scalar32(): Uint8Array {
		const b = this.bytes(32);
		b[31] &= 0x7F;
		return b;
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

// Region helpers. Tests live in a fixed scratch region that avoids the
// substrate's own buffer use:
//   FIELD_TMP starts at offset 4096 (substrate uses slots 0..15 internally)
//   POINT_TMP starts at offset 4736 (substrate uses slots 0..3 internally)
//   LADDER_TMP starts at offset 5376
//
// Tests should allocate scratch ABOVE these regions to avoid clobbering
// substrate state. The substrate's BUFFER_END is 5936, leaving the rest
// of the 2-page module (5936 .. 131072) free for test scratch.
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
