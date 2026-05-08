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
//                           ▀█████▀▀▀
//
// test/unit/mldsa/helpers.ts
//
// WASM test helpers for the mldsa module. Loads build/mldsa.wasm directly
// (no init() system — mldsa WASM has its own memory, not imported).
//
// Mirrors the kyber test harness shape with i32-coefficient polynomials
// (256 × 4 bytes = 1024 B per poly) instead of kyber's i16 (512 B per poly).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

export interface MldsaExports {
	memory: WebAssembly.Memory
	// Buffer layout
	getModuleId:        () => number
	getMemoryPages:     () => number
	getPolySlotBase:    () => number
	getPolySlotSize:    () => number
	getPolySlot0:       () => number
	getPolySlot1:       () => number
	getPolySlot2:       () => number
	getPolySlot3:       () => number
	getPolySlot4:       () => number
	getPolySlot5:       () => number
	getPolySlot6:       () => number
	getPolySlot7:       () => number
	getPolyvecSlotBase: () => number
	getPolyvecSlotSize: () => number
	getPolyvecSlot0:    () => number
	getPolyvecSlot1:    () => number
	getPolyvecSlot2:    () => number
	getPolyvecSlot3:    () => number
	getSeedOffset:      () => number
	getMsgRepOffset:    () => number
	getPkOffset:        () => number
	getSkOffset:        () => number
	getSigOffset:       () => number
	getXofPrfOffset:    () => number
	wipeBuffers:        () => void
	// Reduction
	montgomery_reduce: (a: bigint) => number
	barrett_reduce:    (a: number) => number
	fqmul:             (a: number, b: number) => number
	// NTT
	getZetasOffset: () => number
	getZeta:        (i: number) => number
	BitRev8:        (m: number) => number
	ntt:            (polyOffset: number) => void
	invntt:         (polyOffset: number) => void
	ntt_scalar:     (polyOffset: number) => void
	invntt_scalar:  (polyOffset: number) => void
	// Polynomial arithmetic
	poly_add:                          (rOff: number, aOff: number, bOff: number) => void
	poly_sub:                          (rOff: number, aOff: number, bOff: number) => void
	poly_reduce:                       (polyOff: number) => void
	poly_caddq:                        (polyOff: number) => void
	poly_pointwise_montgomery:         (rOff: number, aOff: number, bOff: number) => void
	poly_add_scalar:                   (rOff: number, aOff: number, bOff: number) => void
	poly_sub_scalar:                   (rOff: number, aOff: number, bOff: number) => void
	poly_reduce_scalar:                (polyOff: number) => void
	poly_caddq_scalar:                 (polyOff: number) => void
	poly_pointwise_montgomery_scalar:  (rOff: number, aOff: number, bOff: number) => void
	poly_freeze:                       (polyOff: number) => void
	poly_chknorm:                      (polyOff: number, bound: number) => number
	// Encoding
	simple_bit_pack:    (rByteOff: number, polyOff: number, bitlen: number) => void
	bit_pack:           (rByteOff: number, polyOff: number, a: number, b: number) => void
	simple_bit_unpack:  (polyOff: number, vByteOff: number, bitlen: number) => void
	bit_unpack:         (polyOff: number, vByteOff: number, a: number, b: number) => void
	hint_bit_pack:      (rByteOff: number, hPvOff: number, k: number, omega: number) => void
	hint_bit_unpack:    (hPvOff: number, vByteOff: number, k: number, omega: number) => number
	// Rounding
	power2round:  (r1Off: number, r0Off: number, aOff: number) => void
	decompose:    (r1Off: number, r0Off: number, aOff: number, gamma2: number) => void
	highbits:     (rOff: number, aOff: number, gamma2: number) => void
	lowbits:      (rOff: number, aOff: number, gamma2: number) => void
	make_hint:    (hOff: number, zOff: number, rOff: number, gamma2: number) => void
	use_hint:     (rOff: number, hOff: number, aOff: number, gamma2: number) => void
	// Polyvec
	polyvec_add:                          (rOff: number, aOff: number, bOff: number, len: number) => void
	polyvec_sub:                          (rOff: number, aOff: number, bOff: number, len: number) => void
	polyvec_reduce:                       (pvOff: number, len: number) => void
	polyvec_caddq:                        (pvOff: number, len: number) => void
	polyvec_freeze:                       (pvOff: number, len: number) => void
	polyvec_ntt:                          (pvOff: number, len: number) => void
	polyvec_invntt:                       (pvOff: number, len: number) => void
	polyvec_pointwise_montgomery:         (rOff: number, aOff: number, bOff: number, len: number) => void
	polyvec_pointwise_acc_montgomery:     (rPolyOff: number, aPvOff: number, bPvOff: number, len: number) => void
	polyvec_matrix_pointwise_montgomery:  (rPvOff: number, matOff: number, vPvOff: number, k: number, l: number) => void
	polyvec_chknorm:                      (pvOff: number, bound: number, len: number) => number
	polyvec_power2round:                  (r1pvOff: number, r0pvOff: number, aPvOff: number, len: number) => void
	polyvec_decompose:                    (r1pvOff: number, r0pvOff: number, aPvOff: number, len: number, gamma2: number) => void
	polyvec_highbits:                     (rPvOff: number, aPvOff: number, len: number, gamma2: number) => void
	polyvec_lowbits:                      (rPvOff: number, aPvOff: number, len: number, gamma2: number) => void
	polyvec_make_hint:                    (hPvOff: number, zPvOff: number, rPvOff: number, len: number, gamma2: number) => number
	polyvec_use_hint:                     (rPvOff: number, hPvOff: number, aPvOff: number, len: number, gamma2: number) => void
	// Sampling
	rej_ntt_poly:      (polyOff: number, ctrStart: number, bufOff: number, bufLen: number) => number
	rej_bounded_poly:  (polyOff: number, ctrStart: number, bufOff: number, bufLen: number, eta: number) => number
	sample_in_ball:    (polyOff: number, signsOff: number, posBytesOff: number, posBytesLen: number, tau: number, startI: number) => number
}

let _instance: MldsaExports | null = null;

export async function loadMldsa(): Promise<MldsaExports> {
	if (_instance) return _instance;
	const wasmPath = join(__dirname, '../../../build/mldsa.wasm');
	const bytes = readFileSync(wasmPath);
	const { instance } = await WebAssembly.instantiate(bytes, {});
	_instance = instance.exports as unknown as MldsaExports;
	return _instance;
}

export function getWasm(): MldsaExports {
	if (!_instance) throw new Error('mldsa WASM not loaded — call loadMldsa() in beforeAll');
	return _instance;
}

/** Read a polynomial (256 × i32) from WASM memory as a number[]. */
export function readPoly(offset: number): number[] {
	const view = new DataView(getWasm().memory.buffer);
	const out: number[] = new Array(256);
	for (let i = 0; i < 256; i++) out[i] = view.getInt32(offset + i * 4, true);
	return out;
}

/** Write a polynomial (256 × i32) into WASM memory. */
export function writePoly(vals: number[], offset: number): void {
	const view = new DataView(getWasm().memory.buffer);
	for (let i = 0; i < 256; i++) view.setInt32(offset + i * 4, vals[i], true);
}

/** Read a contiguous run of bytes from WASM memory. */
export function readBytes(offset: number, len: number): Uint8Array {
	return new Uint8Array(getWasm().memory.buffer, offset, len).slice();
}

/** Write a byte array into WASM memory. */
export function writeBytes(bytes: Uint8Array, offset: number): void {
	new Uint8Array(getWasm().memory.buffer, offset, bytes.length).set(bytes);
}

/** xorshift32 PRNG (deterministic, seed-based). Not crypto-safe. */
export function prng(seed: number): () => number {
	let s = seed >>> 0;
	return () => {
		s = (s ^ (s << 13)) >>> 0;
		s = (s ^ (s >>> 17)) >>> 0;
		s = (s ^ (s << 5))  >>> 0;
		return s;
	};
}

/** Generate a random polynomial with coefficients in [0, q). */
export function randPoly(q: number, rand: () => number): number[] {
	const poly: number[] = new Array(256);
	for (let i = 0; i < 256; i++) poly[i] = rand() % q;
	return poly;
}

/** Reduce x to canonical residue mod q in [0, q). */
export function modQ(x: number, q: number): number {
	const r = x % q;
	return r < 0 ? r + q : r;
}
