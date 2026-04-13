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
// test/unit/kyber/helpers.ts
//
// WASM test helpers for the kyber module. Loads build/kyber.wasm directly
// (no init() system — kyber WASM has its own memory, not imported).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface KyberExports {
	memory: WebAssembly.Memory
	// Buffer layout
	getModuleId: () => number
	getMemoryPages: () => number
	getPolySlotBase: () => number
	getPolySlotSize: () => number
	getPolySlot0: () => number
	getPolySlot1: () => number
	getPolySlot2: () => number
	getPolySlot3: () => number
	getPolySlot4: () => number
	getPolySlot5: () => number
	getPolySlot6: () => number
	getPolySlot7: () => number
	getPolySlot8: () => number
	getPolySlot9: () => number
	getPolyvecSlotBase: () => number
	getPolyvecSlotSize: () => number
	getPolyvecSlot0: () => number
	getPolyvecSlot1: () => number
	getPolyvecSlot2: () => number
	getPolyvecSlot3: () => number
	getPolyvecSlot4: () => number
	getPolyvecSlot5: () => number
	getPolyvecSlot6: () => number
	getPolyvecSlot7: () => number
	getSeedOffset: () => number
	getMsgOffset: () => number
	getPkOffset: () => number
	getSkOffset: () => number
	getCtOffset: () => number
	getCtPrimeOffset: () => number
	getXofPrfOffset: () => number
	wipeBuffers: () => void
	// Arithmetic
	montgomery_reduce: (a: number) => number
	barrett_reduce: (a: number) => number
	fqmul: (a: number, b: number) => number
	// NTT
	getZetasOffset: () => number
	getZeta: (i: number) => number
	ntt: (polyOffset: number) => void
	invntt: (polyOffset: number) => void
	ntt_scalar: (polyOffset: number) => void
	invntt_scalar: (polyOffset: number) => void
	basemul: (rOffset: number, aOffset: number, bOffset: number, zetaIdx: number) => void
	// Polynomial
	poly_tobytes: (rOffset: number, polyOffset: number) => void
	poly_frombytes: (polyOffset: number, aOffset: number) => void
	poly_compress: (rOffset: number, polyOffset: number, dv: number) => void
	poly_decompress: (polyOffset: number, aOffset: number, dv: number) => void
	poly_frommsg: (polyOffset: number, msgOffset: number) => void
	poly_tomsg: (msgOffset: number, polyOffset: number) => void
	poly_add: (rOffset: number, aOffset: number, bOffset: number) => void
	poly_sub: (rOffset: number, aOffset: number, bOffset: number) => void
	poly_reduce: (polyOffset: number) => void
	poly_tomont: (polyOffset: number) => void
	poly_ntt: (polyOffset: number) => void
	poly_invntt: (polyOffset: number) => void
	poly_basemul_montgomery: (rOffset: number, aOffset: number, bOffset: number) => void
	poly_getnoise: (polyOffset: number, bufOffset: number, eta: number) => void
	// Polyvec
	polyvec_tobytes: (rOffset: number, pvOffset: number, k: number) => void
	polyvec_frombytes: (pvOffset: number, aOffset: number, k: number) => void
	polyvec_compress: (rOffset: number, pvOffset: number, k: number, du: number) => void
	polyvec_decompress: (pvOffset: number, aOffset: number, k: number, du: number) => void
	polyvec_ntt: (pvOffset: number, k: number) => void
	polyvec_invntt: (pvOffset: number, k: number) => void
	polyvec_reduce: (pvOffset: number, k: number) => void
	polyvec_add: (rOffset: number, aOffset: number, bOffset: number, k: number) => void
	polyvec_basemul_acc_montgomery: (rOffset: number, aOffset: number, bOffset: number, k: number) => void
	polyvec_modulus_check: (pvOffset: number, k: number) => number
	// Sampling
	rej_uniform: (polyOffset: number, ctrStart: number, bufOffset: number, buflen: number) => number
	// Constant-time
	ct_verify: (aOffset: number, bOffset: number, len: number) => number
	ct_cmov: (rOffset: number, xOffset: number, len: number, b: number) => void
}

let _instance: KyberExports | null = null;

export async function loadKyber(): Promise<KyberExports> {
	if (_instance) return _instance;
	const wasmPath = join(__dirname, '../../../build/kyber.wasm');
	const bytes = readFileSync(wasmPath);
	const { instance } = await WebAssembly.instantiate(bytes, {});
	_instance = instance.exports as unknown as KyberExports;
	return _instance;
}

export function getWasm(): KyberExports {
	if (!_instance) throw new Error('kyber WASM not loaded — call loadKyber() in beforeAll');
	return _instance;
}

export const mem = (): Uint8Array =>
	new Uint8Array(getWasm().memory.buffer);

export const writeBytes = (bytes: Uint8Array, offset: number): void =>
	mem().set(bytes, offset);

export const readBytes = (offset: number, length: number): Uint8Array =>
	mem().slice(offset, offset + length);

export const readI16s = (offset: number, count: number): Int16Array =>
	new Int16Array(getWasm().memory.buffer, offset, count);

export const writeI16s = (vals: number[], offset: number): void => {
	const view = new DataView(getWasm().memory.buffer);
	for (let i = 0; i < vals.length; i++) {
		view.setInt16(offset + i * 2, vals[i], true);
	}
};

export const toHex = (bytes: Uint8Array): string =>
	Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

export const fromHex = (hex: string): Uint8Array =>
	Uint8Array.from(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));

/** Read a polynomial (256 × i16) from WASM memory as an Array. */
export function readPoly(offset: number): number[] {
	const view = new DataView(getWasm().memory.buffer);
	const out: number[] = new Array(256);
	for (let i = 0; i < 256; i++) out[i] = view.getInt16(offset + i * 2, true);
	return out;
}

/** Write a polynomial (256 × i16) into WASM memory. */
export function writePoly(vals: number[], offset: number): void {
	const view = new DataView(getWasm().memory.buffer);
	for (let i = 0; i < 256; i++) view.setInt16(offset + i * 2, vals[i], true);
}

/** Write a polyvec (k × 256 × i16) into WASM memory. */
export function writePolyvec(vecs: number[][], offset: number): void {
	for (let i = 0; i < vecs.length; i++) writePoly(vecs[i], offset + i * 512);
}

/** Read a polyvec (k × 256 × i16) from WASM memory. */
export function readPolyvec(offset: number, k: number): number[][] {
	const out: number[][] = [];
	for (let i = 0; i < k; i++) out.push(readPoly(offset + i * 512));
	return out;
}

/** Seeded deterministic pseudo-random integer in [0, max). Not crypto-safe. */
export function prng(seed: number): () => number {
	let s = seed >>> 0;
	return () => {
		s = (s ^ (s << 13)) >>> 0;
		s = (s ^ (s >>> 17)) >>> 0;
		s = (s ^ (s << 5)) >>> 0;
		return s;
	};
}

/** Generate a random polynomial with coefficients in [0, q). */
export function randPoly(q: number, rand: () => number): number[] {
	const poly: number[] = new Array(256);
	for (let i = 0; i < 256; i++) poly[i] = rand() % q;
	return poly;
}

/** Generate a random byte buffer of given length. */
export function randBytes(len: number, rand: () => number): Uint8Array {
	const buf = new Uint8Array(len);
	for (let i = 0; i < len; i++) buf[i] = rand() & 0xFF;
	return buf;
}

/** Sign-extend a JS number from 16-bit two's complement. */
export function i16(x: number): number {
	return (x << 16) >> 16;
}

// ── SHA3 WASM loader ──────────────────────────────────────────────────────────

export interface Sha3Exports {
	memory:            WebAssembly.Memory;
	getInputOffset:    () => number;
	getOutOffset:      () => number;
	getStateOffset:    () => number;
	sha3_224Init:      () => void;
	sha3_256Init:      () => void;
	sha3_384Init:      () => void;
	sha3_512Init:      () => void;
	shake128Init:      () => void;
	shake256Init:      () => void;
	keccakAbsorb:      (len: number) => void;
	sha3_224Final:     () => void;
	sha3_256Final:     () => void;
	sha3_384Final:     () => void;
	sha3_512Final:     () => void;
	shakeFinal:        (outLen: number) => void;
	shakePad:          () => void;
	shakeSqueezeBlock: () => void;
	wipeBuffers:       () => void;
}

let _sha3Instance: Sha3Exports | null = null;

export async function loadSha3(): Promise<Sha3Exports> {
	if (_sha3Instance) return _sha3Instance;
	const wasmPath = join(__dirname, '../../../build/sha3.wasm');
	const bytes = readFileSync(wasmPath);
	const { instance } = await WebAssembly.instantiate(bytes, {});
	_sha3Instance = instance.exports as unknown as Sha3Exports;
	return _sha3Instance;
}

export function getSha3(): Sha3Exports {
	if (!_sha3Instance) throw new Error('sha3 WASM not loaded — call loadSha3() in beforeAll');
	return _sha3Instance;
}
