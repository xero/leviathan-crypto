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
// test/unit/slhdsa/helpers.ts
//
// Shared test harness for the slhdsa unit suite. Loads the slhdsa WASM
// module via the public init() pathway (mirroring slhdsa-acvp.test.ts /
// slhdsa-hashes.test.ts) and exposes the SlhDsaTestExports overlay so
// tests can drive the internal-only _test* WOTS+ / FORS surface.
//
// The SlhDsaTestExports cast is contained inside this helper file. The
// public consumer surface (src/ts/slhdsa/index.ts) does not surface the
// _test* names, so consumer code is shielded from the test fixtures.

import { slhdsaInit, getSlhDsaExports } from '../../../src/ts/slhdsa/index.js';
import { slhdsaWasm }                   from '../../../src/ts/slhdsa/embedded.js';
import type {
	SlhDsaExports, SlhDsaTestExports,
} from '../../../src/ts/slhdsa/types.js';

export type SlhDsaFullExports = SlhDsaExports & SlhDsaTestExports;

let _x: SlhDsaFullExports | null = null;
let _mem: Uint8Array | null      = null;

export async function loadSlhdsa(): Promise<SlhDsaFullExports> {
	if (_x) return _x;
	await slhdsaInit(slhdsaWasm);
	_x   = getSlhDsaExports() as unknown as SlhDsaFullExports;
	_mem = new Uint8Array(_x.memory.buffer);
	return _x;
}

export function exports_(): SlhDsaFullExports {
	if (!_x) throw new Error('slhdsa not loaded; call loadSlhdsa() in beforeAll');
	return _x;
}

export function mem(): Uint8Array {
	if (!_mem) throw new Error('slhdsa not loaded; call loadSlhdsa() in beforeAll');
	return _mem;
}

export function toHex(b: Uint8Array): string {
	return Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
}

export function hex(s: string): Uint8Array {
	const b = new Uint8Array(s.length / 2);
	for (let i = 0; i < b.length; i++) b[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
	return b;
}

/** Equality helper that produces hex diffs on failure (vitest's deep-equal
 *  is fine but the hex form is far easier to eyeball when ADRS, PK.seed or
 *  signature bytes mismatch). */
export function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

/** Deterministic 32-byte seed material from an arbitrary string label.
 *  Not crypto-safe; intended only for fixture seeds inside this test suite
 *  so that boundary / round-trip tests stay reproducible across runs. */
export function fixedSeed(label: string, n: number): Uint8Array {
	const out = new Uint8Array(n);
	let state = 0x811c9dc5;
	for (let i = 0; i < label.length; i++) {
		state = (state ^ label.charCodeAt(i)) >>> 0;
		state = Math.imul(state, 0x01000193) >>> 0;
	}
	for (let i = 0; i < n; i++) {
		state = (state ^ (state << 13)) >>> 0;
		state = (state ^ (state >>> 17)) >>> 0;
		state = (state ^ (state << 5))  >>> 0;
		out[i] = state & 0xff;
	}
	return out;
}

/** Read n bytes from WASM linear memory as a fresh slice. */
export function read(offset: number, len: number): Uint8Array {
	return mem().slice(offset, offset + len);
}

/** Write bytes into WASM linear memory at the given offset. */
export function write(offset: number, data: Uint8Array): void {
	mem().set(data, offset);
}

/** Per-parameter-set descriptor used by the param-set-fan-out tests. */
export interface ParamSetInfo {
	name: 'SLH-DSA-SHAKE-128f' | 'SLH-DSA-SHAKE-192f' | 'SLH-DSA-SHAKE-256f'
	n:    number
	k:    number
	a:    number
	wotsLen: number  // 2·n + 3
	select: () => void
}

/** Param-set descriptors. Resolved without touching the WASM instance so
 *  vitest can iterate this at collection time, before beforeAll runs. The
 *  `select` closure defers the actual WASM call until test execution, when
 *  the module is guaranteed to be loaded. */
export function paramSets(): ParamSetInfo[] {
	return [
		{ name: 'SLH-DSA-SHAKE-128f', n: 16, k: 33, a: 6, wotsLen: 35,
		  select: () => exports_().slhSetParams128f() },
		{ name: 'SLH-DSA-SHAKE-192f', n: 24, k: 33, a: 8, wotsLen: 51,
		  select: () => exports_().slhSetParams192f() },
		{ name: 'SLH-DSA-SHAKE-256f', n: 32, k: 35, a: 9, wotsLen: 67,
		  select: () => exports_().slhSetParams256f() },
	];
}
