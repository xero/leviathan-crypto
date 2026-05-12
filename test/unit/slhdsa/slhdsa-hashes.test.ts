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
// test/unit/slhdsa/slhdsa-hashes.test.ts
//
// SLH-DSA SHAKE substrate gate test, FIPS 202 + FIPS 205 §11.2.
//
// GATE: the embedded SHAKE256 / SHAKE128 implementation in slhdsa.wasm is
// byte-equivalent to the FIPS 202 reference. Expected values are sourced
// from test/vectors/sha3.ts (which is itself sourced from the FIPS 202
// Appendix A test vectors and cross-checked against Node `crypto` and
// Python `hashlib`). The slhdsa SHAKE port is a verbatim copy of the sha3
// permutation, so matching the same FIPS 202 outputs is the correctness
// signal that the slhdsa port carries the spec faithfully.
//
// Per AGENTS.md §1-3: expected outputs come from the spec, NEVER from the
// AsmScript impl. This gate must pass before FIPS 205 §11.2 callers start
// consuming the SHAKE wrappers.

import { describe, test, expect, beforeAll } from 'vitest';
import { slhdsaInit, getSlhDsaExports } from '../../../src/ts/slhdsa/index.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { shake128Vectors, shake256Vectors } from '../../vectors/sha3.js';

let x: ReturnType<typeof getSlhDsaExports>;
let mem: Uint8Array;

function fromHex(hex: string): Uint8Array {
	const b = new Uint8Array(hex.length / 2);
	for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return b;
}

function toHex(b: Uint8Array): string {
	return Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
}

/** Drive slhShake256 with the input bytes in `data`, output `outLen` bytes. */
function slhShake256(data: Uint8Array, outLen: number): Uint8Array {
	const inOff  = x.getInputOffset();
	const outOff = x.getOutOffset();
	mem.set(data, inOff);
	x.slhShake256(outOff, outLen, inOff, data.length);
	return mem.slice(outOff, outOff + outLen);
}

/** Drive raw SHAKE128 from the embedded Keccak permutation. */
function slhShake128(data: Uint8Array, outLen: number): Uint8Array {
	const inOff  = x.getInputOffset();
	const outOff = x.getOutOffset();
	mem.set(data, inOff);
	x.shake128Init();
	x.keccakAbsorbAt(inOff, data.length);
	x.keccakSqueezeTo(outOff, outLen);
	return mem.slice(outOff, outOff + outLen);
}

beforeAll(async () => {
	await slhdsaInit(slhdsaWasm);
	x   = getSlhDsaExports();
	mem = new Uint8Array(x.memory.buffer);
});

// ── SHAKE256 GATE (FIPS 202 §A) ─────────────────────────────────────────────
// SHAKE256 is the workhorse for FIPS 205 §11.2 (F / H / T_ℓ / PRF / PRFmsg /
// Hmsg all dispatch through SHAKE256). The gate must pass before any of
// those wrappers are trusted.

describe('SHAKE256 gate (FIPS 202 §A, sourced from test/vectors/sha3.ts)', () => {
	for (const v of shake256Vectors) {
		test(`GATE: ${v.description}`, () => {
			const got = slhShake256(fromHex(v.input), v.outputLength);
			expect(toHex(got)).toBe(v.expected);
		});
	}
});

// ── SHAKE128 GATE (FIPS 202 §A) ─────────────────────────────────────────────
// SHAKE128 is not directly invoked by FIPS 205 §11.2 hash family, but it
// shares the same Keccak permutation and a similar absorb/squeeze path. A
// passing SHAKE128 gate confirms the permutation is correct independently of
// the rate / DS byte choice for SHAKE256.

describe('SHAKE128 gate (FIPS 202 §A, sourced from test/vectors/sha3.ts)', () => {
	for (const v of shake128Vectors) {
		test(`GATE: ${v.description}`, () => {
			const got = slhShake128(fromHex(v.input), v.outputLength);
			expect(toHex(got)).toBe(v.expected);
		});
	}
});

// ── FIPS 205 §11.2 wrapper smoke check ──────────────────────────────────────
// Confirms the tweakable-hash family wrappers reach SHAKE256 with the
// concatenated input pattern from FIPS 205 §11.2 Table 4. Expected values
// come from re-deriving the same SHAKE256 call via the raw substrate (which
// was just gated against FIPS 202 above), so this is an internal-consistency
// check, NOT a fresh KAT. Real algorithmic gates land with the ACVP corpus
// in slhdsa-acvp.test.ts.

describe('FIPS 205 §11.2 wrappers consume the right bytes', () => {
	test('F(PK.seed, ADRS, M1) = SHAKE256(PK.seed || ADRS || M1, 8n)', () => {
		// Use 128f (n=16) so the buffers are minimal.
		x.slhSetParams128f();
		const n = x.getParamN();
		expect(n).toBe(16);

		// Lay PK.seed, ADRS, M1 in scratch.
		const scratch = x.getScratchOffset() + 2048;
		const pkSeed  = scratch + 0;
		const adrs    = scratch + 32;
		const m1      = scratch + 64;
		const out     = scratch + 96;
		for (let i = 0; i < 16; i++) mem[pkSeed + i] = i + 1;          // pk seed bytes
		for (let i = 0; i < 32; i++) mem[adrs + i]   = 0x20 + i;       // ADRS bytes
		for (let i = 0; i < 16; i++) mem[m1   + i]   = 0xa0 + i;       // M1 (n bytes)

		// Compute via F wrapper.
		x.slhHashF(out, pkSeed, adrs, m1);
		const got = mem.slice(out, out + n);

		// Independently re-derive via slhShake256 over the same 16+32+16 input.
		const concat = new Uint8Array(16 + 32 + 16);
		concat.set(mem.subarray(pkSeed, pkSeed + 16), 0);
		concat.set(mem.subarray(adrs,   adrs   + 32), 16);
		concat.set(mem.subarray(m1,     m1     + 16), 48);
		const want = slhShake256(concat, n);

		expect(toHex(got)).toBe(toHex(want));
	});

	test('Hmsg output length follows m (param-set m, not n)', () => {
		// 256f: n=32, m=49 → Hmsg returns 49 bytes (not 32).
		x.slhSetParams256f();
		expect(x.getParamN()).toBe(32);
		expect(x.getParamM()).toBe(49);

		const scratch = x.getScratchOffset() + 2048;
		const r       = scratch + 0;
		const pkSeed  = scratch + 32;
		const pkRoot  = scratch + 64;
		const m       = scratch + 96;
		const out     = scratch + 192;
		mem.fill(0x01, r,      r      + 32);
		mem.fill(0x02, pkSeed, pkSeed + 32);
		mem.fill(0x03, pkRoot, pkRoot + 32);
		mem.fill(0x04, m,      m      + 64);

		x.slhHmsg(out, r, pkSeed, pkRoot, m, 64);
		const got = mem.slice(out, out + 49);

		// Re-derive: SHAKE256(R || PK.seed || PK.root || M, 8m).
		const concat = new Uint8Array(32 + 32 + 32 + 64);
		concat.set(mem.subarray(r,      r      + 32),  0);
		concat.set(mem.subarray(pkSeed, pkSeed + 32), 32);
		concat.set(mem.subarray(pkRoot, pkRoot + 32), 64);
		concat.set(mem.subarray(m,      m      + 64), 96);
		const want = slhShake256(concat, 49);

		expect(toHex(got)).toBe(toHex(want));
	});

	test('Param selectors set n,m per FIPS 205 §11.1 Table 2', () => {
		// m = ⌈(h-h/d)/8⌉ + ⌈h/(8·d)⌉ + ⌈(k·a)/8⌉ per FIPS 205 §9.
		// 128f: 8 + 1 + 25 = 34; 192f: 8 + 1 + 33 = 42; 256f: 8 + 1 + 40 = 49.
		x.slhSetParams128f();
		expect(x.getParamN()).toBe(16);
		expect(x.getParamM()).toBe(34);

		x.slhSetParams192f();
		expect(x.getParamN()).toBe(24);
		expect(x.getParamM()).toBe(42);

		x.slhSetParams256f();
		expect(x.getParamN()).toBe(32);
		expect(x.getParamM()).toBe(49);
	});
});

// ── wipeBuffers ─────────────────────────────────────────────────────────────

describe('wipeBuffers zeroes OUT/STATE/SCRATCH', () => {
	test('post-wipe, OUT and SCRATCH regions read all zero', () => {
		// Dirty the regions via a SHAKE call.
		slhShake256(new Uint8Array(0), 200);

		x.wipeBuffers();

		const outOff     = x.getOutOffset();
		const stateOff   = x.getStateOffset();
		const scratchOff = x.getScratchOffset();
		// Spot-check the first 256 bytes of each region.
		for (let i = 0; i < 256; i++) {
			expect(mem[outOff + i]).toBe(0);
			expect(mem[stateOff + i]).toBe(0);
			expect(mem[scratchOff + i]).toBe(0);
		}
	});
});
