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
// test/unit/slhdsa/slhdsa-wots.test.ts
//
// FIPS 205 §5 WOTS+ unit suite. Drives the internal _test* WASM exports
// from src/asm/slhdsa/wots.ts.
//
//   GATE 1: chain boundary s=0 → returns input unchanged
//   GATE 2: chain boundary s=1 → equals direct F application
//   GATE 3: chain boundary s=w−1=15 reaches end (no overshoot vs s=14+1)
//   GATE 4: wots_pkGen × wots_pkFromSig × wots_sign round-trip on fixed seeds
//   GATE 5: base_2b helper matches the nibble-extraction definition
//
// Per AGENTS.md §1-3, expected values are derived from the spec, NOT from
// the WASM implementation. The boundary expectations are properties of
// FIPS 205 §5 Algorithm 5 (chain is identity at s=0; F-composability at
// s=k+1=k·s=1∘k); the round-trip is invariant from FIPS 205 §5 Algorithms
// 6-8 by construction (Algorithm 8 lines 1-7 mirror Algorithm 7 lines 1-7
// and lines 8-11 invert the chain).

import { describe, test, expect, beforeAll } from 'vitest';
import {
	loadSlhdsa, exports_, mem, read, write,
	fixedSeed, paramSets, toHex,
} from './helpers.js';

let adrs:    number;
let pkSeed:  number;   // scratch slot for PK.seed
let skSeed:  number;   // scratch slot for SK.seed
let msg:     number;   // scratch slot for n-byte message
let xBuf:    number;   // scratch slot for chain input X
let outBuf:  number;   // scratch slot for chain output
let outBuf2: number;   // scratch slot for F-direct comparison
let pkBuf:   number;   // scratch slot for WOTS+ pk
let sigBuf:  number;   // scratch slot for WOTS+ signature (up to 67·32 bytes)
let pkRecov: number;   // scratch slot for recovered pk

beforeAll(async () => {
	await loadSlhdsa();
	const x = exports_();
	adrs = x.getAdrsOffset();
	// Carve scratch buffers out of the upper INPUT staging region. INPUT is
	// 8 KB; the WOTS+ implementation reads/writes STATE+SCRATCH. We park
	// caller-supplied PK.seed / SK.seed / msg / out / sig here so they
	// never alias the working-buffer offsets defined in wots.ts.
	const base = x.getInputOffset();
	pkSeed  = base +    0;        // n ≤ 32
	skSeed  = base +   64;        // n ≤ 32
	msg     = base +  128;        // n ≤ 32
	xBuf    = base +  192;        // n ≤ 32
	outBuf  = base +  256;        // n ≤ 32
	outBuf2 = base +  320;        // n ≤ 32
	pkBuf   = base +  384;        // n ≤ 32
	pkRecov = base +  448;        // n ≤ 32
	sigBuf  = base + 1024;        // len·n ≤ 67·32 = 2144  (fits in 8 KB INPUT)
});

// ── base_2b helper (FIPS 205 §4 Algorithm 4) ───────────────────────────────
// Independent JS derivation: split byte string into 2^b digits, big-endian
// across input bytes, MSB-first within each byte. Compares to the WASM
// helper for fixed inputs that span lg_w = 4 (WOTS+) and a ∈ {6, 8, 9}
// (FORS-side digit widths shared with WOTS+ via the same algorithm).

function jsBase2b(X: Uint8Array, b: number, outLen: number): Uint8Array {
	const out = new Uint8Array(outLen);
	let inIdx = 0, bits = 0, total = 0;
	const mask = (1 << b) - 1;
	for (let o = 0; o < outLen; o++) {
		while (bits < b) {
			total = ((total << 8) >>> 0) | X[inIdx++];
			bits += 8;
		}
		bits -= b;
		out[o] = (total >>> bits) & mask;
	}
	return out;
}

describe('base_2b helper (FIPS 205 §4 Algorithm 4)', () => {
	test('lg_w=4 nibble unpack of a 16-byte buffer matches independent JS impl', () => {
		const x = exports_();
		const X = new Uint8Array([
			0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
			0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21,
		]);
		const expected = jsBase2b(X, 4, 32);
		expect(Array.from(expected.slice(0, 8))).toEqual([
			0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
		]);

		const inOff  = x.getInputOffset() + 4096;
		const outOff = x.getInputOffset() + 4096 + 64;
		write(inOff, X);
		x._testBase2b(outOff, inOff, 4, 32);

		const got = read(outOff, 32);
		expect(Array.from(got)).toEqual(Array.from(expected));
	});

	test('b=6 (FORS-128f digit width) packs 16 bytes into 21 digits', () => {
		const x = exports_();
		const X = new Uint8Array(16);
		for (let i = 0; i < 16; i++) X[i] = (i * 17 + 3) & 0xff;
		const expected = jsBase2b(X, 6, 21);

		const inOff  = x.getInputOffset() + 4096;
		const outOff = x.getInputOffset() + 4096 + 64;
		write(inOff, X);
		x._testBase2b(outOff, inOff, 6, 21);

		const got = read(outOff, 21);
		expect(Array.from(got)).toEqual(Array.from(expected));
	});
});

// ── Chain boundary gates (FIPS 205 §5 Algorithm 5) ─────────────────────────

describe('wotsChain boundaries (FIPS 205 §5 Algorithm 5)', () => {
	for (const ps of paramSets()) {
		test(`GATE s=0 returns X unchanged (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const X = fixedSeed(`chain-s0-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`,     ps.n);
			write(xBuf, X);
			write(pkSeed, PK);

			// Set ADRS to WOTS_HASH type, layer=0, tree=0, keypair=0, chain=7.
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x.adrsSetChainAddress(adrs, 7);

			// s=0, i=0
			x._testWotsChain(outBuf, xBuf, 0, 0, pkSeed, adrs);

			expect(toHex(read(outBuf, ps.n))).toBe(toHex(X));
		});

		test(`GATE s=1 equals one direct F application (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const X = fixedSeed(`chain-s1-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`,      ps.n);
			write(xBuf,   X);
			write(pkSeed, PK);

			// Chain starts at i=5; HashAddress(j=5) is set by the chain
			// before the F call.
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x.adrsSetChainAddress(adrs, 3);

			x._testWotsChain(outBuf, xBuf, 5, 1, pkSeed, adrs);

			// Reset ADRS to match what the chain function would have done at
			// the single iteration (HashAddress = 5), and call F directly.
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x.adrsSetChainAddress(adrs, 3);
			x.adrsSetHashAddress(adrs, 5);
			x.slhHashF(outBuf2, pkSeed, adrs, xBuf);

			expect(toHex(read(outBuf, ps.n))).toBe(toHex(read(outBuf2, ps.n)));
		});

		test(`GATE s=w−1 (=15) composes as chain(0,14) ∘ F at j=14 (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const X  = fixedSeed(`chain-s15-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`,        ps.n);
			write(xBuf,   X);
			write(pkSeed, PK);

			// Run a full chain (s=15) starting at i=0.
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x.adrsSetChainAddress(adrs, 11);
			x._testWotsChain(outBuf, xBuf, 0, 15, pkSeed, adrs);

			// Independently: chain s=14 from i=0 → intermediate at step 14;
			// then F at HashAddress(14) → step 15. Result must match.
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x.adrsSetChainAddress(adrs, 11);
			x._testWotsChain(outBuf2, xBuf, 0, 14, pkSeed, adrs);
			x.adrsSetHashAddress(adrs, 14);
			x.slhHashF(outBuf2, pkSeed, adrs, outBuf2);

			expect(toHex(read(outBuf, ps.n))).toBe(toHex(read(outBuf2, ps.n)));
		});
	}
});

// ── len / len_1 derived constants (FIPS 205 §5 lines 5.1-5.4) ──────────────

describe('WOTS+ derived parameters (FIPS 205 §5)', () => {
	for (const ps of paramSets()) {
		test(`len_1 = 2·n and len = 2·n + 3 for ${ps.name}`, () => {
			const x = exports_();
			ps.select();
			expect(x._testWotsLen1()).toBe(ps.n * 2);
			expect(x._testWotsLen()).toBe(ps.n * 2 + 3);
			expect(x._testWotsLen()).toBe(ps.wotsLen);
		});
	}
});

// ── Round-trip GATE (FIPS 205 §5 Algorithms 6 / 7 / 8) ─────────────────────
// pkGen on (SK.seed, PK.seed, ADRS) produces pk. sign on the same inputs
// produces sig over M. pkFromSig(sig, M, PK.seed, ADRS) must yield the same
// pk byte-for-byte.

describe('WOTS+ round-trip (FIPS 205 §5 Algorithms 6, 7, 8)', () => {
	for (const ps of paramSets()) {
		test(`GATE pkGen × sign × pkFromSig round-trip on fixed seed (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`,  ps.n);
			const PK = fixedSeed(`pk-${ps.name}`,  ps.n);
			const M  = fixedSeed(`msg-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			// ADRS encodes WOTS_HASH at layer=2, tree=0, keypair=17.
			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, 2);
			x.adrsSetTreeAddr(adrs, 0, 0, 0);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 17);

			// Expected pk from wots_pkGen.
			x._testWotsPkGen(pkBuf, skSeed, pkSeed, adrs);
			const pkExpected = toHex(read(pkBuf, ps.n));

			// Reset ADRS (sign / pkFromSig assume the same starting ADRS).
			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, 2);
			x.adrsSetTreeAddr(adrs, 0, 0, 0);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 17);

			// Sign M.
			x._testWotsSign(sigBuf, msg, skSeed, pkSeed, adrs);

			// Re-derive pk from the signature.
			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, 2);
			x.adrsSetTreeAddr(adrs, 0, 0, 0);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 17);
			x._testWotsPkFromSig(pkRecov, sigBuf, msg, pkSeed, adrs);

			expect(toHex(read(pkRecov, ps.n))).toBe(pkExpected);
		});

		test(`pkFromSig with a flipped signature byte does NOT match pk (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`,  ps.n);
			const PK = fixedSeed(`pk-${ps.name}`,  ps.n);
			const M  = fixedSeed(`msg-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);

			x._testWotsPkGen(pkBuf, skSeed, pkSeed, adrs);
			const pkExpected = toHex(read(pkBuf, ps.n));

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x._testWotsSign(sigBuf, msg, skSeed, pkSeed, adrs);

			// Flip a single byte in the middle of the signature.
			const sigLen = ps.wotsLen * ps.n;
			const m = mem();
			m[sigBuf + (sigLen >>> 1)] ^= 0x01;

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x._testWotsPkFromSig(pkRecov, sigBuf, msg, pkSeed, adrs);

			expect(toHex(read(pkRecov, ps.n))).not.toBe(pkExpected);
		});

		test(`pkFromSig with a flipped message byte does NOT match pk (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`,  ps.n);
			const PK = fixedSeed(`pk-${ps.name}`,  ps.n);
			const M  = fixedSeed(`msg-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);

			x._testWotsPkGen(pkBuf, skSeed, pkSeed, adrs);
			const pkExpected = toHex(read(pkBuf, ps.n));

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x._testWotsSign(sigBuf, msg, skSeed, pkSeed, adrs);

			// Flip a byte of the message.
			const m = mem();
			m[msg + 0] ^= 0x01;

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x._testWotsPkFromSig(pkRecov, sigBuf, msg, pkSeed, adrs);

			expect(toHex(read(pkRecov, ps.n))).not.toBe(pkExpected);
		});
	}
});
