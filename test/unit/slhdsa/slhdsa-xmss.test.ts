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
// test/unit/slhdsa/slhdsa-xmss.test.ts
//
// FIPS 205 §6 XMSS unit suite. Drives the internal _test* WASM exports from
// src/asm/slhdsa/xmss.ts.
//
//   GATE 1: xmss_node(z=0) byte-identical to wots_pkGen at the same
//           (sk_seed, leaf_index, pk_seed). Falls out of FIPS 205 §6.1
//           Algorithm 9 lines 2-4 by definition.
//   GATE 2: xmss_node(z=h') is deterministic across calls. Two independent
//           recursive computations yield byte-identical roots.
//   GATE 3: xmss_sign × xmss_pkFromSig round-trip recovers the subtree root
//           equal to xmss_node(z=h').
//   GATE 4: signature length = (len + h')·n bytes (structural).
//
// AGENTS.md §3 gate discipline: GATE 1 is a structural identity, not a
// numeric KAT, so it is the right primitive gate for this layer. Numeric
// KAT verification arrives via the ACVP corpus in slhdsa-acvp.test.ts.

import { describe, test, expect, beforeAll } from 'vitest';
import {
	loadSlhdsa, exports_, read, write, fixedSeed, paramSets, toHex,
} from './helpers.js';

let adrs:    number;
let pkSeed:  number;
let skSeed:  number;
let msg:     number;
let outBuf:  number;
let outBuf2: number;
let rootBuf: number;
let sigBuf:  number;

beforeAll(async () => {
	await loadSlhdsa();
	const x = exports_();
	adrs = x.getAdrsOffset();
	const base = x.getInputOffset();
	// XMSS subtree sig max size: (67 + 4)·32 = 2272 bytes (256f). Stage
	// scratch buffers below the sig region. INPUT is 8 KB.
	pkSeed  = base +    0;
	skSeed  = base +   64;
	msg     = base +  128;
	outBuf  = base +  192;
	outBuf2 = base +  256;
	rootBuf = base +  384;
	sigBuf  = base + 1024;        // (len + h')·n ≤ 2272 → ends at +3296
});

// ── Per-parameter-set h' lookup matches FIPS 205 §11.1 Table 2 ─────────────

describe('XMSS h\' per FIPS 205 §11.1 Table 2', () => {
	for (const ps of paramSets()) {
		const expected = ps.name === 'SLH-DSA-SHAKE-256f' ? 4 : 3;
		test(`h' = ${expected} for ${ps.name}`, () => {
			const x = exports_();
			ps.select();
			expect(x._testXmssHPrime()).toBe(expected);
		});
	}
});

// ── GATE 1: xmss_node(z=0) == wots_pkGen at the same leaf index ────────────

describe('xmss_node leaf branch z=0 (FIPS 205 §6.1 Algorithm 9 lines 2-4)', () => {
	for (const ps of paramSets()) {
		test(`GATE z=0 byte-equals wots_pkGen at keypair=i (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);

			const i = 5;

			// 1) WASM xmss_node at z=0. Algorithm 9 lines 2-4 set
			//    ADRS.setTypeAndClear(WOTS_HASH), ADRS.setKeyPairAddress(i),
			//    node ← wots_pkGen(SK.seed, PK.seed, ADRS).
			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, 1);
			x.adrsSetTreeAddr(adrs, 0, 0, 7);
			x._testXmssNode(outBuf, skSeed, i, 0, pkSeed, adrs);

			// 2) Reference: run wots_pkGen directly with ADRS pre-set to
			//    WOTS_HASH/keypair=i, same layer + tree address.
			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, 1);
			x.adrsSetTreeAddr(adrs, 0, 0, 7);
			x.adrsSetType(adrs, x.ADRS_WOTS_HASH.value);
			x.adrsSetKeyPairAddress(adrs, i);
			x._testWotsPkGen(outBuf2, skSeed, pkSeed, adrs);

			expect(toHex(read(outBuf, ps.n))).toBe(toHex(read(outBuf2, ps.n)));
		});
	}
});

// ── GATE 2: xmss_node at subtree root is deterministic ─────────────────────

describe('xmss_node at z=h\' (subtree root) is deterministic across calls', () => {
	for (const ps of paramSets()) {
		const hp = ps.name === 'SLH-DSA-SHAKE-256f' ? 4 : 3;
		test(`GATE z=h' (=${hp}) repeats byte-for-byte (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);

			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, 2);
			x.adrsSetTreeAddr(adrs, 0, 0, 11);
			x._testXmssNode(outBuf, skSeed, 0, hp, pkSeed, adrs);

			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, 2);
			x.adrsSetTreeAddr(adrs, 0, 0, 11);
			x._testXmssNode(outBuf2, skSeed, 0, hp, pkSeed, adrs);

			expect(toHex(read(outBuf, ps.n))).toBe(toHex(read(outBuf2, ps.n)));
		});
	}
});

// ── GATE 3: round-trip xmss_sign × xmss_pkFromSig × xmss_node ─────────────

describe('XMSS round-trip (FIPS 205 §6 Algorithms 9, 10, 11)', () => {
	for (const ps of paramSets()) {
		const hp = ps.name === 'SLH-DSA-SHAKE-256f' ? 4 : 3;

		test(`GATE pk-from-sig recovers xmss_node root (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			const M  = fixedSeed(`msg-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			// Reference root: xmss_node at height h', index 0, in a clean
			// subtree (layer=0, tree=0).
			x.adrsClear(adrs);
			x._testXmssNode(rootBuf, skSeed, 0, hp, pkSeed, adrs);
			const rootExpected = toHex(read(rootBuf, ps.n));

			// Sign M at idx = 0 within the same subtree.
			x.adrsClear(adrs);
			x._testXmssSign(sigBuf, msg, skSeed, 0, pkSeed, adrs);

			// Recover root from signature.
			x.adrsClear(adrs);
			x._testXmssPkFromSig(outBuf, 0, sigBuf, msg, pkSeed, adrs);

			expect(toHex(read(outBuf, ps.n))).toBe(rootExpected);
		});

		test(`round-trip at a non-zero leaf index (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			const M  = fixedSeed(`msg2-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			// Use an idx that exercises both 0 and 1 bits across the depth.
			// 128f/192f: h'=3 → idx ∈ [0,7], pick 5 = 101b.
			// 256f:      h'=4 → idx ∈ [0,15], pick 11 = 1011b.
			const idx = ps.name === 'SLH-DSA-SHAKE-256f' ? 11 : 5;

			// Reference root via xmss_node.
			x.adrsClear(adrs);
			x._testXmssNode(rootBuf, skSeed, 0, hp, pkSeed, adrs);
			const rootExpected = toHex(read(rootBuf, ps.n));

			x.adrsClear(adrs);
			x._testXmssSign(sigBuf, msg, skSeed, idx, pkSeed, adrs);

			x.adrsClear(adrs);
			x._testXmssPkFromSig(outBuf, idx, sigBuf, msg, pkSeed, adrs);

			expect(toHex(read(outBuf, ps.n))).toBe(rootExpected);
		});

		test(`pkFromSig with a tampered M does NOT match root (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			const M  = fixedSeed(`msg3-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			x.adrsClear(adrs);
			x._testXmssNode(rootBuf, skSeed, 0, hp, pkSeed, adrs);
			const rootExpected = toHex(read(rootBuf, ps.n));

			const idx = 2;
			x.adrsClear(adrs);
			x._testXmssSign(sigBuf, msg, skSeed, idx, pkSeed, adrs);

			// Tamper M before verify.
			const tampered = M.slice();
			tampered[0] ^= 0x01;
			write(msg, tampered);

			x.adrsClear(adrs);
			x._testXmssPkFromSig(outBuf, idx, sigBuf, msg, pkSeed, adrs);

			expect(toHex(read(outBuf, ps.n))).not.toBe(rootExpected);
		});
	}
});

// ── GATE 4: auth path length = h' (structural) ─────────────────────────────

describe('XMSS signature layout = sig_WOTS (len·n) || AUTH (h-prime·n)', () => {
	for (const ps of paramSets()) {
		const hp = ps.name === 'SLH-DSA-SHAKE-256f' ? 4 : 3;
		test(`signature size = (len + h')·n; auth path = h'·n bytes (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			const M  = fixedSeed(`msg-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			const sigLen = (ps.wotsLen + hp) * ps.n;
			// Pre-zero a window (sigLen + 64 B) so the overrun check has a
			// clean baseline regardless of what earlier tests wrote at the
			// shared sigBuf offset.
			write(sigBuf, new Uint8Array(sigLen + 64));

			x.adrsClear(adrs);
			x._testXmssSign(sigBuf, msg, skSeed, 0, pkSeed, adrs);

			// Spot-check no overrun: 64 bytes immediately past the declared
			// end remain zero.
			expect(read(sigBuf + sigLen, 64).every(b => b === 0)).toBe(true);
			// The sig itself is not all-zero (sanity that xmss_sign wrote
			// anything at all).
			expect(read(sigBuf, sigLen).some(b => b !== 0)).toBe(true);
			// Confirm h' from the WASM matches the structural expectation.
			expect(x._testXmssHPrime()).toBe(hp);
		});
	}
});
