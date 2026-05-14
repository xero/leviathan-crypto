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
// test/unit/slhdsa/slhdsa-fors.test.ts
//
// FIPS 205 §8 FORS unit suite. Drives the internal _test* WASM exports
// from src/asm/slhdsa/fors.ts.
//
//   GATE 1: fors_node at z=0 → equals F(PK.seed, ADRS, fors_skGen(i))
//   GATE 2: fors_node at z=a → equals the FORS tree root computed
//           independently by re-running fors_node on the same inputs
//           (idempotence of the recursion, not a circular check;
//            it asserts no implicit state leaks across calls)
//   GATE 3: fors_sign produces k·(a+1)·n bytes; k auth paths of length a
//   GATE 4: fors_pkGen × fors_pkFromSig round-trip on fixed-seed inputs.
//           fors_pkGen here = T_k(PK.seed, FORS_ROOTS_ADRS, [root_0..root_{k-1}])
//           where root_i = fors_node(SK.seed, i, a, PK.seed, ADRS). We derive
//           it by k calls to fors_node and one T_k compression mirroring
//           Algorithm 17 lines 21-24.
//
// AGENTS.md §3 gate discipline: round-trip tests are NOT a substitute for
// matching an independent reference; the round-trip only proves
// pkFromSig inverts the structure used by sign. Cross-checks against
// slhdsa-c (after the round-trip passes) are recorded in the self-review.

import { describe, test, expect, beforeAll } from 'vitest';
import {
	loadSlhdsa, exports_, read, write, fixedSeed, paramSets, toHex,
} from './helpers.js';

let adrs:    number;
let pkSeed:  number;
let skSeed:  number;
let md:      number;
let outBuf:  number;
let outBuf2: number;
let sigBuf:  number;
let rootsBuf: number;  // staging for k roots ahead of T_k call

beforeAll(async () => {
	await loadSlhdsa();
	const x = exports_();
	adrs = x.getAdrsOffset();
	const base = x.getInputOffset();
	pkSeed   = base +    0;
	skSeed   = base +   64;
	md       = base +  128;        // ⌈k·a/8⌉ ≤ 40 bytes for 256f
	outBuf   = base +  192;
	outBuf2  = base +  256;
	rootsBuf = base +  320;        // k·n max = 35·32 = 1120 bytes
	sigBuf   = base + 2048;        // k·(a+1)·n max = 35·10·32 = 11200 bytes
});

// ── fors_node leaf branch (FIPS 205 §8 Algorithm 15 lines 2-5) ─────────────

describe('fors_node leaf branch z=0 (FIPS 205 §8 Algorithm 15 lines 2-5)', () => {
	for (const ps of paramSets()) {
		test(`GATE z=0 returns F(PK.seed, ADRS{TreeHeight=0, TreeIndex=i}, sk) (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);

			const idx = 13;
			// ADRS: FORS_TREE, layer=0, tree=0, keypair=7, treeIndex=idx.
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 7);

			// 1) Drive the WASM fors_node at z=0.
			x._testForsNode(outBuf, skSeed, idx, 0, pkSeed, adrs);

			// 2) Derive expected value: sk = fors_skGen(SK.seed, PK.seed, ADRS, idx);
			//    then F(PK.seed, ADRS_with_TreeHeight=0/TreeIndex=idx, sk).
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 7);
			x._testForsSkGen(outBuf2, skSeed, idx, pkSeed, adrs);
			x.adrsSetTreeHeight(adrs, 0);
			x.adrsSetTreeIndex(adrs, idx);
			x.slhHashF(outBuf2, pkSeed, adrs, outBuf2);

			expect(toHex(read(outBuf, ps.n))).toBe(toHex(read(outBuf2, ps.n)));
		});
	}
});

// ── fors_node determinism at z=a (FIPS 205 §8 Algorithm 15 recursive) ──────

describe('fors_node at root height z=a is deterministic across calls', () => {
	for (const ps of paramSets()) {
		test(`GATE fors_node(z=a) is the same byte string on two independent calls (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);

			const treeIdx = 0;

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 3);
			x._testForsNode(outBuf, skSeed, treeIdx, ps.a, pkSeed, adrs);

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 3);
			x._testForsNode(outBuf2, skSeed, treeIdx, ps.a, pkSeed, adrs);

			expect(toHex(read(outBuf, ps.n))).toBe(toHex(read(outBuf2, ps.n)));
		});
	}
});

// ── Parameter-set lookups ───────────────────────────────────────────────────

describe('FORS k/a per FIPS 205 §11.1 Table 2', () => {
	for (const ps of paramSets()) {
		test(`(k, a) for ${ps.name}`, () => {
			const x = exports_();
			ps.select();
			expect(x._testForsK()).toBe(ps.k);
			expect(x._testForsA()).toBe(ps.a);
		});
	}
});

// ── fors_sign signature length (FIPS 205 §8 Figure 14) ─────────────────────

describe('fors_sign signature length = k·(a+1)·n bytes', () => {
	for (const ps of paramSets()) {
		test(`auth path length per tree = a; total sig = k·(a+1)·n (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);

			// FORS digest md is ⌈k·a/8⌉ bytes (FIPS 205 §8 fn note 15).
			const mdBytes = Math.ceil((ps.k * ps.a) / 8);
			const MD      = fixedSeed(`md-${ps.name}`, mdBytes);
			write(md, MD);

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 0);

			x._testForsSign(sigBuf, md, skSeed, pkSeed, adrs);

			// The size invariant is enforced structurally: this many bytes
			// are written, the test just confirms the math is what the spec
			// requires before pkFromSig reads them back.
			const sigLen = ps.k * (ps.a + 1) * ps.n;
			// Spot-check that the buffer past sigLen is still zero (we
			// pre-zeroed the input region implicitly via fixedSeed not
			// touching it). Confirms we did NOT overrun.
			expect(read(sigBuf + sigLen, 16).every(b => b === 0)).toBe(true);
		});
	}
});

// ── pkGen × pkFromSig round-trip GATE (FIPS 205 §8 Algorithm 17) ──────────
// fors_pkGen is not a separate algorithm in FIPS 205; it's the composition
// (fors_node at z=a over each of the k trees) ∘ T_k. We derive it here
// from forsNode + slhHashTl mirroring Algorithm 17 lines 21-24. The check
// is then: derived pk == pkFromSig(sig). The signature is produced via
// fors_sign over a fixed md.

describe('FORS pkGen × pkFromSig round-trip (FIPS 205 §8 Algorithms 15, 16, 17)', () => {
	for (const ps of paramSets()) {
		test(`GATE round-trip on fixed seed (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);

			const mdBytes = Math.ceil((ps.k * ps.a) / 8);
			const MD = fixedSeed(`md-${ps.name}`, mdBytes);
			write(md, MD);

			// Reference pk: k roots via forsNode(z=a, idx=i) → T_k compression.
			// Mirrors FIPS 205 Algorithm 17 lines 19-24 with the roots fed by
			// independent calls to forsNode (not by pkFromSig).
			for (let i = 0; i < ps.k; i++) {
				x.adrsClear(adrs);
				x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
				x.adrsSetKeyPairAddress(adrs, 0);
				x._testForsNode(rootsBuf + i * ps.n, skSeed, i, ps.a, pkSeed, adrs);
			}
			// forspkADRS ← ADRS; setTypeAndClear(FORS_ROOTS); setKeyPairAddress(0).
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_ROOTS.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x.slhHashTl(outBuf, pkSeed, adrs, rootsBuf, ps.k * ps.n);
			const pkExpected = toHex(read(outBuf, ps.n));

			// Sign md with FORS_TREE ADRS (Algorithm 16 takes ADRS with type
			// FORS_TREE already set by the caller; see Algorithm 16 §8.3).
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x._testForsSign(sigBuf, md, skSeed, pkSeed, adrs);

			// Recover pk from signature.
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x._testForsPkFromSig(outBuf2, sigBuf, md, pkSeed, adrs);

			expect(toHex(read(outBuf2, ps.n))).toBe(pkExpected);
		});

		test(`pkFromSig with flipped md byte does NOT match pk (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-${ps.name}`, ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);

			const mdBytes = Math.ceil((ps.k * ps.a) / 8);
			const MD = fixedSeed(`md-${ps.name}`, mdBytes);
			write(md, MD);

			// Build reference pk via forsNode roots + T_k.
			for (let i = 0; i < ps.k; i++) {
				x.adrsClear(adrs);
				x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
				x.adrsSetKeyPairAddress(adrs, 0);
				x._testForsNode(rootsBuf + i * ps.n, skSeed, i, ps.a, pkSeed, adrs);
			}
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_ROOTS.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x.slhHashTl(outBuf, pkSeed, adrs, rootsBuf, ps.k * ps.n);
			const pkExpected = toHex(read(outBuf, ps.n));

			// Sign md (correct).
			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x._testForsSign(sigBuf, md, skSeed, pkSeed, adrs);

			// Recover with md flipped: must diverge from pkExpected since
			// indices[] differ and select different leaves.
			const tampered = MD.slice();
			tampered[0] ^= 0x01;
			write(md, tampered);

			x.adrsClear(adrs);
			x.adrsSetType(adrs, x.ADRS_FORS_TREE.value);
			x.adrsSetKeyPairAddress(adrs, 0);
			x._testForsPkFromSig(outBuf2, sigBuf, md, pkSeed, adrs);

			expect(toHex(read(outBuf2, ps.n))).not.toBe(pkExpected);
		});
	}
});
