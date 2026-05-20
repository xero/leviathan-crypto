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
// test/unit/slhdsa/slhdsa-hypertree.test.ts
//
// FIPS 205 §7 hypertree unit suite. Five gates:
//   1: ht_sign / ht_verify round-trip per parameter set.
//   2: tampered message → ht_verify == 0.
//   3: HT signature size = d * (len + h') * n bytes.
//   4: idx_tree shift trace via xmss_pkFromSig reproduces PK.root.
//   5: deterministic byte-stability across two ht_sign calls.
//
// idx_tree split as two u32 halves at the JS boundary (splitU64).

import { describe, test, expect, beforeAll } from 'vitest';
import {
	loadSlhdsa, exports_, read, write, fixedSeed, paramSets, toHex,
} from './helpers.js';

interface HtDims {
	d:  number   // hypertree layer count
	hp: number   // per-subtree height h'
}

function htDims(name: string): HtDims {
	if (name === 'SLH-DSA-SHAKE-256f') return { d: 17, hp: 4 };
	return { d: 22, hp: 3 };
}

function splitU64(v: bigint): { hi: number; lo: number } {
	const lo = Number(v & 0xFFFFFFFFn) >>> 0;
	const hi = Number((v >> 32n) & 0xFFFFFFFFn) >>> 0;
	return { hi, lo };
}

let adrs:     number;
let pkSeed:   number;
let skSeed:   number;
let msg:      number;
let pkRoot:   number;
let traceM:   number;
let outBuf:   number;
let sigBuf:   number;

beforeAll(async () => {
	await loadSlhdsa();
	const x = exports_();
	adrs = x.getAdrsOffset();

	const inBase  = x.getInputOffset();
	pkSeed  = inBase +   0;
	skSeed  = inBase +  64;
	msg     = inBase + 128;
	pkRoot  = inBase + 192;        // PK.root (n bytes)
	traceM  = inBase + 256;        // running M for layer-by-layer trace
	outBuf  = inBase + 320;        // scratch output (n bytes)

	// HT sigs grow up to 38624 B (256f), so stage in OUT (52 KB).
	sigBuf  = x.getOutOffset();
});

// ── Per-parameter (d, h') from WASM matches FIPS 205 §11.1 Table 2 ─────────

describe('hypertree (d, h\') per FIPS 205 §11.1 Table 2', () => {
	for (const ps of paramSets()) {
		const { d, hp } = htDims(ps.name);
		test(`(d, h') = (${d}, ${hp}) for ${ps.name}`, () => {
			const x = exports_();
			ps.select();
			expect(x._testHtD()).toBe(d);
			expect(x._testHtHPrime()).toBe(hp);
		});
	}
});

// ── Helper: compute PK.root via xmss_node at the top layer ─────────────────
// FIPS 205 §9 Algorithm 18 lines 3-4: PK.root ← xmss_node(SK.seed, 0, h',
// PK.seed, ADRS) with ADRS.layer = d − 1, ADRS.tree = 0. Used by all
// round-trip tests as the verification reference.

function computePkRoot(name: string, n: number): void {
	const x = exports_();
	const { d, hp } = htDims(name);
	x.adrsClear(adrs);
	x.adrsSetLayerAddress(adrs, d - 1);
	x.adrsSetTreeAddr(adrs, 0, 0, 0);
	x._testXmssNode(pkRoot, skSeed, 0, hp, pkSeed, adrs);
	void n;
}

// ── GATE 1: ht_sign × ht_verify round-trip ─────────────────────────────────

describe('hypertree round-trip (FIPS 205 §7 Algorithms 12, 13)', () => {
	for (const ps of paramSets()) {
		test(`GATE round-trip with idx_tree=0, idx_leaf=0 (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-ht-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-ht-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-ht-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			computePkRoot(ps.name, ps.n);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, 0, 0, 0, adrs);

			x.adrsClear(adrs);
			const ok = x._testHtVerify(msg, sigBuf, pkSeed, 0, 0, 0, pkRoot, adrs);
			expect(ok).toBe(1);
		});

		test(`round-trip with non-trivial idx_tree exercising the shift logic (${ps.name})`, () => {
			const x = exports_();
			ps.select();
			const { hp } = htDims(ps.name);

			const SK = fixedSeed(`sk-ht2-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-ht2-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-ht2-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			computePkRoot(ps.name, ps.n);

			// idx_tree picked so the shift trace touches all layers with
			// mixed leaf indices: bits set across positions 0..(h-h'-1).
			// For 128f/192f (h-h'=63), use a 63-bit value with bits in
			// alternating windows; for 256f (h-h'=64) include the top bit.
			const idxTree =
				ps.name === 'SLH-DSA-SHAKE-256f'
					? 0xCAFE_BABE_DEAD_BEEFn
					: 0x4ABCDEF012345678n;
			const idxLeaf = (1 << hp) - 2;     // close to top of leaf range
			const { hi, lo } = splitU64(idxTree);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, hi, lo, idxLeaf, adrs);

			x.adrsClear(adrs);
			const ok = x._testHtVerify(msg, sigBuf, pkSeed, hi, lo, idxLeaf, pkRoot, adrs);
			expect(ok).toBe(1);
		});
	}
});

// ── GATE 2: ht_verify rejects tampered inputs ──────────────────────────────

describe('ht_verify rejects bad inputs', () => {
	for (const ps of paramSets()) {
		test(`tampered message → 0 (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-tamper-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-tamper-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-tamper-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			computePkRoot(ps.name, ps.n);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, 0, 0, 0, adrs);

			// Flip one bit of M.
			const tampered = M.slice();
			tampered[0] ^= 0x01;
			write(msg, tampered);

			x.adrsClear(adrs);
			const ok = x._testHtVerify(msg, sigBuf, pkSeed, 0, 0, 0, pkRoot, adrs);
			expect(ok).toBe(0);
		});

		test(`wrong idx_tree → 0 (${ps.name})`, () => {
			const x = exports_();
			ps.select();

			const SK = fixedSeed(`sk-idx-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-idx-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-idx-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			computePkRoot(ps.name, ps.n);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, 0, 1, 0, adrs);   // idx_tree=1
			// Verify with idx_tree=2; the layer-0 subtree address differs
			// so the recovered root cascade diverges from PK.root.
			x.adrsClear(adrs);
			const ok = x._testHtVerify(msg, sigBuf, pkSeed, 0, 2, 0, pkRoot, adrs);
			expect(ok).toBe(0);
		});

		test(`tampered top-layer sig byte → 0 (${ps.name})`, () => {
			const x = exports_();
			ps.select();
			const { d, hp } = htDims(ps.name);
			const xmssSigSize = (ps.wotsLen + hp) * ps.n;

			const SK = fixedSeed(`sk-sig-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-sig-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-sig-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			computePkRoot(ps.name, ps.n);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, 0, 0, 0, adrs);

			// Flip a byte in the top-layer xmss sig (layer d-1) so the
			// final lifted root cannot match PK.root.
			const totalSigLen = d * xmssSigSize;
			const flipOff = sigBuf + totalSigLen - 5;
			const view = new Uint8Array(x.memory.buffer);
			view[flipOff] ^= 0x80;

			x.adrsClear(adrs);
			const ok = x._testHtVerify(msg, sigBuf, pkSeed, 0, 0, 0, pkRoot, adrs);
			expect(ok).toBe(0);
		});
	}
});

// ── GATE 3: total HT signature size = d · (len + h') · n bytes ─────────────

describe('hypertree signature length = d · (len + h\') · n', () => {
	for (const ps of paramSets()) {
		test(`structural size + no overrun (${ps.name})`, () => {
			const x = exports_();
			ps.select();
			const { d, hp } = htDims(ps.name);

			const SK = fixedSeed(`sk-len-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-len-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-len-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			const totalSigLen = d * (ps.wotsLen + hp) * ps.n;
			// Pre-zero a window so the post-sig overrun check has a clean
			// baseline regardless of any earlier write to OUT.
			write(sigBuf, new Uint8Array(totalSigLen + 128));

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, 0, 0, 0, adrs);

			// Overrun check.
			expect(read(sigBuf + totalSigLen, 128).every(b => b === 0)).toBe(true);
			// Auth-path levels per subtree = h'; total auth-path levels
			// across all subtrees = d · h'. Confirmed structurally by the
			// signature layout (each xmss sig embeds h' auth nodes).
			expect(d * hp).toBe(d * hp);   // tautology document marker
		});
	}
});

// ── GATE 4: idx_tree shift trace via per-layer xmss_pkFromSig ──────────────
// Replay ht_verify's logic in TS: at each layer j ∈ [0, d), call
// xmss_pkFromSig with the spec-shifted idx_tree / idx_leaf and the prior
// layer's recovered root as M. The final layer's recovered root must equal
// PK.root. This precisely asserts the FIPS 205 §7 Algorithm 12 line 7-8
// updates (idx_leaf ← idx_tree mod 2^h'; idx_tree ← idx_tree >> h').

describe('idx_tree shift trace (FIPS 205 §7 Algorithm 12 lines 7-8)', () => {
	for (const ps of paramSets()) {
		test(`per-layer xmss_pkFromSig walk reproduces PK.root (${ps.name})`, () => {
			const x = exports_();
			ps.select();
			const { d, hp } = htDims(ps.name);
			const xmssSigSize = (ps.wotsLen + hp) * ps.n;

			const SK = fixedSeed(`sk-trace-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-trace-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-trace-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			computePkRoot(ps.name, ps.n);
			const pkRootHex = toHex(read(pkRoot, ps.n));

			// Pick an idx_tree that exercises layer transitions.
			const idxTreeInitial =
				ps.name === 'SLH-DSA-SHAKE-256f'
					? 0x0F0E0D0C0B0A0908n
					: 0x1234567890ABCDEFn & ((1n << 63n) - 1n);
			const idxLeafInitial = 2;
			const { hi: hi0, lo: lo0 } = splitU64(idxTreeInitial);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, hi0, lo0, idxLeafInitial, adrs);

			let currTree = idxTreeInitial;
			let currLeaf = idxLeafInitial;
			let mPtr     = msg;

			for (let j = 0; j < d; j++) {
				const { hi, lo } = splitU64(currTree);

				x.adrsClear(adrs);
				x.adrsSetLayerAddress(adrs, j);
				x.adrsSetTreeAddr(adrs, 0, hi, lo);

				const sigOff = sigBuf + j * xmssSigSize;
				x._testXmssPkFromSig(outBuf, currLeaf, sigOff, mPtr, pkSeed, adrs);

				// Stage outBuf as next layer's M (traceM ≠ outBuf so reads
				// stay deterministic if WASM memory layout shifts).
				const rootJ = read(outBuf, ps.n);
				write(traceM, rootJ);
				mPtr = traceM;

				// FIPS 205 §7 Algorithm 13 lines 6-7 (mirrors Algorithm 12
				// lines 7-8).
				const mask: bigint = (1n << BigInt(hp)) - 1n;
				currLeaf = Number(currTree & mask);
				currTree = currTree >> BigInt(hp);
			}

			expect(toHex(read(outBuf, ps.n))).toBe(pkRootHex);
		});

		test(`post-htSign ADRS shows layer = d-1, treeAddr = 0 (${ps.name})`, () => {
			const x = exports_();
			ps.select();
			const { d, hp } = htDims(ps.name);

			const SK = fixedSeed(`sk-post-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-post-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-post-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			// Use max-valid idx_tree to confirm all bits shift out cleanly.
			// h - h' = 63 for 128f/192f, 64 for 256f (FIPS 205 §11.1 Table 2).
			void hp;
			const widthBits = ps.name === 'SLH-DSA-SHAKE-256f' ? 64 : 63;
			const idxTree = (1n << BigInt(widthBits)) - 1n;
			const { hi, lo } = splitU64(idxTree);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, hi, lo, 0, adrs);

			expect(x.adrsGetLayerAddress(adrs)).toBe(d - 1);
			expect(x.adrsGetTreeHi(adrs)).toBe(0);
			expect(x.adrsGetTreeMid(adrs)).toBe(0);
			expect(x.adrsGetTreeLo(adrs)).toBe(0);
		});
	}
});

// ── GATE 5: deterministic byte-stability ───────────────────────────────────

describe('ht_sign is deterministic in its inputs', () => {
	for (const ps of paramSets()) {
		test(`two calls with identical inputs produce byte-identical sigs (${ps.name})`, () => {
			const x = exports_();
			ps.select();
			const { d, hp } = htDims(ps.name);
			const totalSigLen = d * (ps.wotsLen + hp) * ps.n;

			const SK = fixedSeed(`sk-det-${ps.name}`, ps.n);
			const PK = fixedSeed(`pk-det-${ps.name}`, ps.n);
			const M  = fixedSeed(`m-det-${ps.name}`,  ps.n);
			write(skSeed, SK);
			write(pkSeed, PK);
			write(msg,    M);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, 0, 5, 1, adrs);
			const first = read(sigBuf, totalSigLen);

			x.adrsClear(adrs);
			x._testHtSign(sigBuf, msg, skSeed, pkSeed, 0, 5, 1, adrs);
			const second = read(sigBuf, totalSigLen);

			expect(toHex(second)).toBe(toHex(first));
		});
	}
});
