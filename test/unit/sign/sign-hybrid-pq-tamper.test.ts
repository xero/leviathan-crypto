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
// test/unit/sign/sign-hybrid-pq-tamper.test.ts
//
// Security-gate tamper suite for the three PQ-only hybrid suites. Covers
// the seven documented attack shapes:
//
//   1. Tamper sig_mldsa  half        → verify false
//   2. Tamper sig_slhdsa half        → verify false
//   3. Swap halves                   → verify false
//   4. Wrong total length, truncated → verify false
//   5. Wrong total length, padded    → verify false
//   6. Wrong pk under correct sig    → verify false (per half + combined)
//   7. Cross-suite forgery           → verify false
//
// Plus a verify-timing spot check that confirms tampering the ML-DSA half
// vs tampering the SLH-DSA half both still run the full verify cycle,
// i.e. the implementation does not short-circuit on the first half's
// boolean outcome. The two means are NOT expected to be equal (SLH-DSA
// verify is hash-tree dominated, ML-DSA verify is NTT dominated), only
// that each tampered case roughly matches the corresponding honest case
// timing for the same hybrid.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm }  from '../../../src/ts/mldsa/embedded.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import { concat } from '../../../src/ts/utils.js';
import {
	MlDsa44SlhDsa128fSuite,
	MlDsa65SlhDsa192fSuite,
	MlDsa87SlhDsa256fSuite,
	MlDsa44Suite,
	Sign,
} from '../../../src/ts/sign/index.js';
import type { StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import { MLDSA44, MLDSA65, MLDSA87 } from '../../../src/ts/mldsa/index.js';
import { SLHDSA128F, SLHDSA192F, SLHDSA256F } from '../../../src/ts/slhdsa/index.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, slhdsa: slhdsaWasm, sha3: sha3Wasm });
});

interface HybridCase {
	name:            string;
	suite:           StreamableSignatureSuite;
	mldsaSigBytes:   number;
	mldsaPkBytes:    number;
	slhdsaSigBytes:  number;
	slhdsaPkBytes:   number;
}

const CASES: HybridCase[] = [
	{
		name: 'MlDsa44SlhDsa128fSuite', suite: MlDsa44SlhDsa128fSuite,
		mldsaSigBytes: MLDSA44.sigBytes,    mldsaPkBytes: MLDSA44.pkBytes,
		slhdsaSigBytes: SLHDSA128F.sigBytes, slhdsaPkBytes: SLHDSA128F.pkBytes,
	},
	{
		name: 'MlDsa65SlhDsa192fSuite', suite: MlDsa65SlhDsa192fSuite,
		mldsaSigBytes: MLDSA65.sigBytes,    mldsaPkBytes: MLDSA65.pkBytes,
		slhdsaSigBytes: SLHDSA192F.sigBytes, slhdsaPkBytes: SLHDSA192F.pkBytes,
	},
	{
		name: 'MlDsa87SlhDsa256fSuite', suite: MlDsa87SlhDsa256fSuite,
		mldsaSigBytes: MLDSA87.sigBytes,    mldsaPkBytes: MLDSA87.pkBytes,
		slhdsaSigBytes: SLHDSA256F.sigBytes, slhdsaPkBytes: SLHDSA256F.pkBytes,
	},
];

const CTX = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
const MSG = new Uint8Array(64).map((_, i) => (i * 13 + 1) & 0xff);

function flipByte(src: Uint8Array, offset: number): Uint8Array {
	const out = new Uint8Array(src);
	out[offset] ^= 0xff;
	return out;
}

describe.each(CASES)('$name tamper suite', (c) => {
	it('tamper sig_mldsa half → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		// Flip a byte squarely inside the ML-DSA half (mid-half so it does
		// not hit a coincidentally-irrelevant trailer).
		const bad = flipByte(sig, Math.floor(c.mldsaSigBytes / 2));
		expect(c.suite.verify(pk, MSG, bad, CTX)).toBe(false);
	});

	it('tamper sig_slhdsa half → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const offset = c.mldsaSigBytes + Math.floor(c.slhdsaSigBytes / 2);
		const bad = flipByte(sig, offset);
		expect(c.suite.verify(pk, MSG, bad, CTX)).toBe(false);
	});

	it('swap halves → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const sigMldsa  = sig.subarray(0, c.mldsaSigBytes);
		const sigSlhdsa = sig.subarray(c.mldsaSigBytes);
		// With swapped halves the total length is unchanged ONLY if the
		// two halves happen to be the same size, which they never are
		// for any of the three hybrids: ML-DSA sigs are 2420 / 3309 /
		// 4627 vs SLH-DSA 17088 / 35664 / 49856. Total length therefore
		// changes too, but the test still drives the public verify
		// surface and asserts false.
		expect(sigMldsa.length).not.toBe(sigSlhdsa.length);
		const swapped = concat(sigSlhdsa, sigMldsa);
		expect(c.suite.verify(pk, MSG, swapped, CTX)).toBe(false);
	});

	it('wrong total length (truncated) → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const truncated = sig.subarray(0, sig.length - 1);
		expect(c.suite.verify(pk, MSG, truncated, CTX)).toBe(false);
	});

	it('wrong total length (padded) → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const padded = concat(sig, new Uint8Array(1));
		expect(c.suite.verify(pk, MSG, padded, CTX)).toBe(false);
	});

	it('wrong pk (full swap) under correct sig → verify false', () => {
		const { sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const other = c.suite.keygen().pk;
		expect(c.suite.verify(other, MSG, sig, CTX)).toBe(false);
	});

	it('wrong pk (mldsa half only) under correct sig → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const other = c.suite.keygen().pk;
		const mixedPk = concat(
			other.subarray(0, c.mldsaPkBytes),
			pk.subarray(c.mldsaPkBytes),
		);
		expect(c.suite.verify(mixedPk, MSG, sig, CTX)).toBe(false);
	});

	it('wrong pk (slhdsa half only) under correct sig → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const other = c.suite.keygen().pk;
		const mixedPk = concat(
			pk.subarray(0, c.mldsaPkBytes),
			other.subarray(c.mldsaPkBytes),
		);
		expect(c.suite.verify(mixedPk, MSG, sig, CTX)).toBe(false);
	});
});

// ── Cross-suite forgery: standalone ML-DSA-44 sig into a 0x30 hybrid sig ──

describe('cross-suite forgery resistance', () => {
	it('MlDsa44Suite sig placed as ML-DSA half of 0x30 hybrid → false', () => {
		// Standalone MlDsa44Suite uses ctxDomain 'mldsa44-envelope-v3'; the
		// hybrid uses 'mldsa44-slhdsa128f-envelope-v3'. The M' fed to
		// ML-DSA therefore differs, so the standalone sig cannot pass as
		// the hybrid's ML-DSA half even when bytes overlap structurally.
		const { sk: standaloneSk } = MlDsa44Suite.keygen();
		const standaloneSig = MlDsa44Suite.sign(standaloneSk, MSG, CTX);

		// Build a "fake hybrid pk": use the hybrid's own keypair so the
		// SLH-DSA half is real, and slot the standalone ML-DSA sig in
		// place of the hybrid's ML-DSA half. The composite is bogus by
		// construction; the test asserts the suite catches it.
		const { pk: hybridPk, sk: hybridSk } = MlDsa44SlhDsa128fSuite.keygen();
		const hybridSig = MlDsa44SlhDsa128fSuite.sign(hybridSk, MSG, CTX);

		// Replace the ML-DSA portion with the standalone-suite sig. Sizes
		// match (both are MLDSA44 sigBytes).
		expect(standaloneSig.length).toBe(MLDSA44.sigBytes);
		const forged = concat(
			standaloneSig,
			hybridSig.subarray(MLDSA44.sigBytes),
		);
		expect(MlDsa44SlhDsa128fSuite.verify(hybridPk, MSG, forged, CTX)).toBe(false);
	});

	it('the standalone sig itself still verifies under its own suite', () => {
		const { pk, sk } = MlDsa44Suite.keygen();
		const blob = Sign.sign(MlDsa44Suite, sk, MSG, CTX);
		const out  = Sign.verify(MlDsa44Suite, pk, blob, CTX);
		expect(out).toEqual(MSG);
	});
});

// ── Verify-timing spot check ────────────────────────────────────────────────
//
// verifyPrehashed must always run BOTH sub-verifies (AGENTS.md
// "Constant-time operations"). The audit-side gate this test enforces:
// tampering the ML-DSA half does NOT measurably shortcut the verify.
//
// A short-circuiting implementation that early-returned on a failed
// ML-DSA half would SKIP the SLH-DSA verify; for SLH-DSA-128f, SLH-DSA
// verify is roughly the majority of the total verify cost, so a
// short-circuit would visibly cut tampered-mldsa to a small fraction of
// honest. Median-based timing with a generous lower bound (>50% of
// honest) is loose enough to absorb scheduler jitter under concurrent
// `bun check` load while still catching real short-circuits, which would
// produce a tampered/honest ratio in the 0.05-0.2 range.
//
// 0x30 (cat-1) is picked so the spot check is fast; the property is the
// same across all three hybrids.

function timeOne(suite: StreamableSignatureSuite, pk: Uint8Array, sig: Uint8Array): number {
	const t0 = performance.now();
	suite.verify(pk, MSG, sig, CTX);
	return performance.now() - t0;
}

describe('verify timing spot check (0x30)', () => {
	it('tampered-mldsa-half does not measurably shortcut the verify', () => {
		const suite = MlDsa44SlhDsa128fSuite;
		const { pk, sk } = suite.keygen();
		const sig = suite.sign(sk, MSG, CTX);
		const badMldsa = flipByte(sig, Math.floor(MLDSA44.sigBytes / 2));

		// Warm up both paths to amortise WASM JIT-tier promotion noise.
		// Both arms must be warmed because some engines tier per call site.
		for (let i = 0; i < 10; i++) {
			timeOne(suite, pk, sig);
			timeOne(suite, pk, badMldsa);
		}

		// Paired interleaved sampling: each (honest, tampered) pair runs
		// back-to-back, so any scheduler / GC jitter that hits one usually
		// hits the other too. Taking the median of per-pair RATIOS cancels
		// the common-mode load shift that sinks the prior sequential design
		// (21 honest, then 21 tampered) under parallel `bun check`, where
		// other concurrent test files can spike CPU between the two batches
		// and pull the medians apart.
		const trials = 21;
		const ratios: number[] = [];
		const honests:   number[] = [];
		const tampereds: number[] = [];
		for (let i = 0; i < trials; i++) {
			const honest   = timeOne(suite, pk, sig);
			const tampered = timeOne(suite, pk, badMldsa);
			honests.push(honest);
			tampereds.push(tampered);
			// Skip floor-bucket pairs where `honest` is below
			// `performance.now()`'s effective resolution; ratios on near-zero
			// divisors are pure noise.
			if (honest > 0.1) ratios.push(tampered / honest);
		}
		ratios.sort((a, b) => a - b);
		const medianRatio = ratios[Math.floor(ratios.length / 2)];

		honests.sort((a, b) => a - b);
		tampereds.sort((a, b) => a - b);
		const medHonest   = honests[Math.floor(honests.length / 2)];
		const medTampered = tampereds[Math.floor(tampereds.length / 2)];
		console.log(`hybrid 0x30 verify: honest=${medHonest.toFixed(2)}ms tampered-mldsa=${medTampered.toFixed(2)}ms paired-ratio-median=${medianRatio.toFixed(2)} (n=${ratios.length})`);

		// Short-circuit on the ML-DSA half failure would skip the SLH-DSA
		// half, dropping the paired ratio to roughly the ML-DSA share of
		// total verify cost (~0.05-0.2 for SLH-DSA-128f-f). Honest pairs
		// run both halves and sit near 1.0. The 0.5 threshold gives a
		// 2.5x-10x margin while remaining robust to common-mode jitter
		// (which the paired design largely cancels).
		expect(medianRatio).toBeGreaterThan(0.5);
		expect(medHonest).toBeGreaterThan(0);
	});
});
