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
// test/unit/sign/sign-hybrid-classical-tamper.test.ts
//
// Tamper-resistance gate for the four classical+PQ composite hybrid
// suites (composite-sigs §3.2 / §3.3, FIPS 204 §5.2 ctx parameter).
// See docs/signaturesuite.md#hybrid-classicalpq-tamper-coverage.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, utf8ToBytes, concat } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm }   from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }    from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm }    from '../../../src/ts/sha2/embedded.js';
import { ed25519Wasm } from '../../../src/ts/ed25519/embedded.js';
import { p256Wasm }    from '../../../src/ts/ecdsa/embedded.js';
import {
	MlDsa44Suite,
	Ed25519Suite,
	EcdsaP256Suite,
} from '../../../src/ts/sign/index.js';
import type { StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import {
	MlDsa44Ed25519Suite,
	MlDsa65Ed25519Suite,
	MlDsa44EcdsaP256Suite,
	MlDsa65EcdsaP256Suite,
} from '../../../src/ts/sign/suites/hybrid-classical.js';
import { MLDSA44, MLDSA65 } from '../../../src/ts/mldsa/index.js';
import { ecdsaSignatureToDer } from '../../../src/ts/ecdsa/der.js';

beforeAll(async () => {
	_resetForTesting();
	await init({
		mldsa: mldsaWasm,
		sha3: sha3Wasm,
		sha2: sha2Wasm,
		ed25519: ed25519Wasm,
		p256: p256Wasm,
	});
});

type TradFamily = 'ed25519' | 'ecdsa-p256';

interface HybridCase {
	name:           string;
	suite:          StreamableSignatureSuite;
	mldsaSigBytes:  number;
	mldsaPkBytes:   number;
	tradPkBytes:    number;
	tradFamily:     TradFamily;
	// Offset into trad-half guaranteed to land in sig content bytes.
	// Ed25519 raw 64-byte R||S: 32. ECDSA DER (RFC 3279 §2.2.3): 8,
	// past SEQUENCE / INTEGER headers, inside r content.
	tradContentByteOffset: number;
}

const CASES: HybridCase[] = [
	{
		name: 'MlDsa44Ed25519Suite',     suite: MlDsa44Ed25519Suite,
		mldsaSigBytes: MLDSA44.sigBytes, mldsaPkBytes: MLDSA44.pkBytes,
		tradPkBytes: 32,                 tradFamily: 'ed25519',
		tradContentByteOffset: 32,
	},
	{
		name: 'MlDsa65Ed25519Suite',     suite: MlDsa65Ed25519Suite,
		mldsaSigBytes: MLDSA65.sigBytes, mldsaPkBytes: MLDSA65.pkBytes,
		tradPkBytes: 32,                 tradFamily: 'ed25519',
		tradContentByteOffset: 32,
	},
	{
		name: 'MlDsa44EcdsaP256Suite',   suite: MlDsa44EcdsaP256Suite,
		mldsaSigBytes: MLDSA44.sigBytes, mldsaPkBytes: MLDSA44.pkBytes,
		tradPkBytes: 65,                 tradFamily: 'ecdsa-p256',
		tradContentByteOffset: 8,
	},
	{
		name: 'MlDsa65EcdsaP256Suite',   suite: MlDsa65EcdsaP256Suite,
		mldsaSigBytes: MLDSA65.sigBytes, mldsaPkBytes: MLDSA65.pkBytes,
		tradPkBytes: 65,                 tradFamily: 'ecdsa-p256',
		tradContentByteOffset: 8,
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
		// Mid-half offset, avoids structurally inert positions.
		const bad = flipByte(sig, Math.floor(c.mldsaSigBytes / 2));
		expect(c.suite.verify(pk, MSG, bad, CTX)).toBe(false);
	});

	it('tamper sig_trad half → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const offset = c.mldsaSigBytes + c.tradContentByteOffset;
		const bad = flipByte(sig, offset);
		expect(c.suite.verify(pk, MSG, bad, CTX)).toBe(false);
	});

	it('swap halves → verify false', () => {
		const { pk, sk } = c.suite.keygen();
		const sig = c.suite.sign(sk, MSG, CTX);
		const sigMldsa = sig.subarray(0, c.mldsaSigBytes);
		const sigTrad  = sig.subarray(c.mldsaSigBytes);
		// Sizes always differ across all four hybrids; suite.verify still runs
		// and asserts false.
		expect(sigMldsa.length).not.toBe(sigTrad.length);
		const swapped = concat(sigTrad, sigMldsa);
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

	it('wrong pk (trad half only) under correct sig → verify false', () => {
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

// ── Cross-suite forgery resistance ─────────────────────────────────────────

describe('cross-suite forgery resistance', () => {
	// Standalone MlDsa44Suite Label/ctx (FIPS 204 §5.2 Algorithm 2) differs
	// from composite-sigs §3.2 / §6 Label → byte-disjoint sigs.
	it('MlDsa44Suite sig placed as ML-DSA half of 0x20 hybrid → false', () => {
		const standaloneCtx = utf8ToBytes('cross-suite');
		const { sk: standaloneSk } = MlDsa44Suite.keygen();
		const standaloneSig = MlDsa44Suite.sign(standaloneSk, MSG, standaloneCtx);

		// Pair the standalone-ML-DSA-half with the hybrid's real Ed25519
		// half (so the forgery has the correct shape and a plausible Ed25519
		// half; only the ML-DSA half differs from a real hybrid sig).
		const { pk: hybridPk, sk: hybridSk } = MlDsa44Ed25519Suite.keygen();
		const hybridSig = MlDsa44Ed25519Suite.sign(hybridSk, MSG, CTX);

		// MLDSA44 sigBytes are fixed (FIPS 204 §4 Table 1), so a standalone
		// MlDsa44Suite sig and the ML-DSA half of a 0x20 hybrid sig are
		// byte-length-compatible.
		expect(standaloneSig.length).toBe(MLDSA44.sigBytes);
		const forged = concat(
			standaloneSig,
			hybridSig.subarray(MLDSA44.sigBytes),
		);
		expect(MlDsa44Ed25519Suite.verify(hybridPk, MSG, forged, CTX)).toBe(false);
	});

	// Ed25519 64-byte R||S (RFC 8032 §5.1.6) in the DER-shaped trad slot
	// (RFC 3279 §2.2.3) fails ecdsaSignatureFromDer; mldsaOk also false →
	// composite AND-reduction false.
	it('Ed25519Suite sig as trad half of 0x22 → false (DER structural mismatch)', () => {
		const { sk: edSk } = Ed25519Suite.keygen();
		// Ed25519Suite rejects non-empty ctx (the pure mode has no native
		// ctx parameter per RFC 8032 §5.1.6); use empty ctx for the
		// standalone sign and verify the composite with non-empty CTX to
		// show the inputs are unrelated.
		const edSig = Ed25519Suite.sign(edSk, MSG, new Uint8Array(0));
		expect(edSig.length).toBe(64);

		const { pk: hybridPk, sk: hybridSk } = MlDsa44EcdsaP256Suite.keygen();
		const hybridSig = MlDsa44EcdsaP256Suite.sign(hybridSk, MSG, CTX);

		// Use the hybrid's real ML-DSA half so only the trad-slot is
		// forged. The forged trad half is 64 raw Ed25519 bytes where DER
		// expects a SEQUENCE; verify fails.
		const forged = concat(
			hybridSig.subarray(0, MLDSA44.sigBytes),
			edSig,
		);
		expect(MlDsa44EcdsaP256Suite.verify(hybridPk, MSG, forged, CTX)).toBe(false);
	});

	// Standalone ECDSA hashes M directly; composite hashes M' (FIPS 186-5
	// §6.4 ecdsa-with-SHA256 in both). Different inputs → different sigs.
	it('EcdsaP256Suite sig (DER-wrapped) as trad half of 0x22 → false', () => {
		const { sk: ecSk } = EcdsaP256Suite.keygen();
		// EcdsaP256Suite rejects non-empty ctx (single-variant, ECDSA-P256
		// has no native ctx). Sign the user message directly under empty
		// ctx; the composite-vs-standalone divergence is in the M handed
		// to ECDSA's SHA-256 prehash, not in the ctx framing.
		const ecRawSig = EcdsaP256Suite.sign(ecSk, MSG, new Uint8Array(0));
		expect(ecRawSig.length).toBe(64);
		const ecDerSig = ecdsaSignatureToDer(ecRawSig);

		const { pk: hybridPk, sk: hybridSk } = MlDsa44EcdsaP256Suite.keygen();
		const hybridSig = MlDsa44EcdsaP256Suite.sign(hybridSk, MSG, CTX);

		const forged = concat(
			hybridSig.subarray(0, MLDSA44.sigBytes),
			ecDerSig,
		);
		expect(MlDsa44EcdsaP256Suite.verify(hybridPk, MSG, forged, CTX)).toBe(false);
	});
});

// ── Verify-timing spot check (0x20, cheapest hybrid) ───────────────────────
// composite-sigs §3.3 permits early-fail; suite declines for parity with
// hybrid-pq.ts. Gate: median paired ratio > 0.5 catches a short-circuit
// on the ML-DSA half (drops to 0.05-0.2).

function timeOne(suite: StreamableSignatureSuite, pk: Uint8Array, sig: Uint8Array): number {
	const t0 = performance.now();
	suite.verify(pk, MSG, sig, CTX);
	return performance.now() - t0;
}

describe('verify timing spot check (0x20)', () => {
	it('tampered-mldsa-half does not measurably shortcut the verify', () => {
		const suite = MlDsa44Ed25519Suite;
		const { pk, sk } = suite.keygen();
		const sig = suite.sign(sk, MSG, CTX);
		const badMldsa = flipByte(sig, Math.floor(MLDSA44.sigBytes / 2));

		// Warm-up amortises WASM JIT-tier promotion noise.
		for (let i = 0; i < 10; i++) {
			timeOne(suite, pk, sig);
			timeOne(suite, pk, badMldsa);
		}

		// Paired interleaved sampling; median of per-pair ratios cancels common-mode jitter.
		const trials = 21;
		const ratios: number[] = [];
		const honests:   number[] = [];
		const tampereds: number[] = [];
		for (let i = 0; i < trials; i++) {
			const honest   = timeOne(suite, pk, sig);
			const tampered = timeOne(suite, pk, badMldsa);
			honests.push(honest);
			tampereds.push(tampered);
			if (honest > 0.1) ratios.push(tampered / honest);
		}
		ratios.sort((a, b) => a - b);
		const medianRatio = ratios[Math.floor(ratios.length / 2)];

		honests.sort((a, b) => a - b);
		tampereds.sort((a, b) => a - b);
		const medHonest   = honests[Math.floor(honests.length / 2)];
		const medTampered = tampereds[Math.floor(tampereds.length / 2)];
		console.log(`hybrid 0x20 verify: honest=${medHonest.toFixed(2)}ms tampered-mldsa=${medTampered.toFixed(2)}ms paired-ratio-median=${medianRatio.toFixed(2)} (n=${ratios.length})`);

		// 0.5 threshold tolerates CI jitter, catches short-circuits.
		expect(medianRatio).toBeGreaterThan(0.5);
		expect(medHonest).toBeGreaterThan(0);
	});
});
