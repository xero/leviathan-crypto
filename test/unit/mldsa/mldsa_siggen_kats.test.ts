// test/unit/mldsa/mldsa_siggen_kats.test.ts
//
// ML-DSA rejection-path and high-rejection-count KAT suite.
//
// Drives FIPS 204 Algorithm 7 `ML-DSA.Sign_internal` directly with the M'
// values from ACVP §6.1.2 Tables 1 and 2 (see test/vectors/mldsa_siggen_kats.ts
// for the source). Random AFT vectors sample the rejection loop too rarely
// to reliably hit the |z|, |r₀|, hint-popcount, and |ct₀| reject branches;
// these KATs each trigger every reachable branch by construction.
//
// Per-record assertion:
//   1. KeyGen(seed) reproduces a (pk, sk) whose SHA2-256(pk ‖ sk) matches
//      the spec's `keypairHash`.
//   2. Sign_internal(sk, M', 0³²) produces a signature whose SHA2-256(σ)
//      matches the spec's `sigHash`.
//
// Internal-interface access: this test bypasses the public class API and
// calls `mldsaSignInternal` (the exported FIPS 204 Algorithm 7 primitive)
// with the WASM exports fetched directly from the init registry. The
// public `signDerand` path wraps M' construction (it builds
// `0x00 ‖ |ctx| ‖ ctx ‖ M`); the KATs supply M' as raw bytes, so the
// internal entrypoint is the only way to drive the algorithm with the
// spec's input verbatim.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	MlDsa44, MlDsa65, MlDsa87,
	SHA256,
	hexToBytes, bytesToHex,
} from '../../../src/ts/index.js';
import { _resetForTesting, getInstance } from '../../../src/ts/init.js';
import { MLDSA44, MLDSA65, MLDSA87 } from '../../../src/ts/mldsa/params.js';
import type { MlDsaParams } from '../../../src/ts/mldsa/params.js';
import type { MlDsaExports, Sha3Exports } from '../../../src/ts/mldsa/types.js';
import { mldsaSignInternal } from '../../../src/ts/mldsa/sign.js';
import {
	ml_dsa_44_siggen_kats,
	ml_dsa_65_siggen_kats,
	ml_dsa_87_siggen_kats,
} from '../../vectors/mldsa_siggen_kats.js';
import type { SigGenKatVector } from '../../vectors/mldsa_siggen_kats.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const mldsaBytes = readFileSync(join(__dirname, '../../../build/mldsa.wasm'));
	const sha3Bytes  = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
	const sha2Bytes  = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	await init({ mldsa: mldsaBytes, sha3: sha3Bytes, sha2: sha2Bytes });
});

function makeDsa(paramSet: SigGenKatVector['paramSet']): MlDsa44 | MlDsa65 | MlDsa87 {
	if (paramSet === 'ML-DSA-44') return new MlDsa44();
	if (paramSet === 'ML-DSA-65') return new MlDsa65();
	return new MlDsa87();
}

function paramsFor(paramSet: SigGenKatVector['paramSet']): MlDsaParams {
	if (paramSet === 'ML-DSA-44') return MLDSA44;
	if (paramSet === 'ML-DSA-65') return MLDSA65;
	return MLDSA87;
}

function runKatSuite(name: string, vectors: SigGenKatVector[]): void {
	describe(name, () => {
		it.each(vectors)('table $table, $label', (v: SigGenKatVector) => {
			const sha256 = new SHA256();
			const dsa    = makeDsa(v.paramSet);
			try {
				// Step 1, KeyGen(seed) and verify SHA2-256(pk ‖ sk).
				const seed = hexToBytes(v.seed);
				const { verificationKey: pk, signingKey: sk } = dsa.keygenDerand(seed);

				const concat = new Uint8Array(pk.length + sk.length);
				concat.set(pk, 0);
				concat.set(sk, pk.length);
				const kpHash = sha256.hash(concat);
				expect(bytesToHex(kpHash).toUpperCase()).toBe(v.keypairHash.toUpperCase());

				// Step 2, Sign_internal(sk, M', rnd = 0³²) and verify SHA2-256(σ).
				const mPrime = hexToBytes(v.mPrime);
				const rnd    = new Uint8Array(32);
				const mx = getInstance('mldsa').exports as unknown as MlDsaExports;
				const sx = getInstance('sha3').exports  as unknown as Sha3Exports;
				const sig = mldsaSignInternal(mx, sx, paramsFor(v.paramSet), sk, mPrime, rnd);

				const sigHash = sha256.hash(sig);
				expect(bytesToHex(sigHash).toUpperCase()).toBe(v.sigHash.toUpperCase());
			} finally {
				dsa.dispose();
				sha256.dispose();
			}
		});
	});
}

describe('ACVP §6.1.2 Table 1 + Table 2, Sign_internal rejection-path KATs', () => {
	runKatSuite('ML-DSA-44', ml_dsa_44_siggen_kats);
	runKatSuite('ML-DSA-65', ml_dsa_65_siggen_kats);
	runKatSuite('ML-DSA-87', ml_dsa_87_siggen_kats);
});
