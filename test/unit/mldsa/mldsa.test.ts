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
/**
 * ML-DSA ACVP validation suite — FIPS 204 keyGen.
 *
 * Source: NIST ACVP ML-DSA-keyGen-FIPS204
 * Vectors: test/vectors/mldsa_keygen.ts (75 AFT tests across 44/65/87)
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import { init, MlDsa44, MlDsa65, MlDsa87, isInitialized, hexToBytes, bytesToHex } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { MLDSA44, MLDSA65, MLDSA87 } from '../../../src/ts/mldsa/params.js';
import type { MlDsaParams } from '../../../src/ts/mldsa/params.js';
import {
	ml_dsa_44_keygen,
	ml_dsa_65_keygen,
	ml_dsa_87_keygen,
} from '../../vectors/mldsa_keygen.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

// Top-level beforeAll: reset module cache, verify pre-init guard, init both
// modules. This pattern (mirroring test/unit/kyber/mlkem.test.ts) makes init
// happen for every test in this file even when filtering with `-t`.
beforeAll(async () => {
	_resetForTesting();
	// Pre-init guard: with no module loaded, MlDsa* constructors must throw.
	expect(() => new MlDsa44()).toThrow(/call init/);
	const mldsaBytes = readFileSync(join(__dirname, '../../../build/mldsa.wasm'));
	const sha3Bytes  = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
	await init({ mldsa: mldsaBytes, sha3: sha3Bytes });
});

// ── Gate 0 — init system wiring ────────────────────────────────────────────
// GATE: ML-DSA init: init({ mldsa, sha3 }) registers both modules and the
// class constructors succeed.

describe('Gate 0 — init system wiring', () => {
	it('mldsa module initialized', () => {
		expect(isInitialized('mldsa')).toBe(true);
	});

	it('sha3 module initialized', () => {
		expect(isInitialized('sha3')).toBe(true);
	});

	it('MlDsa44 / MlDsa65 / MlDsa87 construct without arguments', () => {
		expect(new MlDsa44().params.paramSet).toBe('ML-DSA-44');
		expect(new MlDsa65().params.paramSet).toBe('ML-DSA-65');
		expect(new MlDsa87().params.paramSet).toBe('ML-DSA-87');
	});

	it('keygen() produces a pair with the expected byte sizes', () => {
		const dsa = new MlDsa44();
		const { verificationKey, signingKey } = dsa.keygen();
		expect(verificationKey.length).toBe(MLDSA44.pkBytes);
		expect(signingKey.length).toBe(MLDSA44.skBytes);
		dsa.dispose();
	});

	it('keygenDerand rejects non-32-byte seeds', () => {
		const dsa = new MlDsa44();
		expect(() => dsa.keygenDerand(new Uint8Array(31))).toThrow(/32 bytes/);
		expect(() => dsa.keygenDerand(new Uint8Array(33))).toThrow(/32 bytes/);
		dsa.dispose();
	});
});

// ── Gate 1 — keyGen ML-DSA-44 first ACVP vector ────────────────────────────
// GATE: ML-DSA keyGen ML-DSA-44 first ACVP test (single-vector smoke).
// Vector: test/vectors/mldsa_keygen.ts → ml_dsa_44_keygen[0].

describe('Gate 1 — keyGen ML-DSA-44 first ACVP vector', () => {
	it('byte-identical pk and sk for tcId=1', () => {
		const v = ml_dsa_44_keygen[0];
		const xi = hexToBytes(v.seed);
		const dsa = new MlDsa44();
		try {
			const { verificationKey, signingKey } = dsa.keygenDerand(xi);
			expect(bytesToHex(verificationKey).toUpperCase()).toBe(v.pk.toUpperCase());
			expect(bytesToHex(signingKey).toUpperCase()).toBe(v.sk.toUpperCase());
		} finally {
			dsa.dispose();
		}
	});
});

// ── Gate 2 — keyGen all parameter sets, all ACVP vectors ───────────────────
// GATE: ML-DSA keyGen full ACVP corpus across 44/65/87.

interface KeyGenVector { tcId: number; seed: string; pk: string; sk: string }

function runAcvpKeygenSuite(
	name: string,
	make: () => MlDsa44 | MlDsa65 | MlDsa87,
	vectors: KeyGenVector[],
	params: MlDsaParams,
): void {
	describe(name, () => {
		it.each(vectors)('tcId=$tcId', ({ tcId: _tcId, seed, pk, sk }) => {
			const xi = hexToBytes(seed);
			const dsa = make();
			try {
				const { verificationKey, signingKey } = dsa.keygenDerand(xi);
				expect(verificationKey.length).toBe(params.pkBytes);
				expect(signingKey.length).toBe(params.skBytes);
				expect(bytesToHex(verificationKey).toUpperCase()).toBe(pk.toUpperCase());
				expect(bytesToHex(signingKey).toUpperCase()).toBe(sk.toUpperCase());
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate 2 — keyGen all ACVP vectors', () => {
	runAcvpKeygenSuite('ML-DSA-44', () => new MlDsa44(), ml_dsa_44_keygen, MLDSA44);
	runAcvpKeygenSuite('ML-DSA-65', () => new MlDsa65(), ml_dsa_65_keygen, MLDSA65);
	runAcvpKeygenSuite('ML-DSA-87', () => new MlDsa87(), ml_dsa_87_keygen, MLDSA87);
});
