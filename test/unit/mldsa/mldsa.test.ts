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
 * ML-DSA ACVP validation suite, FIPS 204 keyGen / sigGen / sigVer.
 *
 * Source: NIST ACVP ML-DSA-{keyGen,sigGen,sigVer}-FIPS204
 * Vectors: test/vectors/mldsa_{keygen,siggen,sigver}.ts
 *
 * Phase-5 scope: external interface + pure preHash (signatureInterface=external,
 * preHash=pure). The internal-interface and HashML-DSA subsets are phase-6
 * surface and are filtered out here.
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
import {
	ml_dsa_44_siggen,
	ml_dsa_65_siggen,
	ml_dsa_87_siggen,
} from '../../vectors/mldsa_siggen.js';
import type { SigGenVector } from '../../vectors/mldsa_siggen.js';
import {
	ml_dsa_44_sigver,
	ml_dsa_65_sigver,
	ml_dsa_87_sigver,
} from '../../vectors/mldsa_sigver.js';
import type { SigVerVector } from '../../vectors/mldsa_sigver.js';

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

// ── Gate 0, init system wiring ────────────────────────────────────────────
// GATE: ML-DSA init: init({ mldsa, sha3 }) registers both modules and the
// class constructors succeed.

describe('Gate 0, init system wiring', () => {
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

// ── Gate 1, keyGen ML-DSA-44 first ACVP vector ────────────────────────────
// GATE: ML-DSA keyGen ML-DSA-44 first ACVP test (single-vector smoke).
// Vector: test/vectors/mldsa_keygen.ts → ml_dsa_44_keygen[0].

describe('Gate 1, keyGen ML-DSA-44 first ACVP vector', () => {
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

// ── Gate 2, keyGen all parameter sets, all ACVP vectors ───────────────────
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

describe('Gate 2, keyGen all ACVP vectors', () => {
	runAcvpKeygenSuite('ML-DSA-44', () => new MlDsa44(), ml_dsa_44_keygen, MLDSA44);
	runAcvpKeygenSuite('ML-DSA-65', () => new MlDsa65(), ml_dsa_65_keygen, MLDSA65);
	runAcvpKeygenSuite('ML-DSA-87', () => new MlDsa87(), ml_dsa_87_keygen, MLDSA87);
});

// ── Phase-5 vector filter ───────────────────────────────────────────────────
// External interface, pure preHash. Internal-interface and HashML-DSA tests
// are phase-6 scope.
const phase5SigGenFilter = (v: SigGenVector): boolean =>
	v.signatureInterface === 'external' && v.preHash === 'pure';
const phase5SigVerFilter = (v: SigVerVector): boolean =>
	v.signatureInterface === 'external' && v.preHash === 'pure';

function makeDsa(paramSet: string): MlDsa44 | MlDsa65 | MlDsa87 {
	if (paramSet === 'ML-DSA-44') return new MlDsa44();
	if (paramSet === 'ML-DSA-65') return new MlDsa65();
	if (paramSet === 'ML-DSA-87') return new MlDsa87();
	throw new Error(`unknown parameterSet: ${paramSet}`);
}

// ── Gate 3, Sign deterministic ML-DSA-44 first ACVP vector ────────────────
// GATE: ML-DSA Sign first ACVP test (deterministic, external, pure).

describe('Gate 3, Sign ML-DSA-44 first ACVP vector', () => {
	it('byte-identical signature for first deterministic external/pure vector', () => {
		const v = ml_dsa_44_siggen.find(phase5SigGenFilter);
		if (!v || !v.deterministic) throw new Error('no det external/pure vector found');
		const sk  = hexToBytes(v.sk);
		const M   = hexToBytes(v.message ?? '');
		const ctx = v.context ? hexToBytes(v.context) : new Uint8Array(0);
		const dsa = makeDsa(v.parameterSet);
		try {
			const sig = dsa.signDeterministic(sk, M, ctx);
			expect(sig.length).toBe(MLDSA44.sigBytes);
			expect(bytesToHex(sig).toUpperCase()).toBe(v.signature.toUpperCase());
		} finally {
			dsa.dispose();
		}
	});
});

// ── Gate 4, Sign all parameter sets, all phase-5 ACVP sigGen vectors ──────
// GATE: ML-DSA sigGen full ACVP corpus (external/pure subset) across 44/65/87,
// driving signDeterministic for det=true and signDerand for det=false.

function runAcvpSigGenSuite(name: string, vectors: SigGenVector[], params: MlDsaParams): void {
	const phase5 = vectors.filter(phase5SigGenFilter);
	describe(name, () => {
		it.each(phase5)('tcId=$tcId det=$deterministic', (v: SigGenVector) => {
			const sk  = hexToBytes(v.sk);
			const M   = hexToBytes(v.message ?? '');
			const ctx = v.context ? hexToBytes(v.context) : new Uint8Array(0);
			const dsa = makeDsa(v.parameterSet);
			try {
				const sig = v.deterministic
					? dsa.signDeterministic(sk, M, ctx)
					: dsa.signDerand(sk, M, ctx, hexToBytes(v.rnd ?? ''));
				expect(sig.length).toBe(params.sigBytes);
				expect(bytesToHex(sig).toUpperCase()).toBe(v.signature.toUpperCase());
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate 4, sigGen all phase-5 ACVP vectors', () => {
	runAcvpSigGenSuite('ML-DSA-44', ml_dsa_44_siggen, MLDSA44);
	runAcvpSigGenSuite('ML-DSA-65', ml_dsa_65_siggen, MLDSA65);
	runAcvpSigGenSuite('ML-DSA-87', ml_dsa_87_siggen, MLDSA87);
});

// ── Gate 5, Verify ML-DSA-44 first ACVP vector ────────────────────────────
// GATE: ML-DSA Verify first ACVP test.

describe('Gate 5, Verify ML-DSA-44 first ACVP vector', () => {
	it('verify returns testPassed for the first phase-5 sigVer vector', () => {
		const v = ml_dsa_44_sigver.find(phase5SigVerFilter);
		if (!v) throw new Error('no external/pure sigVer vector found');
		const pk  = hexToBytes(v.pk);
		const sig = hexToBytes(v.signature);
		const M   = hexToBytes(v.message ?? '');
		const ctx = v.context ? hexToBytes(v.context) : new Uint8Array(0);
		const dsa = makeDsa(v.parameterSet);
		try {
			expect(dsa.verify(pk, M, sig, ctx)).toBe(v.testPassed);
		} finally {
			dsa.dispose();
		}
	});
});

// ── Gate 6, Verify all parameter sets, all phase-5 ACVP sigVer vectors ────
// GATE: ML-DSA sigVer full ACVP corpus (external/pure subset). Includes both
// expected-pass and known-fail cases; verify must return v.testPassed.

function runAcvpSigVerSuite(name: string, vectors: SigVerVector[]): void {
	const phase5 = vectors.filter(phase5SigVerFilter);
	describe(name, () => {
		it.each(phase5)('tcId=$tcId reason=$reason', (v: SigVerVector) => {
			const pk  = hexToBytes(v.pk);
			const sig = hexToBytes(v.signature);
			const M   = hexToBytes(v.message ?? '');
			const ctx = v.context ? hexToBytes(v.context) : new Uint8Array(0);
			const dsa = makeDsa(v.parameterSet);
			try {
				expect(dsa.verify(pk, M, sig, ctx)).toBe(v.testPassed);
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate 6, sigVer all phase-5 ACVP vectors', () => {
	runAcvpSigVerSuite('ML-DSA-44', ml_dsa_44_sigver);
	runAcvpSigVerSuite('ML-DSA-65', ml_dsa_65_sigver);
	runAcvpSigVerSuite('ML-DSA-87', ml_dsa_87_sigver);
});

// ── Gate 7, Round-trip keygen → sign → verify ─────────────────────────────
// GATE: end-to-end coherence with hedged sign across all parameter sets.

describe('Gate 7, Round-trip keygen → sign → verify', () => {
	const cases = [
		{ name: 'ML-DSA-44', make: () => new MlDsa44() },
		{ name: 'ML-DSA-65', make: () => new MlDsa65() },
		{ name: 'ML-DSA-87', make: () => new MlDsa87() },
	];

	for (const { name, make } of cases) {
		it(`${name}: hedged sign → verify true (5 messages)`, () => {
			const dsa = make();
			try {
				const { verificationKey, signingKey } = dsa.keygen();
				for (let i = 0; i < 5; i++) {
					const msg = new Uint8Array([i, 0xAA, 0xBB, ...new Uint8Array(32 + i)]);
					const sig = dsa.sign(signingKey, msg);
					expect(dsa.verify(verificationKey, msg, sig)).toBe(true);
				}
			} finally {
				dsa.dispose();
			}
		});

		it(`${name}: deterministic sign → verify true; reproducible bytes`, () => {
			const dsa = make();
			try {
				const { verificationKey, signingKey } = dsa.keygen();
				const msg = new Uint8Array([1, 2, 3, 4, 5]);
				const sig1 = dsa.signDeterministic(signingKey, msg);
				const sig2 = dsa.signDeterministic(signingKey, msg);
				expect(bytesToHex(sig1)).toBe(bytesToHex(sig2));
				expect(dsa.verify(verificationKey, msg, sig1)).toBe(true);
			} finally {
				dsa.dispose();
			}
		});

		it(`${name}: tampered message → verify false`, () => {
			const dsa = make();
			try {
				const { verificationKey, signingKey } = dsa.keygen();
				const msg = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
				const sig = dsa.sign(signingKey, msg);
				const tampered = new Uint8Array(msg);
				tampered[0] ^= 1;
				expect(dsa.verify(verificationKey, tampered, sig)).toBe(false);
			} finally {
				dsa.dispose();
			}
		});

		it(`${name}: non-empty ctx round-trip`, () => {
			const dsa = make();
			try {
				const { verificationKey, signingKey } = dsa.keygen();
				const msg = new Uint8Array([0x10, 0x20, 0x30]);
				const ctx = new Uint8Array([0xC0, 0xDE]);
				const sig = dsa.sign(signingKey, msg, ctx);
				expect(dsa.verify(verificationKey, msg, sig, ctx)).toBe(true);
				// Different ctx ⇒ verify false (M' construction binds ctx into μ).
				expect(dsa.verify(verificationKey, msg, sig, new Uint8Array(0))).toBe(false);
			} finally {
				dsa.dispose();
			}
		});
	}
});
