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
 * HashML-DSA validation suite, FIPS 204 §5.4 Algorithms 4 & 5.
 *
 * Drives the new public methods signHash / signHashDeterministic /
 * signHashDerand / verifyHash across the 3 parameter sets × 12 approved
 * pre-hash functions, plus the ACVP HashML-DSA sub-corpus merged into
 * mldsa_siggen.ts / mldsa_sigver.ts via the per-vector preHash discriminator.
 *
 * Pre-hash spelling: the public API uses the FIPS 204 §5.4.1 spelling
 * (no hyphen between SHAKE and the digit). The ACVP corpus uses
 * 'SHAKE-128' / 'SHAKE-256' (with hyphen). normalizeHashAlg() bridges
 * the two without altering the public API.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	init,
	MlDsa44,
	MlDsa65,
	MlDsa87,
	hexToBytes,
	bytesToHex,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }  from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm }  from '../../../src/ts/sha2/embedded.js';
import { MLDSA44, MLDSA65, MLDSA87 } from '../../../src/ts/mldsa/params.js';
import type { MlDsaParams } from '../../../src/ts/mldsa/params.js';
import type { PreHashAlgorithm } from '../../../src/ts/mldsa/index.js';
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

beforeAll(async () => {
	_resetForTesting();
	// HashML-DSA needs all three: mldsa orchestrator, sha3 driver (XOF/SHAKE),
	// sha2 driver (SHA-2 family pre-hash).
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm, sha2: sha2Wasm });
});

const ALL_PREHASH: readonly PreHashAlgorithm[] = [
	'SHA2-224', 'SHA2-256', 'SHA2-384', 'SHA2-512',
	'SHA2-512/224', 'SHA2-512/256',
	'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512',
	'SHAKE128', 'SHAKE256',
];

// ACVP labels SHAKE with a hyphen, translate to the FIPS 204 spelling
// the public API takes. All other labels are byte-identical.
function normalizeHashAlg(s: string): PreHashAlgorithm {
	if (s === 'SHAKE-128') return 'SHAKE128';
	if (s === 'SHAKE-256') return 'SHAKE256';
	return s as PreHashAlgorithm;
}

function makeDsa(paramSet: string): MlDsa44 | MlDsa65 | MlDsa87 {
	if (paramSet === 'ML-DSA-44') return new MlDsa44();
	if (paramSet === 'ML-DSA-65') return new MlDsa65();
	if (paramSet === 'ML-DSA-87') return new MlDsa87();
	throw new Error(`unknown parameterSet: ${paramSet}`);
}

// HashML-DSA filter, external interface, preHash branch.
const hashSigGenFilter = (v: SigGenVector): boolean =>
	v.signatureInterface === 'external' && v.preHash === 'preHash';
const hashSigVerFilter = (v: SigVerVector): boolean =>
	v.signatureInterface === 'external' && v.preHash === 'preHash';

// ── Gate 8, HashML-DSA round-trip per (paramSet, prehash) ─────────────────
// GATE: signHash → verifyHash succeeds for every (paramSet, prehash)
// combination (3 × 12 = 36 tuples). The inner Sign_internal / Verify_internal
// is already gated by phase 5; this gate exercises that the M' construction,
// OID dispatch, and pre-hash routing all wire up correctly.

describe('Gate 8, HashML-DSA round-trip per (paramSet, prehash)', () => {
	const cases = [
		{ name: 'ML-DSA-44', make: () => new MlDsa44() },
		{ name: 'ML-DSA-65', make: () => new MlDsa65() },
		{ name: 'ML-DSA-87', make: () => new MlDsa87() },
	];

	for (const { name, make } of cases) {
		describe(name, () => {
			for (const ph of ALL_PREHASH) {
				it(`prehash=${ph}: signHash → verifyHash true`, () => {
					const dsa = make();
					try {
						const { verificationKey, signingKey } = dsa.keygen();
						const msg = new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50]);
						const sig = dsa.signHash(signingKey, msg, ph);
						expect(dsa.verifyHash(verificationKey, msg, sig, ph)).toBe(true);
					} finally {
						dsa.dispose();
					}
				});

				it(`prehash=${ph}: deterministic reproducible bytes`, () => {
					const dsa = make();
					try {
						const { verificationKey, signingKey } = dsa.keygen();
						const msg = new Uint8Array([1, 2, 3]);
						const sig1 = dsa.signHashDeterministic(signingKey, msg, ph);
						const sig2 = dsa.signHashDeterministic(signingKey, msg, ph);
						expect(bytesToHex(sig1)).toBe(bytesToHex(sig2));
						expect(dsa.verifyHash(verificationKey, msg, sig1, ph)).toBe(true);
					} finally {
						dsa.dispose();
					}
				});
			}
		});
	}
});

// ── Gate 9, HashML-DSA byte-identical signatures from ACVP sigGen ──────────
// GATE: sigGen vectors with preHash=preHash drive signHashDerand /
// signHashDeterministic and assert byte-equality of the produced signature.

function runHashSigGenSuite(name: string, vectors: SigGenVector[], params: MlDsaParams): void {
	const sub = vectors.filter(hashSigGenFilter);
	describe(name, () => {
		it.each(sub)('tcId=$tcId hashAlg=$hashAlg det=$deterministic', (v: SigGenVector) => {
			const sk  = hexToBytes(v.sk);
			const M   = hexToBytes(v.message ?? '');
			const ctx = v.context ? hexToBytes(v.context) : new Uint8Array(0);
			const ph  = normalizeHashAlg(v.hashAlg);
			const dsa = makeDsa(v.parameterSet);
			try {
				const sig = v.deterministic
					? dsa.signHashDeterministic(sk, M, ph, ctx)
					: dsa.signHashDerand(sk, M, ph, ctx, hexToBytes(v.rnd ?? ''));
				expect(sig.length).toBe(params.sigBytes);
				expect(bytesToHex(sig).toUpperCase()).toBe(v.signature.toUpperCase());
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate 9, HashML-DSA ACVP sigGen byte-equality', () => {
	runHashSigGenSuite('ML-DSA-44', ml_dsa_44_siggen, MLDSA44);
	runHashSigGenSuite('ML-DSA-65', ml_dsa_65_siggen, MLDSA65);
	runHashSigGenSuite('ML-DSA-87', ml_dsa_87_siggen, MLDSA87);
});

// ── Gate 10, HashML-DSA verify across ACVP sigVer corpus ───────────────────
// GATE: sigVer vectors with preHash=preHash exercise verifyHash; both
// expected-pass and known-fail cases are present, and the verdict must
// match v.testPassed.

function runHashSigVerSuite(name: string, vectors: SigVerVector[]): void {
	const sub = vectors.filter(hashSigVerFilter);
	describe(name, () => {
		it.each(sub)('tcId=$tcId hashAlg=$hashAlg reason=$reason', (v: SigVerVector) => {
			const pk  = hexToBytes(v.pk);
			const sig = hexToBytes(v.signature);
			const M   = hexToBytes(v.message ?? '');
			const ctx = v.context ? hexToBytes(v.context) : new Uint8Array(0);
			const ph  = normalizeHashAlg(v.hashAlg);
			const dsa = makeDsa(v.parameterSet);
			try {
				expect(dsa.verifyHash(pk, M, sig, ph, ctx)).toBe(v.testPassed);
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate 10, HashML-DSA ACVP sigVer verdicts', () => {
	runHashSigVerSuite('ML-DSA-44', ml_dsa_44_sigver);
	runHashSigVerSuite('ML-DSA-65', ml_dsa_65_sigver);
	runHashSigVerSuite('ML-DSA-87', ml_dsa_87_sigver);
});

// ── Cross-protocol separation (FIPS 204 §3.6.4) ─────────────────────────────
// A HashML-DSA signature MUST NOT verify under pure verify(), and a pure
// ML-DSA signature MUST NOT verify under verifyHash(). The 0x01 vs 0x00
// domain-sep byte in M' is what enforces this, confirm explicitly.

describe('Cross-protocol separation, pure ↔ HashML-DSA mutually distinct', () => {
	it('signHash output → verify (pure) returns false', () => {
		const dsa = new MlDsa65();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([0xCA, 0xFE]);
			const sig = dsa.signHash(signingKey, msg, 'SHA2-256');
			expect(dsa.verify(verificationKey, msg, sig)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('sign (pure) output → verifyHash returns false', () => {
		const dsa = new MlDsa65();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([0xCA, 0xFE]);
			const sig = dsa.sign(signingKey, msg);
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA2-256')).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('different prehash on verifyHash returns false', () => {
		const dsa = new MlDsa65();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([0xCA, 0xFE]);
			const sig = dsa.signHash(signingKey, msg, 'SHA2-256');
			// Same M, same key, different OID in M', must fail.
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA3-256')).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('different ctx on verifyHash returns false', () => {
		const dsa = new MlDsa65();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([0xCA, 0xFE]);
			const ctx = new Uint8Array([0xC0, 0xDE]);
			const sig = dsa.signHash(signingKey, msg, 'SHA3-512', ctx);
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA3-512', ctx)).toBe(true);
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA3-512')).toBe(false);
		} finally {
			dsa.dispose();
		}
	});
});

// ── Validate-checks, signHash family + verifyHash ──────────────────────────

describe('signHash / verifyHash, wrong-length sk / pk / σ / ctx', () => {
	it('signHash throws on wrong-length sk', () => {
		const dsa = new MlDsa44();
		try {
			expect(() => dsa.signHash(new Uint8Array(MLDSA44.skBytes - 1), new Uint8Array(8), 'SHA2-256'))
				.toThrow(/signing key must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashDeterministic throws on oversize ctx', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashDeterministic(signingKey, new Uint8Array(8), 'SHA3-256', new Uint8Array(256)))
				.toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashDerand throws on wrong-length rnd', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashDerand(signingKey, new Uint8Array(8), 'SHAKE128', new Uint8Array(0), new Uint8Array(31)))
				.toThrow(/rnd must be 32 bytes/);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHash returns false on wrong-length pk', () => {
		const dsa = new MlDsa44();
		try {
			expect(dsa.verifyHash(
				new Uint8Array(MLDSA44.pkBytes - 1),
				new Uint8Array(8),
				new Uint8Array(MLDSA44.sigBytes),
				'SHA2-256',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHash returns false on wrong-length σ', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHash(
				verificationKey,
				new Uint8Array(8),
				new Uint8Array(MLDSA44.sigBytes - 1),
				'SHA2-512',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHash throws on oversize ctx', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHash(
				verificationKey,
				new Uint8Array(8),
				new Uint8Array(MLDSA44.sigBytes),
				'SHA2-256',
				new Uint8Array(256),
			)).toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});
});

describe('signHash / verifyHash, unsupported prehash throws RangeError', () => {
	// Type system rules out this case at compile time; runtime guard is a
	// belt-and-braces check for callers who widen the type via `as`.
	it('bogus prehash throws on signHash', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHash(
				signingKey,
				new Uint8Array(8),
				'SHA2-999' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashML-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});

	it('bogus prehash throws on verifyHash', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHash(
				verificationKey,
				new Uint8Array(8),
				new Uint8Array(MLDSA44.sigBytes),
				'BLAKE2b' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashML-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});
});
