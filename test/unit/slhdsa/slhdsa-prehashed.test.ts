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
 * HashSLH-DSA prehashed-input variants, FIPS 205 §10.2.2 / §10.3.
 *
 * Drives the public methods `signHashPrehashed`,
 * `signHashPrehashedDeterministic`, `signHashPrehashedDerand`, and
 * `verifyHashPrehashed`. Mirror of
 * `test/unit/mldsa/mldsa-prehashed.test.ts`. The HashSLH-DSA ACVP corpus
 * is reused by extracting PH externally with node:crypto, then feeding
 * (sk, PH, ph, ctx) to the prehashed sign and asserting byte-identical
 * signatures against the canonical sigGen vector.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import {
	SlhDsa128f, SlhDsa192f, SlhDsa256f, SlhDsaBase, slhdsaInit,
} from '../../../src/ts/slhdsa/index.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Init }   from '../../../src/ts/sha3/index.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import { sha2Init }   from '../../../src/ts/sha2/index.js';
import { sha2Wasm }   from '../../../src/ts/sha2/embedded.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { SigningError }     from '../../../src/ts/errors.js';
import {
	SLHDSA128F, SLHDSA192F, SLHDSA256F,
} from '../../../src/ts/slhdsa/params.js';
import type { SlhDsaParams } from '../../../src/ts/slhdsa/params.js';
import type { PreHashAlgorithm } from '../../../src/ts/slhdsa/index.js';
import {
	slh_dsa_128f_siggen,
	slh_dsa_192f_siggen,
	slh_dsa_256f_siggen,
} from '../../vectors/slhdsa_siggen.js';
import type { SigGenVector } from '../../vectors/slhdsa_siggen.js';
import {
	slh_dsa_128f_sigver,
	slh_dsa_192f_sigver,
	slh_dsa_256f_sigver,
} from '../../vectors/slhdsa_sigver.js';
import type { SigVerVector } from '../../vectors/slhdsa_sigver.js';

beforeAll(async () => {
	_resetForTesting();
	await Promise.all([
		slhdsaInit(slhdsaWasm),
		sha3Init(sha3Wasm),
		sha2Init(sha2Wasm),
	]);
});

function hex(s: string): Uint8Array {
	const b = new Uint8Array(s.length / 2);
	for (let i = 0; i < b.length; i++) b[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
	return b;
}

function toHex(b: Uint8Array): string {
	return Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
}

function normalizeHashAlg(s: string): PreHashAlgorithm {
	if (s === 'SHAKE-128') return 'SHAKE128';
	if (s === 'SHAKE-256') return 'SHAKE256';
	return s as PreHashAlgorithm;
}

function makeDsa(paramSet: string): SlhDsaBase {
	if (paramSet === 'SLH-DSA-SHAKE-128f') return new SlhDsa128f();
	if (paramSet === 'SLH-DSA-SHAKE-192f') return new SlhDsa192f();
	if (paramSet === 'SLH-DSA-SHAKE-256f') return new SlhDsa256f();
	throw new Error(`unknown parameterSet: ${paramSet}`);
}

function paramsFor(paramSet: string): SlhDsaParams {
	if (paramSet === 'SLH-DSA-SHAKE-128f') return SLHDSA128F;
	if (paramSet === 'SLH-DSA-SHAKE-192f') return SLHDSA192F;
	if (paramSet === 'SLH-DSA-SHAKE-256f') return SLHDSA256F;
	throw new Error(`unknown parameterSet: ${paramSet}`);
}

function isCategoryRestricted(ps: SlhDsaParams, ph: PreHashAlgorithm): boolean {
	return (ph === 'SHA2-256' || ph === 'SHAKE128') && ps.securityCategory !== 1;
}

const ALL_PREHASH: readonly PreHashAlgorithm[] = [
	'SHA2-224', 'SHA2-256', 'SHA2-384', 'SHA2-512',
	'SHA2-512/224', 'SHA2-512/256',
	'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512',
	'SHAKE128', 'SHAKE256',
];

// Compute PH externally with node:crypto. SHAKE128 / SHAKE256 output
// lengths are fixed per FIPS 205 §10.2.2 Algorithm 23 (256 bits / 512 bits).
function computePh(ph: PreHashAlgorithm, M: Uint8Array): Uint8Array {
	switch (ph) {
	case 'SHA2-224':     return new Uint8Array(createHash('sha224').update(M).digest());
	case 'SHA2-256':     return new Uint8Array(createHash('sha256').update(M).digest());
	case 'SHA2-384':     return new Uint8Array(createHash('sha384').update(M).digest());
	case 'SHA2-512':     return new Uint8Array(createHash('sha512').update(M).digest());
	case 'SHA2-512/224': return new Uint8Array(createHash('sha512-224').update(M).digest());
	case 'SHA2-512/256': return new Uint8Array(createHash('sha512-256').update(M).digest());
	case 'SHA3-224':     return new Uint8Array(createHash('sha3-224').update(M).digest());
	case 'SHA3-256':     return new Uint8Array(createHash('sha3-256').update(M).digest());
	case 'SHA3-384':     return new Uint8Array(createHash('sha3-384').update(M).digest());
	case 'SHA3-512':     return new Uint8Array(createHash('sha3-512').update(M).digest());
	case 'SHAKE128':     return new Uint8Array(createHash('shake128', { outputLength: 32 }).update(M).digest());
	case 'SHAKE256':     return new Uint8Array(createHash('shake256', { outputLength: 64 }).update(M).digest());
	}
}

const hashSigGenFilter = (v: SigGenVector): boolean =>
	v.signatureInterface === 'external' && v.preHash === 'preHash';
const hashSigVerFilter = (v: SigVerVector): boolean =>
	v.signatureInterface === 'external' && v.preHash === 'preHash';

// ── Gate, ACVP sigGen byte-equality through the prehashed API ──────────────
// GATE: signHashPrehashedDeterministic / signHashPrehashedDerand fed the
// externally-computed PH must produce the same bytes as the canonical
// signature from the ACVP vector. This proves the new methods are a
// faithful "skip the prehash step" entry point into the same Sign_internal
// path that signHash drives.

function runSigGenSuite(name: string, vectors: SigGenVector[]): void {
	const all = vectors.filter(hashSigGenFilter);
	const params = paramsFor(vectors[0]?.parameterSet ?? 'SLH-DSA-SHAKE-128f');
	const sub = all.filter(v => !isCategoryRestricted(params, normalizeHashAlg(v.hashAlg)));
	describe(name, () => {
		if (sub.length === 0) {
			it.skip('all preHash vectors for this set are category-restricted', () => {
				/* placeholder */
			});
			return;
		}
		it.each(sub)('tcId=$tcId hashAlg=$hashAlg det=$deterministic', (v: SigGenVector) => {
			const sk  = hex(v.sk);
			const M   = hex(v.message);
			const ctx = hex(v.context);
			const ph  = normalizeHashAlg(v.hashAlg);
			const PH  = computePh(ph, M);
			const dsa = makeDsa(v.parameterSet);
			try {
				const optRand = v.deterministic
					? sk.slice(2 * params.n, 3 * params.n)
					: hex(v.additionalRandomness!);
				const sig = v.deterministic
					? dsa.signHashPrehashedDeterministic(sk, PH, ph, ctx)
					: dsa.signHashPrehashedDerand(sk, PH, ph, optRand, ctx);
				expect(sig.length).toBe(params.sigBytes);
				expect(toHex(sig)).toBe(v.signature.toLowerCase());
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate, HashSLH-DSA prehashed sigGen byte-equality', () => {
	runSigGenSuite('SLH-DSA-128f', slh_dsa_128f_siggen);
	runSigGenSuite('SLH-DSA-192f', slh_dsa_192f_siggen);
	runSigGenSuite('SLH-DSA-256f', slh_dsa_256f_siggen);
});

// ── Gate, ACVP sigVer verdicts through verifyHashPrehashed ─────────────────
// GATE: feeding the externally-computed PH plus (pk, σ, ph, ctx) from
// each preHash sigVer vector must return v.testPassed, including the
// known-fail cases. Length-mutated fail vectors are short-circuited to
// false at the public surface (FIPS 205 §3.6.2 structural-mismatch).

function runSigVerSuite(name: string, vectors: SigVerVector[]): void {
	const all = vectors.filter(hashSigVerFilter);
	const params = paramsFor(vectors[0]?.parameterSet ?? 'SLH-DSA-SHAKE-128f');
	const sub = all.filter(v => !isCategoryRestricted(params, normalizeHashAlg(v.hashAlg)));
	describe(name, () => {
		if (sub.length === 0) {
			it.skip('all preHash sigVer vectors are category-restricted', () => {
				/* placeholder */
			});
			return;
		}
		it.each(sub)('tcId=$tcId hashAlg=$hashAlg reason=$reason', (v: SigVerVector) => {
			const pk  = hex(v.pk);
			const sig = hex(v.signature);
			const M   = hex(v.message);
			const ctx = hex(v.context);
			const ph  = normalizeHashAlg(v.hashAlg);
			const PH  = computePh(ph, M);
			const dsa = makeDsa(v.parameterSet);
			try {
				expect(dsa.verifyHashPrehashed(pk, PH, sig, ph, ctx)).toBe(v.testPassed);
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate, HashSLH-DSA prehashed sigVer verdicts', () => {
	runSigVerSuite('SLH-DSA-128f', slh_dsa_128f_sigver);
	runSigVerSuite('SLH-DSA-192f', slh_dsa_192f_sigver);
	runSigVerSuite('SLH-DSA-256f', slh_dsa_256f_sigver);
});

// ── Hedged variant round-trip per (paramSet, prehash) ──────────────────────
// signHashPrehashed cannot byte-compare (opt_rand is fresh each call) so
// we roundtrip through verifyHashPrehashed instead.

describe('Hedged signHashPrehashed → verifyHashPrehashed round-trip', () => {
	const cases = [
		{ name: 'SLH-DSA-128f', make: (): SlhDsaBase => new SlhDsa128f(), params: SLHDSA128F },
		{ name: 'SLH-DSA-192f', make: (): SlhDsaBase => new SlhDsa192f(), params: SLHDSA192F },
		{ name: 'SLH-DSA-256f', make: (): SlhDsaBase => new SlhDsa256f(), params: SLHDSA256F },
	];

	for (const { name, make, params } of cases) {
		describe(name, () => {
			for (const ph of ALL_PREHASH) {
				if (isCategoryRestricted(params, ph)) continue;
				it(`prehash=${ph}: hedged round-trip`, () => {
					const dsa = make();
					try {
						const { verificationKey, signingKey } = dsa.keygen();
						const msg = new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50]);
						const PH  = computePh(ph, msg);
						const sig = dsa.signHashPrehashed(signingKey, PH, ph);
						expect(dsa.verifyHashPrehashed(verificationKey, PH, sig, ph)).toBe(true);
					} finally {
						dsa.dispose();
					}
				});
			}
		});
	}
});

// ── Equivalence with non-prehashed signHash family ─────────────────────────
// Same (sk, M, ph, ctx) drives the same Sign_internal call;
// signHashDeterministic and signHashPrehashedDeterministic must produce
// byte-identical output.

describe('Equivalence: signHashDeterministic ↔ signHashPrehashedDeterministic', () => {
	const cases = [
		{ name: 'SLH-DSA-128f', make: (): SlhDsaBase => new SlhDsa128f(), params: SLHDSA128F },
		{ name: 'SLH-DSA-192f', make: (): SlhDsaBase => new SlhDsa192f(), params: SLHDSA192F },
		{ name: 'SLH-DSA-256f', make: (): SlhDsaBase => new SlhDsa256f(), params: SLHDSA256F },
	];

	for (const { name, make, params } of cases) {
		for (const ph of ALL_PREHASH) {
			if (isCategoryRestricted(params, ph)) continue;
			it(`${name} ph=${ph}`, () => {
				const dsa = make();
				try {
					const { signingKey, verificationKey } = dsa.keygen();
					const msg = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
					const ctx = new Uint8Array([0x42]);
					const PH  = computePh(ph, msg);
					const sigA = dsa.signHashDeterministic(signingKey, msg, ph, ctx);
					const sigB = dsa.signHashPrehashedDeterministic(signingKey, PH, ph, ctx);
					expect(toHex(sigA)).toBe(toHex(sigB));
					expect(dsa.verifyHashPrehashed(verificationKey, PH, sigA, ph, ctx)).toBe(true);
					expect(dsa.verifyHash(verificationKey, msg, sigB, ph, ctx)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});
		}
	}
});

// ── validateDigest, sign throws SigningError, verify returns false ─────────

describe('signHashPrehashed* throws SigningError on wrong-size digest', () => {
	it('signHashPrehashed throws on short digest', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			const bad = new Uint8Array(16);
			expect(() => dsa.signHashPrehashed(signingKey, bad, 'SHA2-256'))
				.toThrow(SigningError);
			expect(() => dsa.signHashPrehashed(signingKey, bad, 'SHA2-256'))
				.toThrow(/sig-malformed-input|digest length/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashPrehashedDeterministic throws on long digest', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			const bad = new Uint8Array(128);
			expect(() => dsa.signHashPrehashedDeterministic(signingKey, bad, 'SHAKE128'))
				.toThrow(SigningError);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashPrehashedDerand throws on wrong-size digest', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			const bad = new Uint8Array(31);
			expect(() => dsa.signHashPrehashedDerand(
				signingKey, bad, 'SHA3-256', new Uint8Array(SLHDSA128F.n),
			)).toThrow(SigningError);
		} finally {
			dsa.dispose();
		}
	});

	it('SigningError carries the sig-malformed-input discriminator', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			try {
				dsa.signHashPrehashedDeterministic(signingKey, new Uint8Array(7), 'SHA2-512');
				expect.fail('should have thrown');
			} catch (e) {
				expect(e).toBeInstanceOf(SigningError);
				expect((e as SigningError).discriminator).toBe('sig-malformed-input');
			}
		} finally {
			dsa.dispose();
		}
	});
});

describe('verifyHashPrehashed returns false on wrong-size digest (no throw)', () => {
	it('short digest → false', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(16),
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHA2-256',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('long digest → false', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(96),
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHAKE256',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('non-Uint8Array digest → false', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHashPrehashed(
				verificationKey,
				null as unknown as Uint8Array,
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHA3-512',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});
});

// ── Misc length-error parity with the non-prehashed family ─────────────────

describe('Length / contract errors mirror the non-prehashed signHash family', () => {
	it('signHashPrehashed throws on wrong-length sk', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(() => dsa.signHashPrehashed(
				new Uint8Array(SLHDSA128F.skBytes - 1),
				new Uint8Array(32),
				'SHA2-256',
			)).toThrow(/signing key must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashPrehashedDeterministic throws on oversize ctx (256 bytes)', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashPrehashedDeterministic(
				signingKey,
				new Uint8Array(32),
				'SHA3-256',
				new Uint8Array(256),
			)).toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashPrehashedDeterministic on ctx=256 throws SigningError(sig-ctx-too-long)', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			try {
				dsa.signHashPrehashedDeterministic(
					signingKey, new Uint8Array(32), 'SHA3-256', new Uint8Array(256),
				);
				expect.fail('should have thrown');
			} catch (e) {
				expect(e).toBeInstanceOf(SigningError);
				expect((e as SigningError).discriminator).toBe('sig-ctx-too-long');
			}
		} finally {
			dsa.dispose();
		}
	});

	it('signHashPrehashedDerand throws on wrong-length optRand', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashPrehashedDerand(
				signingKey,
				new Uint8Array(32),
				'SHAKE256',
				new Uint8Array(SLHDSA128F.n - 1),
				new Uint8Array(0),
			)).toThrow(/opt_rand must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHashPrehashed returns false on wrong-length pk', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(dsa.verifyHashPrehashed(
				new Uint8Array(SLHDSA128F.pkBytes - 1),
				new Uint8Array(32),
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHA2-256',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHashPrehashed returns false on wrong-length σ', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(64),
				new Uint8Array(SLHDSA128F.sigBytes - 1),
				'SHA2-512',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHashPrehashed throws on oversize ctx', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(32),
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHA2-256',
				new Uint8Array(256),
			)).toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('bogus prehash throws RangeError on signHashPrehashed', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashPrehashed(
				signingKey,
				new Uint8Array(32),
				'BLAKE2b' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashSLH-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});

	it('bogus prehash throws RangeError on verifyHashPrehashed', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(32),
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHA2-999' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashSLH-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});
});
