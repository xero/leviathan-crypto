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
 * HashSLH-DSA M' construction and end-to-end coverage.
 *
 * Mirror of `test/unit/mldsa/hashvariant.test.ts`. Drives the public
 * `signHash` family across 3 parameter sets × approved pre-hash functions
 * (filtered by FIPS 205 §10.2.2 category restriction on SHA-256 /
 * SHAKE128) plus the M' byte-exact construction.
 *
 * Vector source: the ACVP HashSLH-DSA preHash sub-corpus already imported
 * by `slhdsa-acvp.test.ts`, replayed through the TS class layer so we get
 * byte-equality of signature output for the deterministic vectors.
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
import {
	SLHDSA128F, SLHDSA192F, SLHDSA256F,
} from '../../../src/ts/slhdsa/params.js';
import type { SlhDsaParams } from '../../../src/ts/slhdsa/params.js';
import type { PreHashAlgorithm } from '../../../src/ts/slhdsa/index.js';
import { constructMPrimeHash, getOid } from '../../../src/ts/slhdsa/prehash.js';
import { SigningError } from '../../../src/ts/errors.js';
import {
	slh_dsa_128f_siggen,
	slh_dsa_192f_siggen,
	slh_dsa_256f_siggen,
} from '../../vectors/slhdsa_siggen.js';
import type { SigGenVector } from '../../vectors/slhdsa_siggen.js';

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

// ACVP labels SHAKE with a hyphen. Translate to the FIPS 205 §10.2.2
// spelling the public API takes. All other labels are byte-identical.
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

// FIPS 205 §10.2.2 category restriction: SHA-256 and SHAKE128 are only
// appropriate for security category 1 (128f). The TS layer enforces this
// at `_assertHashPrereqs`, ACVP vectors that violate the rule are
// exercised at the negative-test layer below; the positive-path runs
// filter them out so deterministic byte-equality has somewhere to land.
function isCategoryRestricted(ps: SlhDsaParams, ph: PreHashAlgorithm): boolean {
	return (ph === 'SHA2-256' || ph === 'SHAKE128') && ps.securityCategory !== 1;
}

const hashSigGenFilter = (v: SigGenVector): boolean =>
	v.signatureInterface === 'external' && v.preHash === 'preHash';

// All 12 FIPS 205 §10.2.2 approved pre-hashes.
const ALL_PREHASH: readonly PreHashAlgorithm[] = [
	'SHA2-224', 'SHA2-256', 'SHA2-384', 'SHA2-512',
	'SHA2-512/224', 'SHA2-512/256',
	'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512',
	'SHAKE128', 'SHAKE256',
];

// ── M' byte-exact construction ─────────────────────────────────────────────
// GATE: M' built by `constructMPrimeHash` matches the spec layout
// `0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ digest` for every (ph, ctx, digest) tuple.
// This is the only test that pins the wire bytes; downstream tests assume
// the same construction.

describe('M\' construction byte-exact (FIPS 205 §10.2.2 Algorithm 23 lines 18-19)', () => {
	it.each(ALL_PREHASH)('ph=%s produces 0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ digest', (ph) => {
		const digestSize = (() => {
			switch (ph) {
			case 'SHA2-224':     return 28;
			case 'SHA2-256':     return 32;
			case 'SHA2-384':     return 48;
			case 'SHA2-512':     return 64;
			case 'SHA2-512/224': return 28;
			case 'SHA2-512/256': return 32;
			case 'SHA3-224':     return 28;
			case 'SHA3-256':     return 32;
			case 'SHA3-384':     return 48;
			case 'SHA3-512':     return 64;
			case 'SHAKE128':     return 32;
			case 'SHAKE256':     return 64;
			}
		})();
		const digest = new Uint8Array(digestSize).fill(0xAB);
		const ctx    = new Uint8Array([0xC0, 0xDE, 0xCA, 0xFE]);
		const oid    = getOid(ph);
		const out    = constructMPrimeHash(digest, ph, ctx);
		expect(out[0]).toBe(0x01);
		expect(out[1]).toBe(ctx.length);
		expect(toHex(out.subarray(2, 2 + ctx.length))).toBe(toHex(ctx));
		expect(toHex(out.subarray(2 + ctx.length, 2 + ctx.length + oid.length))).toBe(toHex(oid));
		expect(toHex(out.subarray(2 + ctx.length + oid.length))).toBe(toHex(digest));
		expect(out.length).toBe(2 + ctx.length + oid.length + digest.length);
	});

	it('empty ctx still yields 0x01 ‖ 0x00 ‖ OID ‖ digest', () => {
		const digest = new Uint8Array(32);
		const out    = constructMPrimeHash(digest, 'SHA2-256', new Uint8Array(0));
		expect(out[0]).toBe(0x01);
		expect(out[1]).toBe(0x00);
		expect(out.length).toBe(2 + 11 + 32);
	});

	it('255-byte ctx encodes |ctx| = 0xFF', () => {
		const digest = new Uint8Array(32);
		const ctx    = new Uint8Array(255).fill(0x42);
		const out    = constructMPrimeHash(digest, 'SHA3-256', ctx);
		expect(out[1]).toBe(0xFF);
	});

	it('M\' byte-identical to FIPS 204 §5.4 mldsa construction for the shared layout', () => {
		// FIPS 205 §10.2.2 M' and FIPS 204 §5.4 M' share the same byte
		// layout (the OIDs are also identical). This test pins that
		// invariant on the SLH-DSA side; the mldsa side is gated by
		// test/unit/mldsa/hashvariant.test.ts.
		const ph: PreHashAlgorithm = 'SHA2-256';
		const digest = new Uint8Array(32).fill(0xCD);
		const ctx    = new Uint8Array([0x01, 0x02, 0x03]);
		const oid    = getOid(ph);
		const out    = constructMPrimeHash(digest, ph, ctx);
		// 0x01 ‖ 0x03 ‖ 01 02 03 ‖ OID(11) ‖ digest(32)
		const expected = new Uint8Array(2 + 3 + 11 + 32);
		expected[0] = 0x01;
		expected[1] = 0x03;
		expected.set(ctx,    2);
		expected.set(oid,    5);
		expected.set(digest, 16);
		expect(toHex(out)).toBe(toHex(expected));
	});
});

// ── Gate, HashSLH-DSA round-trip per (paramSet, prehash) ───────────────────
// GATE: signHash → verifyHash succeeds for every allowed (paramSet,
// prehash) combination. Combos restricted by category (SHA-256 / SHAKE128
// on 192f / 256f) are excluded and tested separately below.

describe('Gate, HashSLH-DSA round-trip per (paramSet, prehash)', () => {
	const cases = [
		{ name: 'SLH-DSA-128f', make: (): SlhDsaBase => new SlhDsa128f(), params: SLHDSA128F },
		{ name: 'SLH-DSA-192f', make: (): SlhDsaBase => new SlhDsa192f(), params: SLHDSA192F },
		{ name: 'SLH-DSA-256f', make: (): SlhDsaBase => new SlhDsa256f(), params: SLHDSA256F },
	];

	for (const { name, make, params } of cases) {
		describe(name, () => {
			for (const ph of ALL_PREHASH) {
				if (isCategoryRestricted(params, ph)) continue;
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
						expect(toHex(sig1)).toBe(toHex(sig2));
						expect(dsa.verifyHash(verificationKey, msg, sig1, ph)).toBe(true);
					} finally {
						dsa.dispose();
					}
				});
			}
		});
	}
});

// ── Gate, HashSLH-DSA byte-identical signatures from ACVP sigGen ───────────
// GATE: sigGen vectors with preHash=preHash drive signHashDerand /
// signHashDeterministic and assert byte-equality of the produced
// signature. Vectors that target category-restricted (ph, paramSet)
// combos are skipped here and surfaced as throw-tests below.

function runHashSigGenSuite(name: string, vectors: SigGenVector[]): void {
	const all = vectors.filter(hashSigGenFilter);
	const params = paramsFor(vectors[0]?.parameterSet ?? 'SLH-DSA-SHAKE-128f');
	const sub = all.filter(v => !isCategoryRestricted(params, normalizeHashAlg(v.hashAlg)));
	describe(name, () => {
		if (sub.length === 0) {
			it.skip('all preHash vectors for this set are category-restricted', () => {
				// Placeholder: 256f corpus carries a SHAKE-128 case but
				// FIPS 205 §10.2.2 rejects SHAKE128 on cat 5.
			});
			return;
		}
		it.each(sub)('tcId=$tcId hashAlg=$hashAlg det=$deterministic', (v: SigGenVector) => {
			const sk      = hex(v.sk);
			const M       = hex(v.message);
			const ctx     = hex(v.context);
			const ph      = normalizeHashAlg(v.hashAlg);
			const dsa     = makeDsa(v.parameterSet);
			try {
				const optRand = v.deterministic
					? sk.slice(2 * params.n, 3 * params.n)
					: hex(v.additionalRandomness!);
				const sig = v.deterministic
					? dsa.signHashDeterministic(sk, M, ph, ctx)
					: dsa.signHashDerand(sk, M, ph, optRand, ctx);
				expect(sig.length).toBe(params.sigBytes);
				expect(toHex(sig)).toBe(v.signature.toLowerCase());
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate, HashSLH-DSA ACVP sigGen byte-equality', () => {
	runHashSigGenSuite('SLH-DSA-128f', slh_dsa_128f_siggen);
	runHashSigGenSuite('SLH-DSA-192f', slh_dsa_192f_siggen);
	runHashSigGenSuite('SLH-DSA-256f', slh_dsa_256f_siggen);
});

// ── Cross-protocol separation (FIPS 205 §10.2 narrative) ────────────────────
// A HashSLH-DSA signature MUST NOT verify under pure verify(), and a pure
// SLH-DSA signature MUST NOT verify under verifyHash(). The 0x01 vs 0x00
// domain-sep byte in M' is what enforces this.

describe('Cross-protocol separation, pure ↔ HashSLH-DSA mutually distinct', () => {
	it('signHash output → verify (pure) returns false', () => {
		const dsa = new SlhDsa128f();
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
		const dsa = new SlhDsa128f();
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
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([0xCA, 0xFE]);
			const sig = dsa.signHash(signingKey, msg, 'SHA2-256');
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA3-256')).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('different ctx on verifyHash returns false', () => {
		const dsa = new SlhDsa128f();
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

// ── Category restriction (FIPS 205 §10.2.2) ─────────────────────────────────
// SHA-256 / SHAKE128 only valid for cat 1 (128f). 192f / 256f throw
// RangeError. The negative coverage here pairs with the positive coverage
// gated by `isCategoryRestricted` above.

describe('Category restriction, SHA-256 / SHAKE128 rejected on non-128f', () => {
	const cases = [
		{ name: 'SLH-DSA-192f', make: (): SlhDsaBase => new SlhDsa192f() },
		{ name: 'SLH-DSA-256f', make: (): SlhDsaBase => new SlhDsa256f() },
	];

	for (const { name, make } of cases) {
		describe(name, () => {
			it('signHash with SHA-256 throws RangeError', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					expect(() => dsa.signHash(signingKey, new Uint8Array(8), 'SHA2-256'))
						.toThrow(/only appropriate for security category 1/);
				} finally {
					dsa.dispose();
				}
			});

			it('signHash with SHAKE128 throws RangeError', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					expect(() => dsa.signHash(signingKey, new Uint8Array(8), 'SHAKE128'))
						.toThrow(/only appropriate for security category 1/);
				} finally {
					dsa.dispose();
				}
			});

			it('verifyHash with SHA-256 throws RangeError', () => {
				const dsa = make();
				try {
					const { verificationKey } = dsa.keygen();
					expect(() => dsa.verifyHash(
						verificationKey,
						new Uint8Array(8),
						new Uint8Array(dsa.params.sigBytes),
						'SHA2-256',
					)).toThrow(/only appropriate for security category 1/);
				} finally {
					dsa.dispose();
				}
			});
		});
	}

	it('128f accepts both SHA-256 and SHAKE128 without throwing', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([1, 2, 3]);
			const sigA = dsa.signHashDeterministic(signingKey, msg, 'SHA2-256');
			expect(dsa.verifyHash(verificationKey, msg, sigA, 'SHA2-256')).toBe(true);
			const sigB = dsa.signHashDeterministic(signingKey, msg, 'SHAKE128');
			expect(dsa.verifyHash(verificationKey, msg, sigB, 'SHAKE128')).toBe(true);
		} finally {
			dsa.dispose();
		}
	});
});

// ── Length / contract errors ────────────────────────────────────────────────

describe('signHash / verifyHash, wrong-length sk / pk / σ / ctx', () => {
	it('signHash throws on wrong-length sk', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(() => dsa.signHash(new Uint8Array(SLHDSA128F.skBytes - 1), new Uint8Array(8), 'SHA2-256'))
				.toThrow(/signing key must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashDeterministic throws on oversize ctx', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashDeterministic(signingKey, new Uint8Array(8), 'SHA3-256', new Uint8Array(256)))
				.toThrow(SigningError);
			expect(() => dsa.signHashDeterministic(signingKey, new Uint8Array(8), 'SHA3-256', new Uint8Array(256)))
				.toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashDerand throws on wrong-length optRand', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashDerand(signingKey, new Uint8Array(8), 'SHAKE256', new Uint8Array(0), new Uint8Array(0)))
				.toThrow(/opt_rand must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHash returns false on wrong-length pk', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(dsa.verifyHash(
				new Uint8Array(SLHDSA128F.pkBytes - 1),
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHA2-256',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHash returns false on wrong-length σ', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHash(
				verificationKey,
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes - 1),
				'SHA2-512',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHash throws on oversize ctx', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHash(
				verificationKey,
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHA2-256',
				new Uint8Array(256),
			)).toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});
});

describe('signHash / verifyHash, unsupported prehash throws RangeError', () => {
	it('bogus prehash throws on signHash', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHash(
				signingKey,
				new Uint8Array(8),
				'SHA2-999' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashSLH-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});

	it('bogus prehash throws on verifyHash', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHash(
				verificationKey,
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes),
				'BLAKE2b' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashSLH-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});
});

// ── Cross-check against an independent prehash oracle ──────────────────────
// node:crypto computes PH externally; the TS class's internal preHashMessage
// must produce the same M' (and thus the same signature) for the
// deterministic variant.

describe('Cross-check vs node:crypto SHA-2 / SHA-3 prehash', () => {
	it('SHA2-256 signHashDeterministic matches signHashPrehashedDeterministic on node:crypto PH', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			const msg = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
			const ph: PreHashAlgorithm = 'SHA2-256';
			const PH  = new Uint8Array(createHash('sha256').update(msg).digest());
			const sigA = dsa.signHashDeterministic(signingKey, msg, ph);
			const sigB = dsa.signHashPrehashedDeterministic(signingKey, PH, ph);
			expect(toHex(sigA)).toBe(toHex(sigB));
		} finally {
			dsa.dispose();
		}
	});

	it('SHA3-512 signHashDeterministic matches signHashPrehashedDeterministic on node:crypto PH', () => {
		const dsa = new SlhDsa192f();
		try {
			const { signingKey } = dsa.keygen();
			const msg = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
			const ph: PreHashAlgorithm = 'SHA3-512';
			const PH  = new Uint8Array(createHash('sha3-512').update(msg).digest());
			const sigA = dsa.signHashDeterministic(signingKey, msg, ph);
			const sigB = dsa.signHashPrehashedDeterministic(signingKey, PH, ph);
			expect(toHex(sigA)).toBe(toHex(sigB));
		} finally {
			dsa.dispose();
		}
	});
});
