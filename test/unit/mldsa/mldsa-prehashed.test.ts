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
 * HashML-DSA prehashed variants, FIPS 204 §5.4 Algorithms 4 & 5. Drives
 * signHashPrehashed / Deterministic / Derand / verifyHashPrehashed.
 * Reuses HashML-DSA ACVP corpus (preHash branch), PH extracted externally.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	init,
	MlDsa44,
	MlDsa65,
	MlDsa87,
	SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256,
	SHA3_224, SHA3_256, SHA3_384, SHA3_512,
	SHAKE128, SHAKE256,
	hexToBytes,
	bytesToHex,
} from '../../../src/ts/index.js';
import { SigningError } from '../../../src/ts/errors.js';
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
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm, sha2: sha2Wasm });
});

const ALL_PREHASH: readonly PreHashAlgorithm[] = [
	'SHA2-224', 'SHA2-256', 'SHA2-384', 'SHA2-512',
	'SHA2-512/224', 'SHA2-512/256',
	'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512',
	'SHAKE128', 'SHAKE256',
];

// ACVP labels SHAKE with a hyphen, translate to the FIPS 204 spelling.
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

// Compute PH ← Hash(M, ph) using the public hash classes. Each class is
// disposed inline so it releases its WASM module before the subsequent
// mldsa sign / verify call (sha3 / sha2 are owned exclusively by the
// stateful XOF classes, atomic SHA-2 / SHA-3 instances do not block but
// still get a defensive dispose() for hygiene).
function computePh(ph: PreHashAlgorithm, M: Uint8Array): Uint8Array {
	switch (ph) {
	case 'SHA2-224':     { const h = new SHA224();     try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA2-256':     { const h = new SHA256();     try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA2-384':     { const h = new SHA384();     try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA2-512':     { const h = new SHA512();     try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA2-512/224': { const h = new SHA512_224(); try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA2-512/256': { const h = new SHA512_256(); try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA3-224':     { const h = new SHA3_224();   try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA3-256':     { const h = new SHA3_256();   try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA3-384':     { const h = new SHA3_384();   try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHA3-512':     { const h = new SHA3_512();   try {
		return h.hash(M);
	} finally {
		h.dispose();
	} }
	case 'SHAKE128':     { const h = new SHAKE128();   try {
		return h.hash(M, 32);
	} finally {
		h.dispose();
	} }
	case 'SHAKE256':     { const h = new SHAKE256();   try {
		return h.hash(M, 64);
	} finally {
		h.dispose();
	} }
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

function runSigGenSuite(name: string, vectors: SigGenVector[], params: MlDsaParams): void {
	const sub = vectors.filter(hashSigGenFilter);
	describe(name, () => {
		it.each(sub)('tcId=$tcId hashAlg=$hashAlg det=$deterministic', (v: SigGenVector) => {
			const sk  = hexToBytes(v.sk);
			const M   = hexToBytes(v.message ?? '');
			const ctx = v.context ? hexToBytes(v.context) : new Uint8Array(0);
			const ph  = normalizeHashAlg(v.hashAlg);
			const PH  = computePh(ph, M);
			const dsa = makeDsa(v.parameterSet);
			try {
				const sig = v.deterministic
					? dsa.signHashPrehashedDeterministic(sk, PH, ph, ctx)
					: dsa.signHashPrehashedDerand(sk, PH, ph, hexToBytes(v.rnd ?? ''), ctx);
				expect(sig.length).toBe(params.sigBytes);
				expect(bytesToHex(sig).toUpperCase()).toBe(v.signature.toUpperCase());
			} finally {
				dsa.dispose();
			}
		});
	});
}

describe('Gate, HashML-DSA prehashed sigGen byte-equality', () => {
	runSigGenSuite('ML-DSA-44', ml_dsa_44_siggen, MLDSA44);
	runSigGenSuite('ML-DSA-65', ml_dsa_65_siggen, MLDSA65);
	runSigGenSuite('ML-DSA-87', ml_dsa_87_siggen, MLDSA87);
});

// ── Gate, ACVP sigVer verdicts through verifyHashPrehashed ─────────────────
// GATE: feeding the externally-computed PH plus (pk, σ, ph, ctx) from
// each preHash sigVer vector must return v.testPassed, including the
// known-fail cases.

function runSigVerSuite(name: string, vectors: SigVerVector[]): void {
	const sub = vectors.filter(hashSigVerFilter);
	describe(name, () => {
		it.each(sub)('tcId=$tcId hashAlg=$hashAlg reason=$reason', (v: SigVerVector) => {
			const pk  = hexToBytes(v.pk);
			const sig = hexToBytes(v.signature);
			const M   = hexToBytes(v.message ?? '');
			const ctx = v.context ? hexToBytes(v.context) : new Uint8Array(0);
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

describe('Gate, HashML-DSA prehashed sigVer verdicts', () => {
	runSigVerSuite('ML-DSA-44', ml_dsa_44_sigver);
	runSigVerSuite('ML-DSA-65', ml_dsa_65_sigver);
	runSigVerSuite('ML-DSA-87', ml_dsa_87_sigver);
});

// ── Hedged variant round-trip per (paramSet, prehash) ──────────────────────
// signHashPrehashed cannot byte-compare (rnd is fresh each call) so we
// roundtrip through verifyHashPrehashed instead.

describe('Hedged signHashPrehashed → verifyHashPrehashed round-trip', () => {
	const cases = [
		{ name: 'ML-DSA-44', make: () => new MlDsa44() },
		{ name: 'ML-DSA-65', make: () => new MlDsa65() },
		{ name: 'ML-DSA-87', make: () => new MlDsa87() },
	];

	for (const { name, make } of cases) {
		describe(name, () => {
			for (const ph of ALL_PREHASH) {
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
// Same (sk, M, ph, ctx, rnd=zeros) drives the same Sign_internal call;
// signHashDeterministic and signHashPrehashedDeterministic must produce
// byte-identical output.

describe('Equivalence: signHashDeterministic ↔ signHashPrehashedDeterministic', () => {
	const cases: { name: string; make: () => MlDsa44 | MlDsa65 | MlDsa87 }[] = [
		{ name: 'ML-DSA-44', make: () => new MlDsa44() },
		{ name: 'ML-DSA-65', make: () => new MlDsa65() },
		{ name: 'ML-DSA-87', make: () => new MlDsa87() },
	];

	for (const { name, make } of cases) {
		for (const ph of ALL_PREHASH) {
			it(`${name} ph=${ph}`, () => {
				const dsa = make();
				try {
					const { signingKey, verificationKey } = dsa.keygen();
					const msg = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
					const ctx = new Uint8Array([0x42]);
					const PH  = computePh(ph, msg);
					const sigA = dsa.signHashDeterministic(signingKey, msg, ph, ctx);
					const sigB = dsa.signHashPrehashedDeterministic(signingKey, PH, ph, ctx);
					expect(bytesToHex(sigA)).toBe(bytesToHex(sigB));
					expect(dsa.verifyHashPrehashed(verificationKey, PH, sigA, ph, ctx)).toBe(true);
					// Cross-API: signature produced via the prehashed path
					// also verifies via the non-prehashed verifyHash.
					expect(dsa.verifyHash(verificationKey, msg, sigB, ph, ctx)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});
		}
	}
});

// ── validateDigest: sign throws, verify returns false ──────────────────────

describe('signHashPrehashed* throws SigningError on wrong-size digest', () => {
	it('signHashPrehashed throws on short digest', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			const bad = new Uint8Array(16);   // SHA2-256 expects 32
			expect(() => dsa.signHashPrehashed(signingKey, bad, 'SHA2-256'))
				.toThrow(SigningError);
			expect(() => dsa.signHashPrehashed(signingKey, bad, 'SHA2-256'))
				.toThrow(/sig-malformed-input|digest length/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashPrehashedDeterministic throws on long digest', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			const bad = new Uint8Array(128);   // SHAKE128 expects 32
			expect(() => dsa.signHashPrehashedDeterministic(signingKey, bad, 'SHAKE128'))
				.toThrow(SigningError);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashPrehashedDerand throws on wrong-size digest', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			const bad = new Uint8Array(31);   // SHA3-256 expects 32
			expect(() => dsa.signHashPrehashedDerand(
				signingKey, bad, 'SHA3-256', new Uint8Array(32),
			)).toThrow(SigningError);
		} finally {
			dsa.dispose();
		}
	});

	it('SigningError carries the sig-malformed-input discriminator', () => {
		const dsa = new MlDsa44();
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
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(16),   // SHA2-256 expects 32
				new Uint8Array(MLDSA44.sigBytes),
				'SHA2-256',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('long digest → false', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(96),   // SHAKE256 expects 64
				new Uint8Array(MLDSA44.sigBytes),
				'SHAKE256',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('non-Uint8Array digest → false', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHashPrehashed(
				verificationKey,
				null as unknown as Uint8Array,
				new Uint8Array(MLDSA44.sigBytes),
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
		const dsa = new MlDsa44();
		try {
			expect(() => dsa.signHashPrehashed(
				new Uint8Array(MLDSA44.skBytes - 1),
				new Uint8Array(32),
				'SHA2-256',
			)).toThrow(/signing key must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('signHashPrehashedDeterministic throws on oversize ctx', () => {
		const dsa = new MlDsa44();
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

	it('signHashPrehashedDerand throws on wrong-length rnd', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashPrehashedDerand(
				signingKey,
				new Uint8Array(32),
				'SHAKE128',
				new Uint8Array(31),
				new Uint8Array(0),
			)).toThrow(/rnd must be 32 bytes/);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHashPrehashed returns false on wrong-length pk', () => {
		const dsa = new MlDsa44();
		try {
			expect(dsa.verifyHashPrehashed(
				new Uint8Array(MLDSA44.pkBytes - 1),
				new Uint8Array(32),
				new Uint8Array(MLDSA44.sigBytes),
				'SHA2-256',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHashPrehashed returns false on wrong-length σ', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(64),
				new Uint8Array(MLDSA44.sigBytes - 1),
				'SHA2-512',
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHashPrehashed throws on oversize ctx', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(32),
				new Uint8Array(MLDSA44.sigBytes),
				'SHA2-256',
				new Uint8Array(256),
			)).toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('bogus prehash throws RangeError on signHashPrehashed', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashPrehashed(
				signingKey,
				new Uint8Array(32),
				'BLAKE2b' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashML-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});

	it('bogus prehash throws RangeError on verifyHashPrehashed', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(32),
				new Uint8Array(MLDSA44.sigBytes),
				'SHA2-999' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashML-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});
});
