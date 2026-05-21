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
 * SLH-DSA ACVP vector replay (FIPS 205).
 *
 * Drives the curated NIST ACVP-Server subset (15 keygen + 39 sigGen +
 * 27 sigVer = 81 cases) through the WASM internal entry points and
 * asserts byte-for-byte equality with the published expected outputs.
 *
 * For sigGen / sigVer the test must construct the M' that
 * slh_sign_internal / slh_verify_internal consumes per the
 * (signatureInterface, preHash) discriminator from the ACVP vector:
 *
 *   external/pure    → M' = 0x00 ‖ |ctx| ‖ ctx ‖ M             (FIPS 205 §10.2.1 Algorithm 22)
 *   external/preHash → M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ PH_M    (FIPS 205 §10.2.2 Algorithm 23)
 *   internal/none    → M' = M                                  (FIPS 205 §9 raw entry)
 *
 * PreHash digests come from node:crypto for SHA-2 / SHA-3 / SHAKE
 * families (independent of the slhdsa WASM, so this isn't a self-check).
 *
 * Source: NIST ACVP SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205, vsId=53.
 * Pin: ACVP-Server 15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0
 *      (v1.1.0.42, 2026-04-16). See test/vectors/README.md.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';

import { loadSlhdsa, exports_, mem } from './helpers.js';
import { SLHDSA128F, SLHDSA192F, SLHDSA256F } from '../../../src/ts/slhdsa/params.js';
import type { SlhDsaParams } from '../../../src/ts/slhdsa/params.js';
import {
	slh_dsa_128f_keygen,
	slh_dsa_192f_keygen,
	slh_dsa_256f_keygen,
} from '../../vectors/slhdsa_keygen.js';
import {
	slh_dsa_128f_siggen,
	slh_dsa_192f_siggen,
	slh_dsa_256f_siggen,
} from '../../vectors/slhdsa_siggen.js';
import {
	slh_dsa_128f_sigver,
	slh_dsa_192f_sigver,
	slh_dsa_256f_sigver,
} from '../../vectors/slhdsa_sigver.js';

// Curated counts: 5 keygen + 13 sigGen + 9 sigVer per parameter set.
// Totals 81 across 128f / 192f / 256f.
const EXPECTED = {
	keygenPerSet: 5,
	siggenPerSet: 13,   // 5 pure-det + 5 pure-hedged + 3 preHash-det
	sigverPerSet: 9,    // 2 pure-pass + 3 pure-fail + 2 preHash-pass + 2 preHash-fail
} as const;

function hex(s: string): Uint8Array {
	const b = new Uint8Array(s.length / 2);
	for (let i = 0; i < b.length; i++) b[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
	return b;
}

function toHex(b: Uint8Array): string {
	return Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
}

function hexLen(s: string): number {
	return s.length / 2;
}

beforeAll(async () => {
	await loadSlhdsa();
});

describe('SLH-DSA ACVP vectors (FIPS 205), load + shape gate', () => {
	it('keygen arrays carry the curated count per parameter set', () => {
		expect(slh_dsa_128f_keygen.length).toBe(EXPECTED.keygenPerSet);
		expect(slh_dsa_192f_keygen.length).toBe(EXPECTED.keygenPerSet);
		expect(slh_dsa_256f_keygen.length).toBe(EXPECTED.keygenPerSet);
	});

	it('siggen arrays carry the curated count per parameter set', () => {
		expect(slh_dsa_128f_siggen.length).toBe(EXPECTED.siggenPerSet);
		expect(slh_dsa_192f_siggen.length).toBe(EXPECTED.siggenPerSet);
		expect(slh_dsa_256f_siggen.length).toBe(EXPECTED.siggenPerSet);
	});

	it('sigver arrays carry the curated count per parameter set', () => {
		expect(slh_dsa_128f_sigver.length).toBe(EXPECTED.sigverPerSet);
		expect(slh_dsa_192f_sigver.length).toBe(EXPECTED.sigverPerSet);
		expect(slh_dsa_256f_sigver.length).toBe(EXPECTED.sigverPerSet);
	});

	// Per FIPS 205 §11.1 Table 2 + §11.2 / §9:
	//   pk = 2·n bytes, sk = 4·n bytes, sig = sigBytes per Table 2
	const sets: [string, SlhDsaParams, typeof slh_dsa_128f_keygen, typeof slh_dsa_128f_siggen, typeof slh_dsa_128f_sigver][] = [
		['128f', SLHDSA128F, slh_dsa_128f_keygen, slh_dsa_128f_siggen, slh_dsa_128f_sigver],
		['192f', SLHDSA192F, slh_dsa_192f_keygen, slh_dsa_192f_siggen, slh_dsa_192f_sigver],
		['256f', SLHDSA256F, slh_dsa_256f_keygen, slh_dsa_256f_siggen, slh_dsa_256f_sigver],
	];

	for (const [label, params, kg, sg, sv] of sets) {
		it(`${label}: keygen seed + key encodings match FIPS 205 sizes`, () => {
			for (const v of kg) {
				expect(hexLen(v.skSeed)).toBe(params.n);
				expect(hexLen(v.skPrf)).toBe(params.n);
				expect(hexLen(v.pkSeed)).toBe(params.n);
				expect(hexLen(v.pk)).toBe(params.pkBytes);
				expect(hexLen(v.sk)).toBe(params.skBytes);
			}
		});

		it(`${label}: siggen sk/pk/signature lengths match FIPS 205 sizes`, () => {
			for (const v of sg) {
				expect(v.parameterSet).toBe(params.paramSet);
				expect(hexLen(v.sk)).toBe(params.skBytes);
				expect(hexLen(v.pk)).toBe(params.pkBytes);
				expect(hexLen(v.signature)).toBe(params.sigBytes);
				if (!v.deterministic) {
					expect(v.additionalRandomness).toBeDefined();
					expect(hexLen(v.additionalRandomness!)).toBe(params.n);
				}
			}
		});

		it(`${label}: sigver pk/signature lengths match FIPS 205 sizes`, () => {
			// sigVer fail-cases legitimately include length-mutated signatures
			// (reason "invalid signature - too large" / "too small" in the
			// ACVP corpus). Restrict the signature-length assertion to
			// expected-pass cases; sigBytes is a fixed-length contract for
			// well-formed signatures only.
			for (const v of sv) {
				expect(v.parameterSet).toBe(params.paramSet);
				expect(hexLen(v.pk)).toBe(params.pkBytes);
				if (v.testPassed) {
					expect(hexLen(v.signature)).toBe(params.sigBytes);
				}
			}
		});
	}
});

// ─── HashSLH-DSA prehash table (FIPS 205 §10.2.2 + FIPS 204 §5.4.1 Table 1) ──
// OID DER prefix: 06 09 60 86 48 01 65 03 04 02 NN. PH_M output length is
// fixed per hash function (SHAKE128 / SHAKE256 produce 32 / 64 bytes per FIPS
// 205 §10.2.2 Algorithm 23). digestForACVP returns the (oid, ph_m) pair so
// callers can splice them into M' verbatim.
interface PreHashSpec {
	readonly oid:  Uint8Array;
	readonly hash: (m: Uint8Array) => Uint8Array;
}

const PREHASHES: Record<string, PreHashSpec> = {
	'SHA2-224': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04]),
		hash: (m) => new Uint8Array(createHash('sha224').update(m).digest()),
	},
	'SHA2-256': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
		hash: (m) => new Uint8Array(createHash('sha256').update(m).digest()),
	},
	'SHA2-384': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]),
		hash: (m) => new Uint8Array(createHash('sha384').update(m).digest()),
	},
	'SHA2-512': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]),
		hash: (m) => new Uint8Array(createHash('sha512').update(m).digest()),
	},
	'SHA2-512/224': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05]),
		hash: (m) => new Uint8Array(createHash('sha512-224').update(m).digest()),
	},
	'SHA2-512/256': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06]),
		hash: (m) => new Uint8Array(createHash('sha512-256').update(m).digest()),
	},
	'SHA3-224': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07]),
		hash: (m) => new Uint8Array(createHash('sha3-224').update(m).digest()),
	},
	'SHA3-256': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08]),
		hash: (m) => new Uint8Array(createHash('sha3-256').update(m).digest()),
	},
	'SHA3-384': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09]),
		hash: (m) => new Uint8Array(createHash('sha3-384').update(m).digest()),
	},
	'SHA3-512': {
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A]),
		hash: (m) => new Uint8Array(createHash('sha3-512').update(m).digest()),
	},
	'SHAKE-128': {
		// FIPS 205 §10.2.2 Algorithm 23: PH_M = SHAKE128(M, 256) → 32 bytes.
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B]),
		hash: (m) => new Uint8Array(createHash('shake128', { outputLength: 32 }).update(m).digest()),
	},
	'SHAKE-256': {
		// FIPS 205 §10.2.2 Algorithm 23: PH_M = SHAKE256(M, 512) → 64 bytes.
		oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C]),
		hash: (m) => new Uint8Array(createHash('shake256', { outputLength: 64 }).update(m).digest()),
	},
};

/** Build M' per FIPS 205 §10 for the given (signatureInterface, preHash). */
function buildMPrime(
	signatureInterface: string, preHash: string, hashAlg: string,
	message: Uint8Array, ctx: Uint8Array,
): Uint8Array {
	if (ctx.length > 255) throw new RangeError('ctx > 255');

	if (signatureInterface === 'internal') {
		return message;
	}
	if (signatureInterface === 'external' && preHash === 'pure') {
		// FIPS 205 §10.2.1 Algorithm 22 line 8.
		const out = new Uint8Array(2 + ctx.length + message.length);
		out[0] = 0;
		out[1] = ctx.length;
		out.set(ctx, 2);
		out.set(message, 2 + ctx.length);
		return out;
	}
	if (signatureInterface === 'external' && preHash === 'preHash') {
		// FIPS 205 §10.2.2 Algorithm 23 line 24.
		const spec = PREHASHES[hashAlg];
		if (!spec) throw new Error(`unsupported hashAlg ${hashAlg}`);
		const ph_m = spec.hash(message);
		const out  = new Uint8Array(2 + ctx.length + spec.oid.length + ph_m.length);
		out[0] = 1;
		out[1] = ctx.length;
		out.set(ctx, 2);
		out.set(spec.oid, 2 + ctx.length);
		out.set(ph_m, 2 + ctx.length + spec.oid.length);
		return out;
	}
	throw new Error(`unsupported (sigInt=${signatureInterface}, preHash=${preHash})`);
}

interface ParamCtx {
	readonly label:   string;
	readonly params:  SlhDsaParams;
	readonly setter:  () => void;
}

const PARAMS: readonly ParamCtx[] = [
	{ label: '128f', params: SLHDSA128F, setter: () => exports_().slhSetParams128f() },
	{ label: '192f', params: SLHDSA192F, setter: () => exports_().slhSetParams192f() },
	{ label: '256f', params: SLHDSA256F, setter: () => exports_().slhSetParams256f() },
];

const KEYGEN_VECTORS = {
	'128f': slh_dsa_128f_keygen, '192f': slh_dsa_192f_keygen, '256f': slh_dsa_256f_keygen,
};
const SIGGEN_VECTORS = {
	'128f': slh_dsa_128f_siggen, '192f': slh_dsa_192f_siggen, '256f': slh_dsa_256f_siggen,
};
const SIGVER_VECTORS = {
	'128f': slh_dsa_128f_sigver, '192f': slh_dsa_192f_sigver, '256f': slh_dsa_256f_sigver,
};

// ─── Per-vector implementation, drives the WASM internal entry points ──────

describe('SLH-DSA ACVP, keyGen', () => {
	for (const { label, params: p, setter } of PARAMS) {
		for (const v of KEYGEN_VECTORS[label as keyof typeof KEYGEN_VECTORS]) {
			it(`${label} keygen tcId=${v.tcId}: slh_keygen_internal matches ACVP sk/pk`, () => {
				const x  = exports_();
				const m  = mem();
				setter();

				const skSeed = hex(v.skSeed);
				const skPrf  = hex(v.skPrf);
				const pkSeed = hex(v.pkSeed);

				const inOff  = x.getInputOffset();
				const outOff = x.getOutOffset();
				m.set(skSeed, inOff);
				m.set(skPrf,  inOff + p.n);
				m.set(pkSeed, inOff + p.n * 2);
				x.slhKeygenInternal();

				const sk = m.slice(outOff,             outOff + p.skBytes);
				const pk = m.slice(outOff + p.skBytes, outOff + p.skBytes + p.pkBytes);

				expect(toHex(sk)).toBe(v.sk.toLowerCase());
				expect(toHex(pk)).toBe(v.pk.toLowerCase());
			});
		}
	}
});

describe('SLH-DSA ACVP, sigGen', () => {
	for (const { label, params: p, setter } of PARAMS) {
		for (const v of SIGGEN_VECTORS[label as keyof typeof SIGGEN_VECTORS]) {
			it(`${label} sigGen tcId=${v.tcId} (${v.preHash}, det=${v.deterministic}): matches ACVP signature`, () => {
				const x  = exports_();
				const m  = mem();
				setter();

				const sk      = hex(v.sk);
				const message = hex(v.message);
				const ctx     = hex(v.context);
				const expectedSig = v.signature.toLowerCase();

				const Mprime = buildMPrime(v.signatureInterface, v.preHash, v.hashAlg, message, ctx);

				// opt_rand: PK.seed for deterministic (sk[2n..3n]), else the
				// ACVP-supplied additionalRandomness.
				let optRand: Uint8Array;
				if (v.deterministic) {
					optRand = sk.slice(p.n * 2, p.n * 3);
				} else {
					if (!v.additionalRandomness) throw new Error(`hedged tcId ${v.tcId} missing additionalRandomness`);
					optRand = hex(v.additionalRandomness);
				}

				const inOff  = x.getInputOffset();
				const outOff = x.getOutOffset();
				m.set(sk,      inOff);
				m.set(Mprime,  inOff + p.skBytes);
				m.set(optRand, inOff + p.skBytes + Mprime.length);
				x.slhSignInternal(Mprime.length);

				const sig = m.slice(outOff, outOff + p.sigBytes);
				expect(toHex(sig)).toBe(expectedSig);
			});
		}
	}
});

describe('SLH-DSA ACVP, sigVer', () => {
	for (const { label, params: p, setter } of PARAMS) {
		for (const v of SIGVER_VECTORS[label as keyof typeof SIGVER_VECTORS]) {
			it(`${label} sigVer tcId=${v.tcId} (${v.preHash}) → ${v.testPassed}`, () => {
				const x  = exports_();
				const m  = mem();
				setter();

				const pk      = hex(v.pk);
				const message = hex(v.message);
				const ctx     = hex(v.context);
				const sig     = hex(v.signature);

				// Structural-length pre-check: a fail case may carry a
				// length-mutated signature. The WASM verify ABI assumes
				// |sig| === sigBytes, so any mismatch goes straight to
				// rejection without invoking the WASM.
				if (sig.length !== p.sigBytes) {
					expect(v.testPassed).toBe(false);
					return;
				}

				const Mprime = buildMPrime(v.signatureInterface, v.preHash, v.hashAlg, message, ctx);

				const inOff = x.getInputOffset();
				m.set(pk,     inOff);
				m.set(Mprime, inOff + p.pkBytes);
				m.set(sig,    inOff + p.pkBytes + Mprime.length);
				const ok = x.slhVerifyInternal(Mprime.length);

				expect(ok === 1).toBe(v.testPassed);
			});
		}
	}
});
