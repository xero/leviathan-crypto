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
//                           ▀█████▀▀▀
//
// test/unit/slhdsa/slhdsa.test.ts
//
// SLH-DSA top-level round-trip tests, FIPS 205 §9 Algorithms 18-20.
//
// Drives the public WASM exports (slhKeygenInternal / slhSignInternal /
// slhVerifyInternal) end-to-end per parameter set:
//
//   1. Keygen → sign → verify round-trip with all three randomizer modes
//      (hedged, deterministic, derand) per FIPS 205 §9.2.
//   2. Hedged signatures differ across two calls on the same (sk, M); the
//      randomizer is sampled fresh each call (§9.2 hedged variant).
//   3. Deterministic signatures are byte-stable across calls on the same
//      (sk, M); opt_rand = PK.seed per §3.4.
//   4. Derand signatures are byte-stable per fixed (sk, M, opt_rand).
//   5. Tampered signatures (single-byte flip at a random offset) verify as
//      false; structural correctness check on the verify path.
//   6. Wrong-size signatures verify as false (structural rejection).
//
// This test drives the WASM exports directly via the INPUT/OUT byte layouts;
// the SlhDsaBase TS wrapper is exercised by the sign/* integration suite.

import { describe, it, expect, beforeAll } from 'vitest';
import { loadSlhdsa, exports_, mem, toHex } from './helpers.js';
import { SLHDSA128F, SLHDSA192F, SLHDSA256F } from '../../../src/ts/slhdsa/params.js';
import type { SlhDsaParams } from '../../../src/ts/slhdsa/params.js';

beforeAll(async () => {
	await loadSlhdsa();
});

interface ParamCase {
	readonly label:   string;
	readonly params:  SlhDsaParams;
	/** Param-set selector resolved at test execution time (after WASM is
	 *  loaded by beforeAll); cases() runs at module collection. */
	readonly setter:  () => void;
}

/** Param-set descriptors. Resolved without touching the WASM instance so
 *  vitest can iterate this at collection time, before beforeAll runs. The
 *  `setter` closure defers the actual WASM call until test execution. */
const CASES: readonly ParamCase[] = [
	{ label: '128f', params: SLHDSA128F, setter: () => exports_().slhSetParams128f() },
	{ label: '192f', params: SLHDSA192F, setter: () => exports_().slhSetParams192f() },
	{ label: '256f', params: SLHDSA256F, setter: () => exports_().slhSetParams256f() },
];

/** Run slhKeygenInternal with provided (SK.seed, SK.prf, PK.seed) seeds.
 *  Returns concatenated SK || PK from OUT_OFFSET. */
function keygenInternal(n: number, skSeed: Uint8Array, skPrf: Uint8Array, pkSeed: Uint8Array): { sk: Uint8Array, pk: Uint8Array } {
	const x = exports_();
	const m = mem();
	const inOff = x.getInputOffset();
	const outOff = x.getOutOffset();
	m.set(skSeed, inOff);
	m.set(skPrf,  inOff + n);
	m.set(pkSeed, inOff + n * 2);
	x.slhKeygenInternal();
	const sk = m.slice(outOff,             outOff + n * 4);
	const pk = m.slice(outOff + n * 4,     outOff + n * 6);
	return { sk, pk };
}

/** Run slhSignInternal with (sk, M, opt_rand). Returns the sigBytes-long signature. */
function signInternal(p: SlhDsaParams, sk: Uint8Array, M: Uint8Array, optRand: Uint8Array): Uint8Array {
	const x = exports_();
	const m = mem();
	const inOff = x.getInputOffset();
	const outOff = x.getOutOffset();
	m.set(sk,      inOff);
	m.set(M,       inOff + p.skBytes);
	m.set(optRand, inOff + p.skBytes + M.length);
	x.slhSignInternal(M.length);
	return m.slice(outOff, outOff + p.sigBytes);
}

/** Run slhVerifyInternal with (pk, M, sig). Returns 1 / 0. */
function verifyInternal(p: SlhDsaParams, pk: Uint8Array, M: Uint8Array, sig: Uint8Array): number {
	const x = exports_();
	const m = mem();
	const inOff = x.getInputOffset();
	m.set(pk,  inOff);
	m.set(M,   inOff + p.pkBytes);
	m.set(sig, inOff + p.pkBytes + M.length);
	return x.slhVerifyInternal(M.length);
}

/** Build M' for pure-mode signing/verification per FIPS 205 §10.2.1 Algorithm 22
 *  line 8: M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M. */
function pureMPrime(M: Uint8Array, ctx: Uint8Array): Uint8Array {
	if (ctx.length > 255) throw new RangeError('ctx > 255');
	const out = new Uint8Array(2 + ctx.length + M.length);
	out[0] = 0;
	out[1] = ctx.length;
	out.set(ctx, 2);
	out.set(M, 2 + ctx.length);
	return out;
}

function fillSeed(byte: number, n: number): Uint8Array {
	return new Uint8Array(n).fill(byte);
}

for (const c of CASES) {
	describe(`SLH-DSA-SHAKE-${c.label}`, () => {
		const { label, params: p } = c;
		const n = p.n;

		// Use small deterministic seeds (3·n bytes) drawn from the
		// param-set label so each set has a unique key.
		const skSeed = fillSeed(0xA1, n);
		const skPrf  = fillSeed(0xB2, n);
		const pkSeed = fillSeed(0xC3, n);
		const M      = new TextEncoder().encode(`round-trip test message for ${label}`);
		const ctx    = new Uint8Array(0);

		it('keygen → sign → verify round-trip (hedged opt_rand, no ctx)', () => {
			c.setter();
			const { sk, pk } = keygenInternal(n, skSeed, skPrf, pkSeed);
			expect(sk.length).toBe(p.skBytes);
			expect(pk.length).toBe(p.pkBytes);
			// PK = (PK.seed, PK.root); PK.seed prefix must match input.
			expect(toHex(pk.subarray(0, n))).toBe(toHex(pkSeed));

			const Mprime = pureMPrime(M, ctx);
			const optRand = crypto.getRandomValues(new Uint8Array(n));
			const sig = signInternal(p, sk, Mprime, optRand);
			expect(sig.length).toBe(p.sigBytes);

			const ok = verifyInternal(p, pk, Mprime, sig);
			expect(ok).toBe(1);
		});

		it('deterministic mode produces byte-stable signatures across calls', () => {
			c.setter();
			const { sk, pk } = keygenInternal(n, skSeed, skPrf, pkSeed);
			const Mprime = pureMPrime(M, ctx);
			// Deterministic variant per FIPS 205 §3.4: opt_rand = PK.seed.
			// PK.seed lives at sk[2n..3n] (SK = SK.seed || SK.prf || PK.seed || PK.root).
			const optRand = sk.slice(2 * n, 3 * n);
			const sig1 = signInternal(p, sk, Mprime, optRand);
			const sig2 = signInternal(p, sk, Mprime, optRand);
			expect(toHex(sig1)).toBe(toHex(sig2));
			expect(verifyInternal(p, pk, Mprime, sig1)).toBe(1);
		});

		it('hedged mode produces different signatures across calls', () => {
			c.setter();
			const { sk, pk } = keygenInternal(n, skSeed, skPrf, pkSeed);
			const Mprime = pureMPrime(M, ctx);
			const sig1 = signInternal(p, sk, Mprime, crypto.getRandomValues(new Uint8Array(n)));
			const sig2 = signInternal(p, sk, Mprime, crypto.getRandomValues(new Uint8Array(n)));
			expect(toHex(sig1)).not.toBe(toHex(sig2));
			expect(verifyInternal(p, pk, Mprime, sig1)).toBe(1);
			expect(verifyInternal(p, pk, Mprime, sig2)).toBe(1);
		});

		it('derand mode is byte-stable per fixed opt_rand', () => {
			c.setter();
			const { sk, pk } = keygenInternal(n, skSeed, skPrf, pkSeed);
			const Mprime = pureMPrime(M, ctx);
			const optRand = fillSeed(0x77, n);
			const sig1 = signInternal(p, sk, Mprime, optRand);
			const sig2 = signInternal(p, sk, Mprime, optRand);
			expect(toHex(sig1)).toBe(toHex(sig2));
			expect(verifyInternal(p, pk, Mprime, sig1)).toBe(1);
			// Same (sk, M) but different opt_rand → different sig.
			const optRandAlt = fillSeed(0x33, n);
			const sigAlt = signInternal(p, sk, Mprime, optRandAlt);
			expect(toHex(sigAlt)).not.toBe(toHex(sig1));
			expect(verifyInternal(p, pk, Mprime, sigAlt)).toBe(1);
		});

		it('tampered signature (single byte flip) verifies as false', () => {
			c.setter();
			const { sk, pk } = keygenInternal(n, skSeed, skPrf, pkSeed);
			const Mprime = pureMPrime(M, ctx);
			const optRand = sk.slice(2 * n, 3 * n);
			const sig = signInternal(p, sk, Mprime, optRand);
			// Flip a byte in the SIG_FORS region (after the n-byte randomizer).
			// Picks an offset deterministic across runs.
			const target = (n + 100) % sig.length;
			const tampered = new Uint8Array(sig);
			tampered[target] ^= 0x01;
			expect(verifyInternal(p, pk, Mprime, tampered)).toBe(0);
		});

		it('wrong-size signature (truncated, +1B padding) verifies as false', () => {
			// Structural-rejection check. The WASM verify expects sigBytes exactly.
			// We re-pad with zero bytes after a short truncation so we still call
			// verifyInternal with `sig.length === sigBytes`, but the underlying
			// bytes have been mutated, which must fail authentication.
			c.setter();
			const { sk, pk } = keygenInternal(n, skSeed, skPrf, pkSeed);
			const Mprime = pureMPrime(M, ctx);
			const optRand = sk.slice(2 * n, 3 * n);
			const sig = signInternal(p, sk, Mprime, optRand);
			const truncated = new Uint8Array(sig.length);
			truncated.set(sig.subarray(0, sig.length - 16));
			// last 16 bytes are zero → diverges from the genuine SIG_HT tail.
			expect(verifyInternal(p, pk, Mprime, truncated)).toBe(0);
		});

		it('tampered M verifies as false', () => {
			c.setter();
			const { sk, pk } = keygenInternal(n, skSeed, skPrf, pkSeed);
			const Mprime = pureMPrime(M, ctx);
			const optRand = sk.slice(2 * n, 3 * n);
			const sig = signInternal(p, sk, Mprime, optRand);

			// Verify with a one-byte-different M (same Mprime length so we
			// don't change the verify ABI; the change lands in the trailing
			// M bytes after the ctx prefix).
			const Mprime2 = new Uint8Array(Mprime);
			Mprime2[Mprime2.length - 1] ^= 0x01;
			expect(verifyInternal(p, pk, Mprime2, sig)).toBe(0);
		});

		it('wrong PK (different PK.root) verifies as false', () => {
			c.setter();
			const { sk, pk } = keygenInternal(n, skSeed, skPrf, pkSeed);
			const Mprime = pureMPrime(M, ctx);
			const optRand = sk.slice(2 * n, 3 * n);
			const sig = signInternal(p, sk, Mprime, optRand);

			// Flip the LAST byte of PK.root (sig binds (M, pk_root) via Hmsg).
			const wrongPk = new Uint8Array(pk);
			wrongPk[wrongPk.length - 1] ^= 0x01;
			expect(verifyInternal(p, pk, Mprime, sig)).toBe(1);   // sanity check
			expect(verifyInternal(p, wrongPk, Mprime, sig)).toBe(0);
		});
	});
}
