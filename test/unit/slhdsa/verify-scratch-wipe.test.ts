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
// test/unit/slhdsa/verify-scratch-wipe.test.ts
//
// Verifies that wipeBuffers() zeroes the OUT, STATE, and SCRATCH regions
// after slhVerifyInternal leaves its working state behind.
//
// Verify is less secret-sensitive than sign (it touches no SK material),
// but the working state still carries Keccak sponge contents and the
// recomputed PK_FORS / digest slots. wipeBuffers() discipline applies
// uniformly across all three entry points.

import { describe, it, expect, beforeAll } from 'vitest';
import { loadSlhdsa, exports_, mem } from './helpers.js';

beforeAll(async () => {
	await loadSlhdsa();
});

function regionIsZero(buf: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (buf[off + i] !== 0) return false;
	return true;
}

function regionHasNonZero(buf: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (buf[off + i] !== 0) return true;
	return false;
}

interface Plan {
	readonly label: string;
	readonly n: number;
	readonly pkBytes: number;
	readonly skBytes: number;
	readonly sigBytes: number;
	readonly setter: () => void;
}

const PLANS: readonly Plan[] = [
	{ label: '128f', n: 16, pkBytes: 32, skBytes: 64,  sigBytes: 17088, setter: () => exports_().slhSetParams128f() },
	{ label: '192f', n: 24, pkBytes: 48, skBytes: 96,  sigBytes: 35664, setter: () => exports_().slhSetParams192f() },
	{ label: '256f', n: 32, pkBytes: 64, skBytes: 128, sigBytes: 49856, setter: () => exports_().slhSetParams256f() },
];

/** Produce a (pk, M, sig) tuple via keygen + sign, then return them. */
function genKeyPairAndSig(p: Plan): { pk: Uint8Array, M: Uint8Array, sig: Uint8Array } {
	const x = exports_();
	const m = mem();
	p.setter();

	const inOff  = x.getInputOffset();
	const outOff = x.getOutOffset();

	// keygen
	m.fill(0x21, inOff,            inOff + p.n);
	m.fill(0x32, inOff + p.n,      inOff + p.n * 2);
	m.fill(0x43, inOff + p.n * 2,  inOff + p.n * 3);
	x.slhKeygenInternal();
	const sk = m.slice(outOff, outOff + p.skBytes);
	const pk = m.slice(outOff + p.skBytes, outOff + p.skBytes + p.pkBytes);

	// sign with deterministic opt_rand
	const M = new Uint8Array(8).fill(0xCC);
	m.set(sk, inOff);
	m.set(M,  inOff + p.skBytes);
	m.set(sk.slice(p.n * 2, p.n * 3), inOff + p.skBytes + M.length);
	x.slhSignInternal(M.length);
	const sig = m.slice(outOff, outOff + p.sigBytes);

	return { pk, M, sig };
}

describe('slhVerifyInternal scratch-wipe (FIPS 205 §9.3)', () => {
	for (const plan of PLANS) {
		const { label } = plan;

		it(`${label}: STATE/SCRATCH non-zero after verify, fully zero after wipe`, () => {
			const x = exports_();
			const m = mem();
			const { pk, M, sig } = genKeyPairAndSig(plan);

			// Stage verify input: pk || M || sig
			const inOff = x.getInputOffset();
			m.set(pk, inOff);
			m.set(M,  inOff + plan.pkBytes);
			m.set(sig, inOff + plan.pkBytes + M.length);

			const ok = x.slhVerifyInternal(M.length);
			expect(ok).toBe(1);

			// STATE holds the recomputed digest / PK_FORS; SCRATCH holds the
			// last Keccak sponge state. At least one of them must be non-zero.
			expect(
				regionHasNonZero(m, x.getStateOffset(),   1024) ||
				regionHasNonZero(m, x.getScratchOffset(), 256),
			).toBe(true);

			x.wipeBuffers();
			expect(regionIsZero(m, x.getOutOffset(),     52 * 1024)).toBe(true);
			expect(regionIsZero(m, x.getStateOffset(),    4 * 1024)).toBe(true);
			expect(regionIsZero(m, x.getScratchOffset(),  8 * 1024)).toBe(true);
		});

		it(`${label}: pre-dirtied OUT/STATE/SCRATCH are zeroed after wipe`, () => {
			const x = exports_();
			const m = mem();
			const { pk, M, sig } = genKeyPairAndSig(plan);

			// Poison must avoid STATE bytes 0..47 (ADRS + PARAMS slot).
			m.fill(0x33, x.getOutOffset(),         x.getOutOffset()     + 1024);
			m.fill(0x44, x.getStateOffset() + 48,  x.getStateOffset()   + 256 + 48);
			m.fill(0x55, x.getScratchOffset(),     x.getScratchOffset() + 256);
			// Re-set params after the poison stripe.
			plan.setter();

			const inOff = x.getInputOffset();
			m.set(pk, inOff);
			m.set(M,  inOff + plan.pkBytes);
			m.set(sig, inOff + plan.pkBytes + M.length);
			x.slhVerifyInternal(M.length);
			x.wipeBuffers();

			expect(regionIsZero(m, x.getOutOffset(),     52 * 1024)).toBe(true);
			expect(regionIsZero(m, x.getStateOffset(),    4 * 1024)).toBe(true);
			expect(regionIsZero(m, x.getScratchOffset(),  8 * 1024)).toBe(true);
		});
	}
});
