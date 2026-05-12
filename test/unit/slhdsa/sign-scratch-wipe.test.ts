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
// test/unit/slhdsa/sign-scratch-wipe.test.ts
//
// Verifies that wipeBuffers() zeroes the OUT, STATE, and SCRATCH regions
// after slhSignInternal leaves its working state behind.
//
// FIPS 205 sign drives FORS sign + hypertree sign + many SHAKE256 calls.
// STATE accumulates FORS auth scratch, WOTS+ chains, XMSS pair stacks,
// hypertree intermediate roots, and the digest / PK_FORS slots from slh.ts.
// SCRATCH holds the embedded Keccak sponge state. Both are dirty after
// signing and must be zeroed on wipeBuffers().

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
	readonly n:     number;
	readonly skBytes: number;
	readonly sigBytes: number;
	readonly setter: () => void;
}

const PLANS: readonly Plan[] = [
	{ label: '128f', n: 16, skBytes: 64,  sigBytes: 17088, setter: () => exports_().slhSetParams128f() },
	{ label: '192f', n: 24, skBytes: 96,  sigBytes: 35664, setter: () => exports_().slhSetParams192f() },
	{ label: '256f', n: 32, skBytes: 128, sigBytes: 49856, setter: () => exports_().slhSetParams256f() },
];

/** Build a known SK by running keygen first, then leave it staged in INPUT
 *  followed by a small M and a fixed opt_rand. Returns the input layout's
 *  total size in bytes for downstream tests that need it. */
function setupSignInput(p: Plan): void {
	const x = exports_();
	const m = mem();
	p.setter();

	// Build a fresh SK via keygen with deterministic seeds.
	const inOff  = x.getInputOffset();
	const outOff = x.getOutOffset();
	m.fill(0x21, inOff,            inOff + p.n);          // SK.seed
	m.fill(0x32, inOff + p.n,      inOff + p.n * 2);      // SK.prf
	m.fill(0x43, inOff + p.n * 2,  inOff + p.n * 3);      // PK.seed
	x.slhKeygenInternal();

	// Copy SK from OUT to INPUT (first 4·n bytes), then append M and opt_rand.
	const sk = m.slice(outOff, outOff + p.skBytes);
	m.set(sk, inOff);
	const M = new Uint8Array(8).fill(0x55);
	m.set(M, inOff + p.skBytes);
	// opt_rand = PK.seed (deterministic mode per FIPS 205 §3.4)
	m.set(sk.slice(p.n * 2, p.n * 3), inOff + p.skBytes + M.length);
}

describe('slhSignInternal scratch-wipe (FIPS 205 §9.2)', () => {
	for (const plan of PLANS) {
		const { label, sigBytes } = plan;

		it(`${label}: OUT non-zero after sign, fully zero after wipe`, () => {
			const x = exports_();
			const m = mem();
			setupSignInput(plan);
			x.slhSignInternal(8);

			// Signature lives at OUT_OFFSET, sigBytes long.
			expect(regionHasNonZero(m, x.getOutOffset(), sigBytes)).toBe(true);

			x.wipeBuffers();
			expect(regionIsZero(m, x.getOutOffset(),     52 * 1024)).toBe(true);
			expect(regionIsZero(m, x.getStateOffset(),    4 * 1024)).toBe(true);
			expect(regionIsZero(m, x.getScratchOffset(),  8 * 1024)).toBe(true);
		});

		it(`${label}: pre-dirtied STATE/SCRATCH are zeroed after wipe`, () => {
			const x = exports_();
			const m = mem();
			setupSignInput(plan);

			// Stripe a poison pattern across STATE and SCRATCH; sign will
			// overwrite parts during the run, wipe must zero the rest.
			// Poison must avoid STATE bytes 0..47 (ADRS + PARAMS slot) so the
			// param-set readout the sign flow performs stays consistent.
			m.fill(0x5a, x.getStateOffset() + 48,  x.getStateOffset()   + 256 + 48);
			m.fill(0xa5, x.getScratchOffset(),     x.getScratchOffset() + 256);
			// Re-set params after the poison stripe in case any was overwritten.
			plan.setter();

			x.slhSignInternal(8);
			x.wipeBuffers();

			expect(regionIsZero(m, x.getStateOffset(),   4 * 1024)).toBe(true);
			expect(regionIsZero(m, x.getScratchOffset(), 8 * 1024)).toBe(true);
		});
	}
});
