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
import { describe, test, expect, beforeAll, afterEach } from 'vitest';
import { init, Fortuna } from '../../../src/ts/index.js';
import { SerpentGenerator } from '../../../src/ts/serpent/index.js';
import { SHA256Hash } from '../../../src/ts/sha2/index.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm });
});

function isZero(b: Uint8Array): boolean {
	for (const x of b) if (x !== 0) return false;
	return true;
}

/** Expected pool indices consumed at reseed r per Practical Cryptography §9.5.5. */
function expectedConsumedPools(r: number): Set<number> {
	const s = new Set<number>();
	for (let i = 0; i < 32; i++) {
		if ((r & ((1 << i) - 1)) === 0) s.add(i);
	}
	return s;
}

/** Fill all pools via round-robin addEntropy so each pool has data. */
function fillAllPools(f: Fortuna, rounds = 2): void {
	for (let j = 0; j < 32 * rounds; j++) {
		f.addEntropy(new Uint8Array(8));
	}
}

describe('Fortuna — pool-selection spec conformance (§9.5.5)', () => {
	let fortuna: Fortuna;

	afterEach(() => {
		try {
			if (fortuna) fortuna.stop();
		} catch { /* already disposed */ }
	});

	test('spec §9.5.5 — pool P_i consumed iff 2^i divides reseedCnt', async () => {
		// We verify reseeds 1..16, checking pools 0..4 (well within the fill range).
		// Strategy per reseed:
		//   1. Fill all pools so they hold non-zero data.
		//   2. Capture LIVE references to pool hashes immediately before get().
		//   3. Call get() to trigger exactly one reseed.
		//   4. Check which live references were wiped (now all-zero).
		//   5. Compare against the spec divisibility rule.
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		// create() already triggered reseed #1.
		const checkUpTo = 5;

		for (let r = 2; r <= 16; r++) {
			fillAllPools(fortuna);

			// Capture LIVE references to the first `checkUpTo` pool hashes.
			const liveRefs = fortuna._getPoolHash().slice(0, checkUpTo);

			const cntBefore = fortuna._getReseedCnt();
			fortuna.get(16);
			expect(fortuna._getReseedCnt()).toBe(cntBefore + 1);

			// After the reseed, consumed pool buffers are wiped (all-zero via wipe()).
			// New buffers are installed at the same array indices.
			const expected = expectedConsumedPools(r);
			for (let i = 0; i < checkUpTo; i++) {
				if (expected.has(i)) {
					expect(isZero(liveRefs[i])).toBe(true);
				}
			}
		}
	});

	test('pool 0 is consumed on every reseed (F-1 regression)', async () => {
		// Across 32 sequential reseeds, pool 0's buffer is wiped every time.
		// This is the property the F-1 bug violated.
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });

		for (let r = 0; r < 32; r++) {
			fillAllPools(fortuna);
			// Capture the LIVE reference to pool[0] right before the reseed.
			const pool0Live = fortuna._getPoolHash()[0];
			expect(isZero(pool0Live)).toBe(false); // pool has data — pre-state sanity

			const cntBefore = fortuna._getReseedCnt();
			fortuna.get(16);
			expect(fortuna._getReseedCnt()).toBe(cntBefore + 1);

			// The old pool[0] buffer must be wiped (it was consumed).
			expect(isZero(pool0Live)).toBe(true);
		}
	});
});
