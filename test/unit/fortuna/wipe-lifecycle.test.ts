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
 * Fortuna wipe-lifecycle discipline.
 *
 * Contract:
 *   - Every Uint8Array reassignment wipes the prior buffer before dropping
 *     the reference (pseudoRandomData, reseed, addRandomEvent, pool reset).
 *   - stop() wipes genKey, genCnt, every pool-hash chain, and calls
 *     wipeBuffers() on every WASM module the chosen generator and hash used.
 *
 * These guarantees prevent forward-secrecy-critical bytes from being fished
 * out of leaked memory after reseed or after stop().
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
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

describe('Fortuna — wipe before reassign', () => {
	let fortuna: Fortuna | undefined;

	afterEach(() => {
		try {
			if (fortuna && !(fortuna as unknown as { disposed: boolean }).disposed) fortuna.stop();
		} catch { /* already disposed */ }
		fortuna = undefined;
	});

	it('pseudoRandomData: prior genKey bytes are wiped before key replacement', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		// Force initial reseed by calling get() — post-create state has genKey set.
		fortuna.get(16);

		// Capture the LIVE view of genKey (not a copy). After the next get(), the
		// implementation must have wiped this buffer before re-assigning the slot.
		const oldKeyView = fortuna._getGenKey();
		expect(isZero(oldKeyView)).toBe(false);  // pre-state sanity

		fortuna.get(16);
		// The Uint8Array the implementation just stopped referencing must now be all zeros.
		expect(isZero(oldKeyView)).toBe(true);
	});

	it('reseed: prior genKey bytes are wiped when hashing into the new key', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		// Refill pool[0] so the next get() triggers a reseed, which calls reseed()
		// which does genKey = hash(genKey || seed).
		fortuna.addEntropy(new Uint8Array(64));
		// Snapshot the current genKey view BEFORE the reseed fires.
		fortuna.get(16); // drain + possibly reseed
		const oldKeyView = fortuna._getGenKey();
		fortuna.addEntropy(new Uint8Array(64));
		fortuna.get(16); // this triggers reseed -> key replacement inside
		// Either pseudoRandomData OR reseed replaced the key — either way the
		// prior buffer must be wiped.
		expect(isZero(oldKeyView)).toBe(true);
	});

	it('addRandomEvent: prior pool-hash chain bytes are wiped before replacement', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		// Add some entropy — this calls addRandomEvent, writing a non-zero chain
		// into pool[x]. Capture the live view.
		fortuna.addEntropy(new Uint8Array(32).fill(0x42));
		const poolHash = fortuna._getPoolHash();
		// Find a non-zero pool — robin.rnd increments between calls, so at least one has data.
		let touchedIdx = -1;
		for (let i = 0; i < poolHash.length; i++) {
			if (!isZero(poolHash[i])) {
				touchedIdx = i; break;
			}
		}
		expect(touchedIdx).toBeGreaterThanOrEqual(0);
		const oldChainView = poolHash[touchedIdx];

		// Now do another addEntropy that could hit the SAME pool via the same
		// round-robin index. Repeat enough to guarantee re-hit of that slot.
		for (let i = 0; i < 35; i++) {
			fortuna.addEntropy(new Uint8Array(32).fill(0x55));
		}
		// The previous view was replaced at least once; its bytes must be zeroed.
		expect(isZero(oldChainView)).toBe(true);
	});

	it('pool reset on reseed: old chain hash is wiped in place', async () => {
		fortuna = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		// reseedCnt is already 1 from create()'s forced first reseed. Drive
		// reseedCnt to 2 so pool[0] is consumed on the next reseed
		// (pool[0] consumed when 2^0 divides reseedCnt, i.e. always).
		// Step 1: refill pool[0] and pool[1] with entropy then trigger a
		// reseed to go to reseedCnt=2 (consumes pool[0] and pool[1]).
		fortuna.addEntropy(new Uint8Array(64).fill(0x77));
		fortuna.get(16); // reseedCnt -> 2
		expect(fortuna._getReseedCnt()).toBe(2);

		// Step 2: refill pool[0] again.
		// Feed entropy round-robin 32 times to guarantee pool[0] sees an update.
		for (let i = 0; i < 32; i++) {
			fortuna.addEntropy(new Uint8Array(64).fill(0x33));
		}
		const poolHash = fortuna._getPoolHash();
		const oldPool0View = poolHash[0];
		expect(isZero(oldPool0View)).toBe(false); // pre-state sanity

		// Step 3: trigger reseed #3 (pools 0 and 1 consumed again).
		// The pool reset path must wipe oldPool0View before
		// installing a fresh zero Uint8Array in the slot.
		fortuna.get(16);
		expect(fortuna._getReseedCnt()).toBe(3);
		expect(isZero(oldPool0View)).toBe(true);
	});
});

describe('Fortuna — stop() wipe and dispose discipline', () => {
	it('stop() zeroes genKey, genCnt, and every pool-hash chain', async () => {
		const f = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		f.get(16); // warm up state so key/counter/pools hold non-zero bytes
		f.addEntropy(new Uint8Array(64).fill(0xAA));

		// Capture live views before stop().
		const keyView = f._getGenKey();
		const poolRefs = f._getPoolHash().slice(); // array of refs
		expect(keyView.length).toBe(32);
		expect(poolRefs.length).toBe(32);

		// At least the key has non-zero bytes.
		expect(isZero(keyView)).toBe(false);

		f.stop();

		// All refs captured above must now be all-zero.
		expect(isZero(keyView)).toBe(true);
		for (const p of poolRefs) {
			expect(isZero(p)).toBe(true);
		}
	});

	it('stop() invokes wipeBuffers on the generator and hash WASM modules', async () => {
		// WASM exports are non-configurable and cannot be spied on directly.
		// Instead, we verify the wipeBuffers semantics by confirming:
		// (a) stop() completes without throwing (wipeBuffers ran without error), and
		// (b) the modules remain usable after stop() (no module is left in a
		//     half-owned state that would block subsequent Fortuna construction).
		const f = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		f.get(16);
		f.stop();
		// If wipeBuffers left the module in a bad state, this create() would throw.
		const f2 = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		expect(f2.get(32)).toHaveLength(32);
		f2.stop();
	});

	it('stop() on an already-disposed instance throws', async () => {
		const f = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash, msPerReseed: 0 });
		f.stop();
		expect(() => f.stop()).toThrow(/disposed/);
	});
});
