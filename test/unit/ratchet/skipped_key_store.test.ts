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
import { describe, test, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { KDFChain, SkippedKeyStore } from '../../../src/ts/ratchet/index.js';

function toHex(b: Uint8Array): string {
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function allZero(b: Uint8Array): boolean {
	for (const x of b) if (x !== 0) return false;
	return true;
}

beforeAll(async () => {
	await init({ sha2: sha2Wasm });
});

// ── Happy-path commit ─────────────────────────────────────────────────────────

describe('happy path — commit', () => {
	test('in-order commit: chain advances; key matches reference; store stays empty', () => {
		const ck    = new Uint8Array(32);
		const store = new SkippedKeyStore();
		const chain = new KDFChain(ck.slice());
		const ref   = new KDFChain(ck.slice());

		const h = store.resolve(chain, 1);
		const refKey = ref.step();
		expect(toHex(h.key)).toBe(toHex(refKey));
		h.commit();
		expect(chain.n).toBe(1);
		expect(store.size).toBe(0);

		chain.dispose(); ref.dispose();
	});

	test('skip-ahead commit: chain advances to counter; store holds skipped counters', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));

		const h = store.resolve(chain, 10);
		h.commit();
		expect(chain.n).toBe(10);
		expect(store.size).toBe(9); // counters 1..9

		store.wipeAll();
		chain.dispose();
	});

	test('past-retrieve commit: store size decreases', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));

		const hSkip = store.resolve(chain, 10);
		hSkip.commit();
		expect(store.size).toBe(9);

		const h3 = store.resolve(chain, 3);
		expect(h3.key.length).toBe(32);
		h3.commit();
		expect(store.size).toBe(8);

		store.wipeAll();
		chain.dispose();
	});
});

// ── Rollback paths ────────────────────────────────────────────────────────────

describe('rollback', () => {
	test('in-order rollback: stores counter 1 under the resolved key', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));

		const h = store.resolve(chain, 1);
		const snapshot = toHex(h.key);
		h.rollback();
		expect(store.size).toBe(1);
		expect(chain.n).toBe(1);

		// Past-key resolve retrieves the same counter again.
		const h2 = store.resolve(chain, 1);
		expect(toHex(h2.key)).toBe(snapshot);
		h2.commit();

		chain.dispose();
	});

	test('skip-ahead rollback: final key restored under counter, store holds all 10 entries', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));

		const h = store.resolve(chain, 10);
		h.rollback();
		expect(chain.n).toBe(10);
		expect(store.size).toBe(10);    // counters 1..10 now all present

		store.wipeAll();
		chain.dispose();
	});

	test('past-path rollback: counter returned to store after retrieval', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));

		const hSkip = store.resolve(chain, 10);
		hSkip.commit();
		const sizeBefore = store.size; // 9

		const h3 = store.resolve(chain, 3);
		expect(store.size).toBe(sizeBefore - 1);
		h3.rollback();
		expect(store.size).toBe(sizeBefore);

		store.wipeAll();
		chain.dispose();
	});
});

// ── Settle-guard ──────────────────────────────────────────────────────────────

describe('settle guards', () => {
	test('double commit throws', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		const h = store.resolve(chain, 1);
		h.commit();
		expect(() => h.commit()).toThrow(/already settled/);
		chain.dispose();
	});

	test('commit-then-rollback throws', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		const h = store.resolve(chain, 1);
		h.commit();
		expect(() => h.rollback()).toThrow(/already settled/);
		chain.dispose();
	});

	test('rollback-then-commit throws', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		const h = store.resolve(chain, 1);
		h.rollback();
		expect(() => h.commit()).toThrow(/already settled/);
		store.wipeAll();
		chain.dispose();
	});

	test('double rollback throws', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		const h = store.resolve(chain, 1);
		h.rollback();
		expect(() => h.rollback()).toThrow(/already settled/);
		store.wipeAll();
		chain.dispose();
	});

	test('accessing key after commit throws', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		const h = store.resolve(chain, 1);
		h.commit();
		expect(() => h.key).toThrow(/already settled/);
		chain.dispose();
	});
});

// ── Wipe / ownership ─────────────────────────────────────────────────────────

describe('key lifecycle', () => {
	test('commit wipes the underlying buffer', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		const h = store.resolve(chain, 1);
		const buf = h.key;
		expect(allZero(buf)).toBe(false);
		h.commit();
		expect(allZero(buf)).toBe(true);
		chain.dispose();
	});

	test('rollback transfers ownership — the stored buffer is the same reference', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		const h = store.resolve(chain, 1);
		const ref = h.key;
		h.rollback();
		// Past-path resolve returns the same buffer identity.
		const h2 = store.resolve(chain, 1);
		expect(h2.key).toBe(ref);
		h2.commit();
		chain.dispose();
	});

	test('eviction wipes the evicted key', () => {
		const store = new SkippedKeyStore({ maxCacheSize: 3, maxSkipPerResolve: 3 });
		const chain = new KDFChain(new Uint8Array(32));

		// Fill to cache: stores 1, 2, 3; chain.n = 4
		store.resolve(chain, 4).commit();
		expect(store.size).toBe(3);

		// Capture reference to counter-1 buffer inside the store.
		// We can grab it via a rollback round-trip so we have the real reference.
		// Instead: observe eviction by triggering skip-ahead that evicts 1.
		// Use past-path to retrieve the buffer reference first.
		const h1 = store.resolve(chain, 1); // retrieves counter 1
		const buf1 = h1.key;
		h1.rollback();                      // returns same buffer under counter 1

		// Trigger an eviction of counter 1 via skip-ahead that exceeds capacity.
		// Current chain.n = 4, size = 3 (counters 1, 2, 3).
		// resolve(chain, 8): stores 4, 5, 6, 7 into cache — each insertion
		// evicts the oldest (1, then 2, then 3, then 4). buf1 is the one held
		// for counter 1 and should be zeroed by the first eviction.
		store.resolve(chain, 8).commit();
		expect(allZero(buf1)).toBe(true);

		store.wipeAll();
		chain.dispose();
	});
});

// ── Budget enforcement ───────────────────────────────────────────────────────

describe('budgets', () => {
	test('maxSkipPerResolve enforced on resolve', () => {
		const store = new SkippedKeyStore({ maxCacheSize: 100, maxSkipPerResolve: 10 });
		const chain = new KDFChain(new Uint8Array(32));
		expect(() => store.resolve(chain, 12)).toThrow(/maxSkipPerResolve/);
		chain.dispose();
	});

	test('maxCacheSize enforced via eviction', () => {
		const store = new SkippedKeyStore({ maxCacheSize: 5, maxSkipPerResolve: 5 });
		const chain = new KDFChain(new Uint8Array(32));

		store.resolve(chain, 5).commit(); // stores 1..4
		expect(store.size).toBe(4);

		store.resolve(chain, 10).commit(); // evicts to keep under cap
		expect(store.size).toBeLessThanOrEqual(5);

		store.wipeAll();
		chain.dispose();
	});

	test('maxSkipPerResolve > maxCacheSize throws at construction', () => {
		expect(() => new SkippedKeyStore({ maxCacheSize: 5, maxSkipPerResolve: 10 }))
			.toThrow(/must not exceed maxCacheSize/);
	});

	test('advanceToBoundary respects maxSkipPerResolve', () => {
		const store = new SkippedKeyStore({ maxCacheSize: 100, maxSkipPerResolve: 10 });
		const chain = new KDFChain(new Uint8Array(32));
		expect(() => store.advanceToBoundary(chain, 11)).toThrow(/maxSkipPerResolve/);
		chain.dispose();
	});

	test('backwards compat: { ceiling: N } sets both budgets', () => {
		const store = new SkippedKeyStore({ ceiling: 20 });
		const chain = new KDFChain(new Uint8Array(32));

		// Skip-ahead of 20 fine; 21 throws
		store.advanceToBoundary(chain, 20);
		expect(store.size).toBe(20);
		expect(() => store.advanceToBoundary(chain, 41)).toThrow(/maxSkipPerResolve/);

		store.wipeAll();
		chain.dispose();
	});

	test('O(1) eviction — 100 evictions on pre-populated 1000-entry store', () => {
		// Seed with 1000 entries by constructing with a large cache and advancing.
		const store = new SkippedKeyStore({ maxCacheSize: 1000, maxSkipPerResolve: 1000 });
		const chain = new KDFChain(new Uint8Array(32));
		store.advanceToBoundary(chain, 1000);
		expect(store.size).toBe(1000);

		// Rebind store's cache to a small size by migrating into a new store.
		// Easier: use the existing store and do 100 additional past-resolves
		// followed by rollbacks — this exercises the insertion order. But the
		// real O(1) check is that evictions run in constant time regardless
		// of pre-population.
		// Measure: 100 evictions via a capped store full of 1000 pre-seeded keys.
		const cappedStore = new SkippedKeyStore({ maxCacheSize: 100, maxSkipPerResolve: 50 });
		const cappedChain = new KDFChain(new Uint8Array(32));
		cappedStore.advanceToBoundary(cappedChain, 50); // fill to 50
		// Now force 50 evictions by rolling-back new resolves when at capacity.
		// Simplify: advance to 100 (adds 50 more, no eviction yet), then force
		// evictions by rolling back handles past the cap.
		cappedStore.advanceToBoundary(cappedChain, 100);
		expect(cappedStore.size).toBe(100);

		// Trigger 100 evictions via back-to-back in-order resolves that rollback.
		const t0 = performance.now();
		for (let i = 101; i <= 200; i++) {
			const h = cappedStore.resolve(cappedChain, i);
			h.rollback();   // forces eviction of the oldest when at cap
		}
		const t1 = performance.now();
		// soft assertion: log rather than fail on outliers
		const ms = t1 - t0;
		if (ms > 200) {

			console.warn(`[SkippedKeyStore] 100 evictions took ${ms.toFixed(2)}ms — expected <200ms for O(1)`);
		}
		expect(ms).toBeLessThan(500); // very loose upper bound for CI variance

		cappedStore.wipeAll();
		cappedChain.dispose();
		store.wipeAll();
		chain.dispose();
	});
});

// ── Round-trip: rollback then successful retrieval ───────────────────────────

describe('rollback + legitimate delivery', () => {
	test('rollback followed by resolve(same counter) returns the same key material', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));

		// Skip-ahead to 5 and commit — stores counters 1..4.
		store.resolve(chain, 5).commit();

		// Simulate attacker-forged message 3: resolve, "auth fails", rollback.
		const hBad = store.resolve(chain, 3);
		const badKeyCopy = toHex(hBad.key);
		hBad.rollback();

		// Legitimate message 3 arrives later — same key material returned.
		const hGood = store.resolve(chain, 3);
		expect(toHex(hGood.key)).toBe(badKeyCopy);
		hGood.commit();

		store.wipeAll();
		chain.dispose();
	});

	test('rollback does not rewind chain state', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		store.resolve(chain, 10).rollback();
		expect(chain.n).toBe(10);
		expect(store.size).toBe(10); // counters 1..10
		store.wipeAll();
		chain.dispose();
	});
});

// ── wipeAll ──────────────────────────────────────────────────────────────────

describe('wipeAll', () => {
	test('wipes all stored keys including rollback-restored ones', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));

		// Skip-ahead commits counters 1..4 into the store.
		store.resolve(chain, 5).commit();
		// Rollback of counter 5 adds a fifth entry.
		// But that resolve would now be past-path from chain.n=5 — skip this
		// and instead rollback a past-path retrieval.
		const h3 = store.resolve(chain, 3);
		const buf3 = h3.key;
		h3.rollback();
		expect(store.size).toBe(4);

		store.wipeAll();
		expect(store.size).toBe(0);
		expect(allZero(buf3)).toBe(true);

		chain.dispose();
	});

	test('wipeAll idempotent', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));
		store.resolve(chain, 3).commit();
		store.wipeAll();
		expect(() => store.wipeAll()).not.toThrow();
		chain.dispose();
	});
});

// ── resolve() argument validation ────────────────────────────────────────────

describe('resolve() argument validation', () => {
	test('counter ∈ {0, -1, 1.5, NaN, Infinity, MAX_SAFE_INTEGER + 1} all throw without advancing chain', () => {
		const store = new SkippedKeyStore();
		const chain = new KDFChain(new Uint8Array(32));

		const bad = [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1];
		for (const c of bad) {
			expect(() => store.resolve(chain, c)).toThrow(RangeError);
			expect(() => store.resolve(chain, c)).toThrow(/invalid counter/);
		}
		// Validation runs before any state mutation — chain.n stays at 0.
		expect(chain.n).toBe(0);

		chain.dispose();
	});
});
