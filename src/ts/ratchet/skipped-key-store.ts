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
// src/ts/ratchet/skipped-key-store.ts
//
// SkippedKeyStore — MKSKIPPED cache for a single KDFChain (DR spec §3.2/§3.5).
// Manages out-of-order and skipped message key storage with transactional
// resolve via ResolveHandle. Split budgets: maxCacheSize bounds memory;
// maxSkipPerResolve bounds per-message HKDF work (DoS mitigation).

import { wipe } from '../utils.js';
import { KDFChain } from './kdf-chain.js';
import type { ResolveHandle, SkippedKeyStoreOpts } from './types.js';

// Best-effort wipe if a handle is GC'd without settling. GC is non-deterministic
// so this is a safety net only; the contract remains that callers MUST settle.
const finalizer = new FinalizationRegistry<Uint8Array>(key => wipe(key));

export class SkippedKeyStore {
	private _store:             Map<number, Uint8Array>;
	private _maxCacheSize:      number;
	private _maxSkipPerResolve: number;

	constructor(opts?: SkippedKeyStoreOpts) {
		const cache = opts?.maxCacheSize      ?? opts?.ceiling ?? 100;
		const skip  = opts?.maxSkipPerResolve ?? opts?.ceiling ?? 50;

		if (!Number.isSafeInteger(cache) || cache < 1)
			throw new RangeError('SkippedKeyStore: maxCacheSize must be a safe integer >= 1');
		if (!Number.isSafeInteger(skip) || skip < 1)
			throw new RangeError('SkippedKeyStore: maxSkipPerResolve must be a safe integer >= 1');
		if (skip > cache)
			throw new RangeError(
				`SkippedKeyStore: maxSkipPerResolve (${skip}) must not exceed maxCacheSize (${cache})`,
			);

		this._store             = new Map();
		this._maxCacheSize      = cache;
		this._maxSkipPerResolve = skip;
	}

	// O(1) eviction — Map iteration is insertion order, and keys are inserted
	// in strictly increasing counter order, so the first key yielded IS the
	// oldest (lowest counter).
	private _evictOldest(): void {
		const oldest = this._store.keys().next().value;
		if (oldest === undefined) return;
		const val = this._store.get(oldest);
		if (val !== undefined) wipe(val);
		this._store.delete(oldest);
	}

	// Resolve a message key for the given counter. Returns a ResolveHandle the
	// caller settles via commit() (success — key wiped) or rollback()
	// (failure — key returned to the store so a later legitimate message at
	// the same counter can still decrypt).
	//
	// Three paths based on counter vs chain.n:
	//   in-order   (=== n+1): step chain, wrap final key
	//   skip-ahead (>   n+1): step chain storing intermediates, wrap final
	//   past       (<=   n):  look up in map and delete; throw if absent
	resolve(chain: KDFChain, counter: number): ResolveHandle {
		if (!Number.isSafeInteger(counter) || counter < 1)
			throw new RangeError(`SkippedKeyStore: invalid counter ${counter}`);

		let key: Uint8Array;
		if (counter === chain.n + 1) {
			key = chain.step();
		} else if (counter > chain.n + 1) {
			const skipNeeded = counter - chain.n - 1;
			if (skipNeeded > this._maxSkipPerResolve)
				throw new RangeError(
					`SkippedKeyStore: counter ${counter} requires ${skipNeeded} skip derivations, `
					+ `exceeds maxSkipPerResolve=${this._maxSkipPerResolve}`,
				);
			while (chain.n < counter - 1) {
				const k = chain.step();
				if (this._store.size >= this._maxCacheSize) this._evictOldest();
				this._store.set(chain.n, k);
			}
			key = chain.step();
		} else {
			const stored = this._store.get(counter);
			if (stored === undefined)
				throw new Error(`SkippedKeyStore: unrecoverable. key for counter ${counter} not found`);
			this._store.delete(counter);
			key = stored;
		}

		return this._makeHandle(key, counter);
	}

	private _makeHandle(key: Uint8Array, counter: number): ResolveHandle {
		let settled = false;
		const handle: ResolveHandle = {
			get key() {
				if (settled) throw new Error('SkippedKeyStore: handle already settled');
				return key;
			},
			commit: () => {
				if (settled) throw new Error('SkippedKeyStore: handle already settled');
				settled = true;
				finalizer.unregister(handle);
				wipe(key);
			},
			rollback: () => {
				if (settled) throw new Error('SkippedKeyStore: handle already settled');
				settled = true;
				finalizer.unregister(handle);
				if (this._store.size >= this._maxCacheSize) this._evictOldest();
				this._store.set(counter, key);
			},
		};
		finalizer.register(handle, key, handle);
		return handle;
	}

	// Step chain from its current position up to and including pn, storing each
	// key. Used at epoch transitions so late-arriving old-epoch messages can
	// still be decrypted. No-op when pn <= chain.n. Enforces maxSkipPerResolve
	// so a malicious header can't force unbounded HKDF work.
	advanceToBoundary(chain: KDFChain, pn: number): void {
		if (!Number.isSafeInteger(pn) || pn < 0)
			throw new RangeError(`SkippedKeyStore: invalid pn ${pn}`);
		const skipNeeded = pn - chain.n;
		if (skipNeeded > this._maxSkipPerResolve)
			throw new RangeError(
				`SkippedKeyStore: pn=${pn} requires ${skipNeeded} skip derivations, `
				+ `exceeds maxSkipPerResolve=${this._maxSkipPerResolve}`,
			);
		while (chain.n < pn) {
			const key = chain.step();
			if (this._store.size >= this._maxCacheSize) this._evictOldest();
			this._store.set(chain.n, key);
		}
	}

	get size(): number {
		return this._store.size;
	}

	// Wipe all stored key buffers and clear the map. Idempotent.
	wipeAll(): void {
		for (const v of this._store.values())
			wipe(v);
		this._store.clear();
	}
}
