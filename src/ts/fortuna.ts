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
// src/ts/fortuna.ts
//
// Fortuna CSPRNG — Ferguson & Schneier, Practical Cryptography (2003), Chapter 9.
// Backed by a pluggable Generator (cipher PRF) and HashFn (accumulator hash).
// Requires init() for the modules used by the chosen generator and hash pair.

import { isInitialized, getInstance } from './init.js';
import type { Generator, HashFn } from './types.js';
import { wipe, utf8ToBytes, concat } from './utils.js';

const isBrowser = typeof window !== 'undefined';
const isNode = typeof process !== 'undefined' && typeof process.pid === 'number';

/**
 * Fortuna CSPRNG — spec §9.3–§9.5
 *
 * Use `Fortuna.create({ generator, hash })` to instantiate. Direct construction is not allowed.
 */
export class Fortuna {
	// ── Constants ──────────────────────────────────────────────────────────
	private static readonly NUM_POOLS = 32;
	private static readonly RESEED_LIMIT = 64;          // bits — pool 0 threshold (spec §9.5)
	private static readonly MS_PER_RESEED = 100;        // ms — minimum reseed interval (spec §9.5)
	private static readonly NODE_STATS_INTERVAL = 1000; // ms — OS stats collector interval
	private static readonly CRYPTO_INTERVAL = 3000;     // ms — crypto.randomBytes interval

	// ── State ─────────────────────────────────────────────────────────────
	private gen: Generator;
	private hash: HashFn;
	private poolHash: Uint8Array[];       // 32 running hash chain values
	private poolEntropy: number[];
	private genKey: Uint8Array;
	private genCnt: Uint8Array;
	private reseedCnt: number;
	private lastReseed: number;
	private entropyLevel: number;
	private eventId: number;
	private active: boolean;
	private disposed: boolean;
	private msPerReseed: number;
	private robin: Record<string, number>;

	// Collector references for cleanup
	private boundCollectors: Record<string, EventListener> = {};
	private timers: ReturnType<typeof setInterval>[] = [];

	// ── Static factory ────────────────────────────────────────────────────

	static async create(opts: {
		generator: Generator;
		hash: HashFn;
		msPerReseed?: number;
		entropy?: Uint8Array;
	}): Promise<Fortuna> {
		if (!opts || !opts.generator || !opts.hash)
			throw new TypeError(
				'leviathan-crypto: Fortuna.create() requires { generator, hash }',
			);
		if (opts.hash.outputSize !== opts.generator.keySize)
			throw new RangeError(
				`leviathan-crypto: Fortuna requires hash.outputSize (${opts.hash.outputSize}) `
				+ `to match generator.keySize (${opts.generator.keySize})`,
			);

		const required = new Set<string>([...opts.generator.wasmModules, ...opts.hash.wasmModules]);
		for (const mod of required) {
			if (!isInitialized(mod as never)) {
				const args = [...required].map(m => `${m}: ...`).join(', ');
				throw new Error(`leviathan-crypto: call init({ ${args} }) before using Fortuna`);
			}
		}

		const f = new Fortuna(opts.generator, opts.hash, opts.msPerReseed ?? Fortuna.MS_PER_RESEED);
		f.initialize(opts.entropy);
		// Force the first reseed — pool[0] is saturated by initialize(),
		// so this call triggers an immediate reseed and guarantees get() never
		// returns undefined. The byte is discarded.
		f.get(1);
		return f;
	}

	private constructor(gen: Generator, hash: HashFn, msPerReseed: number) {
		this.gen  = gen;
		this.hash = hash;
		this.poolHash = [];
		this.poolEntropy = [];
		this.genKey = new Uint8Array(gen.keySize);
		this.genCnt = new Uint8Array(gen.counterSize);
		this.reseedCnt = 0;
		this.lastReseed = 0;
		this.entropyLevel = 0;
		this.eventId = 0;
		this.active = false;
		this.disposed = false;
		this.msPerReseed = msPerReseed;
		this.robin = { kbd: 0, mouse: 0, scroll: 0, touch: 0, motion: 0, time: 0, rnd: 0, dom: 0 };

		for (let i = 0; i < Fortuna.NUM_POOLS; i++) {
			this.poolHash.push(new Uint8Array(hash.outputSize)); // zero-initialized chain value
			this.poolEntropy.push(0);
		}
	}

	// ── Public API ────────────────────────────────────────────────────────

	/** Get n random bytes. Always returns Uint8Array — instance is guaranteed seeded after create(). */
	get(length: number): Uint8Array {
		if (this.disposed) throw new Error('Fortuna instance has been disposed');
		// Capture hrtime jitter at call time (Node.js) — spec §9.5
		if (isNode) this.captureHrtime();

		// Check reseed trigger — spec §9.5
		if (this.poolEntropy[0] >= Fortuna.RESEED_LIMIT &&
			Date.now() >= this.lastReseed + this.msPerReseed) {
			this.reseedCnt = (this.reseedCnt + 1) >>> 0; // u32 wrap

			let seed: Uint8Array = new Uint8Array(0);
			let strength = 0;
			for (let i = 0; i < Fortuna.NUM_POOLS; i++) {
				// Practical Cryptography (Ferguson & Schneier, 2003) §9.5.5:
				// pool P_i is used in reseed r iff 2^i divides r.
				if ((this.reseedCnt & ((1 << i) - 1)) === 0) {
					// Pool digest = current chain hash
					seed = concat(seed, this.poolHash[i]);
					strength += this.poolEntropy[i];
					// Reset pool — wipe old chain hash before dropping the reference.
					const old = this.poolHash[i];
					this.poolHash[i] = new Uint8Array(this.hash.outputSize);
					wipe(old);
					this.poolEntropy[i] = 0;
				}
			}
			this.entropyLevel -= strength;
			this.reseed(seed);
			// seed is built from concatenated pool-hash copies; wipe the temp.
			wipe(seed);
		}

		return this.pseudoRandomData(length);
	}

	/** Add external entropy to the pools. */
	addEntropy(entropy: Uint8Array): void {
		if (this.disposed) throw new Error('Fortuna instance has been disposed');
		this.addRandomEvent(entropy, this.robin.rnd, entropy.length * 8);
		this.robin.rnd = (this.robin.rnd + 1) % Fortuna.NUM_POOLS;
	}

	/** Get estimated available entropy in bytes. */
	getEntropy(): number {
		if (this.disposed) throw new Error('Fortuna instance has been disposed');
		return Math.floor(this.entropyLevel / 8);
	}

	/** Permanently dispose this instance. Wipes key material, stops all collectors. */
	stop(): void {
		if (this.disposed) throw new Error('Fortuna instance has been disposed');
		// Mark disposed FIRST. WASM wipeBuffers can throw if a stateful instance
		// holds the module; we must not allow get()/addEntropy()/getEntropy() to
		// run on a partially-disposed instance.
		this.disposed = true;
		this.stopCollectors();
		wipe(this.genKey);
		wipe(this.genCnt);
		// Wipe all 32 pool-hash chain values so residual entropy-bearing
		// bytes do not outlive the instance.
		for (const p of this.poolHash) wipe(p);
		this.reseedCnt = 0;
		// Best-effort wipe of WASM scratch buffers for every module the chosen
		// generator and hash touched. Surface the first error so the caller
		// knows the WASM scratch leak occurred.
		const required = new Set<string>([...this.gen.wasmModules, ...this.hash.wasmModules]);
		let err: unknown;
		for (const mod of required) {
			try {
				(getInstance(mod as never).exports as { wipeBuffers(): void }).wipeBuffers();
			} catch (e) {
				err ??= e;
			}
		}
		if (err) throw err;
	}

	// ── Test-only accessors ───────────────────────────────────────────────

	/** @internal — exposed for testing key replacement */
	_getGenKey(): Uint8Array {
		return this.genKey;
	}

	/** @internal — exposed for testing pool state */
	_getPoolEntropy(): number[] {
		return this.poolEntropy;
	}

	/** @internal — exposed for testing reseed count */
	_getReseedCnt(): number {
		return this.reseedCnt;
	}

	/** @internal — exposed for testing pool-hash backing arrays */
	_getPoolHash(): Uint8Array[] {
		return this.poolHash;
	}

	/**
	 * @internal — test-only deterministic factory. Seeds pool[0] with the provided
	 * entropy and triggers one reseed directly, bypassing all OS entropy collection
	 * and the hrtime jitter capture in get(). This makes KAT vectors reproducible
	 * across runs. Not suitable for production use.
	 */
	static async _createDeterministicForTesting(opts: {
		generator: Generator;
		hash: HashFn;
		entropy: Uint8Array;
	}): Promise<Fortuna> {
		if (!opts || !opts.generator || !opts.hash)
			throw new TypeError('Fortuna._createDeterministicForTesting() requires { generator, hash, entropy }');
		if (opts.hash.outputSize !== opts.generator.keySize)
			throw new RangeError(
				`leviathan-crypto: Fortuna requires hash.outputSize (${opts.hash.outputSize}) `
				+ `to match generator.keySize (${opts.generator.keySize})`,
			);
		const required = new Set<string>([...opts.generator.wasmModules, ...opts.hash.wasmModules]);
		for (const mod of required) {
			if (!isInitialized(mod as never)) {
				const args = [...required].map(m => `${m}: ...`).join(', ');
				throw new Error(`leviathan-crypto: call init({ ${args} }) before using Fortuna`);
			}
		}
		const f = new Fortuna(opts.generator, opts.hash, 0);
		// Seed pool[0] with the provided entropy, no OS collection.
		f.addRandomEvent(opts.entropy, 0, opts.entropy.length * 8);
		// Manually trigger reseed #1 without calling get() — get() calls captureHrtime()
		// in Node.js which adds non-deterministic data before the reseed fires.
		f.reseedFromPool0();
		return f;
	}

	// ── Generator (spec §9.4) ─────────────────────────────────────────────

	/** Get length pseudo-random bytes. — spec §9.4 */
	private pseudoRandomData(length: number): Uint8Array {
		const blocks = Math.ceil(length / this.gen.blockSize);
		const out = this.gen.generate(this.genKey, this.genCnt, length);
		// External counter advance — generator is stateless and does not mutate caller's counter
		for (let i = 0; i < blocks; i++) this.incrementCounter();

		// Key replacement — mandatory forward secrecy (spec §9.4).
		// Wipe the prior key BEFORE dropping its reference so no key bytes are
		// reachable after key replacement; anyone holding a Uint8Array view to
		// the old key now observes zero.
		const newKey = this.gen.generate(this.genKey, this.genCnt, this.gen.keySize);
		for (let i = 0; i < Math.ceil(this.gen.keySize / this.gen.blockSize); i++) this.incrementCounter();
		wipe(this.genKey);
		this.genKey = newKey;
		return out;
	}

	/** Reseed the generator — spec §9.4 */
	private reseed(seed: Uint8Array): void {
		// genKey = hash(genKey ‖ seed). Wipe both the hash input and the
		// prior key before dropping references.
		const combined = concat(this.genKey, seed);
		const newKey = this.hash.digest(combined);
		wipe(combined);
		wipe(this.genKey);
		this.genKey = newKey;

		// Increment counter — makes it nonzero on first reseed, marking generator as seeded
		this.incrementCounter();
		this.lastReseed = Date.now();
	}

	/** Drain pool 0 into a fresh seed and reseed. Used by the deterministic
	 *  test factory; production reseeds in get() walk the §9.5.5 schedule
	 *  across all pools, not just pool 0. Caller is responsible for any
	 *  entropy-threshold check. */
	private reseedFromPool0(): void {
		this.reseedCnt = (this.reseedCnt + 1) >>> 0;
		const seed = this.poolHash[0].slice();
		const old = this.poolHash[0];
		this.poolHash[0] = new Uint8Array(this.hash.outputSize);
		wipe(old);
		this.entropyLevel -= this.poolEntropy[0];
		this.poolEntropy[0] = 0;
		this.reseed(seed);
		wipe(seed);
	}

	/** Increment little-endian counter. — spec §9.4 */
	private incrementCounter(): void {
		for (let i = 0; i < this.genCnt.length; i++) {
			if (++this.genCnt[i] !== 0) break;
		}
	}

	// ── Accumulator (spec §9.5) ───────────────────────────────────────────

	/** Add an event to a pool via hash chaining: poolHash[i] = hash(poolHash[i] ‖ eventId ‖ data). */
	private addRandomEvent(data: Uint8Array, poolIdx: number, entropyBits: number): void {
		// Encode eventId as 4 bytes little-endian
		const id = new Uint8Array(4);
		id[0] = this.eventId & 0xff;
		id[1] = (this.eventId >>> 8) & 0xff;
		id[2] = (this.eventId >>> 16) & 0xff;
		id[3] = (this.eventId >>> 24) & 0xff;
		this.eventId = (this.eventId + 1) >>> 0; // u32 wrap

		// Chain: poolHash[i] = hash(poolHash[i] ‖ id ‖ data).
		// Wipe the chain input and the prior chain value before dropping refs.
		const combined = concat(this.poolHash[poolIdx], id, data);
		const newChain = this.hash.digest(combined);
		wipe(combined);
		wipe(this.poolHash[poolIdx]);
		this.poolHash[poolIdx] = newChain;

		this.poolEntropy[poolIdx] += entropyBits;
		this.entropyLevel += entropyBits;
	}

	// ── Initialization ────────────────────────────────────────────────────

	private initialize(entropy?: Uint8Array): void {
		// Initial seeding — crypto random per pool (spec §9.5)
		for (let i = 0; i < Fortuna.NUM_POOLS * 4; i++) {
			this.collectorCryptoRandom();
		}

		// Timing entropy
		this.collectorTime();

		// DOM entropy (browser only)
		this.collectorDom();

		// Extra entropy from caller
		if (entropy) {
			this.addRandomEvent(entropy, this.robin.rnd, entropy.length * 8);
			this.robin.rnd = (this.robin.rnd + 1) % Fortuna.NUM_POOLS;
		}

		// F-2 invariant: fail loudly if no OS entropy source delivered anything.
		// The try/catch in collectorCryptoRandom is preserved to protect against
		// platforms where crypto.getRandomValues itself throws (non-standard
		// runtimes). This post-init check covers all silent-failure paths uniformly.
		if (this.poolEntropy[0] < Fortuna.RESEED_LIMIT)
			throw new Error(
				'leviathan-crypto: Fortuna initialization could not gather sufficient entropy. '
				+ 'No working crypto.getRandomValues or node:crypto in this environment.',
			);

		this.startCollectors();
	}

	// ── Collectors ────────────────────────────────────────────────────────

	private startCollectors(): void {
		if (this.active) return;

		if (isBrowser) {
			const target = typeof window !== 'undefined' ? window : document;
			if (target) {
				this.boundCollectors.click = this.collectorClick.bind(this) as EventListener;
				this.boundCollectors.keydown = this.collectorKeyboard.bind(this) as EventListener;
				this.boundCollectors.scroll = this.collectorScroll.bind(this) as EventListener;
				this.boundCollectors.mousemove = this.throttle(this.collectorMouse, 50, this) as EventListener;
				this.boundCollectors.devicemotion = this.throttle(this.collectorMotion, 100, this) as EventListener;
				this.boundCollectors.deviceorientation = this.collectorMotion.bind(this) as EventListener;
				this.boundCollectors.orientationchange = this.collectorMotion.bind(this) as EventListener;
				this.boundCollectors.touchmove = this.throttle(this.collectorTouch, 50, this) as EventListener;
				this.boundCollectors.touchstart = this.collectorTouch.bind(this) as EventListener;
				this.boundCollectors.touchend = this.collectorTouch.bind(this) as EventListener;
				this.boundCollectors.load = this.collectorTime.bind(this) as unknown as EventListener;

				for (const [event, handler] of Object.entries(this.boundCollectors)) {
					target.addEventListener(event, handler, true);
				}
			}
		}

		if (isNode) {
			// OS stats timer
			this.timers.push(setInterval(() => this.collectNodeStats(), Fortuna.NODE_STATS_INTERVAL));
		}

		// Crypto timer — both environments
		this.timers.push(setInterval(() => this.collectorCryptoRandom(), Fortuna.CRYPTO_INTERVAL));

		this.active = true;
	}

	private stopCollectors(): void {
		if (!this.active) return;

		if (isBrowser && typeof window !== 'undefined') {
			for (const [event, handler] of Object.entries(this.boundCollectors)) {
				window.removeEventListener(event, handler, true);
			}
		}

		for (const timer of this.timers) clearInterval(timer);
		this.timers = [];
		this.boundCollectors = {};
		this.active = false;
	}

	// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type -- legacy throttle utility
	private throttle(fn: Function, threshold: number, scope?: object) {
		let last: number | undefined;
		let deferTimer: ReturnType<typeof setTimeout> | undefined;
		return function (this: unknown, ...args: unknown[]) {
			const context = scope || this;
			const now = Date.now();
			if (last && now < last + threshold) {
				clearTimeout(deferTimer);
				deferTimer = setTimeout(() => {
					last = now;
					fn.apply(context, args);
				}, threshold);
			} else {
				last = now;
				fn.apply(context, args);
			}
		};
	}

	private collectorKeyboard(ev: KeyboardEvent): void {
		const key = ev.key || '';
		const b = new Uint8Array([key.charCodeAt(0) || 0, (ev.timeStamp || 0) & 0xff]);
		this.addRandomEvent(b, this.robin.kbd, 1);
		this.robin.kbd = (this.robin.kbd + 1) % Fortuna.NUM_POOLS;
		this.collectorTime();
	}

	private collectorMouse(ev: MouseEvent): void {
		const x = ev.clientX || 0, y = ev.clientY || 0;
		this.addRandomEvent(new Uint8Array([x >>> 8, x & 0xff, y >>> 8, y & 0xff]), this.robin.mouse, 2);
		this.robin.mouse = (this.robin.mouse + 1) % Fortuna.NUM_POOLS;
	}

	private collectorClick(ev: MouseEvent): void {
		const x = ev.clientX || 0, y = ev.clientY || 0;
		this.addRandomEvent(new Uint8Array([x >>> 8, x & 0xff, y >>> 8, y & 0xff]), this.robin.mouse, 2);
		this.robin.mouse = (this.robin.mouse + 1) % Fortuna.NUM_POOLS;
		this.collectorTime();
	}

	private collectorTouch(ev: TouchEvent): void {
		const touch = ev.touches[0] || ev.changedTouches[0];
		if (!touch) return;
		const x = touch.pageX || touch.clientX || 0;
		const y = touch.pageY || touch.clientY || 0;
		this.addRandomEvent(new Uint8Array([x >>> 8, x & 0xff, y >>> 8, y & 0xff]), this.robin.touch, 2);
		this.robin.touch = (this.robin.touch + 1) % Fortuna.NUM_POOLS;
		this.collectorTime();
	}

	private collectorScroll(): void {
		if (typeof window === 'undefined') return;
		const x = window.scrollX || 0, y = window.scrollY || 0;
		this.addRandomEvent(new Uint8Array([x >>> 8, x & 0xff, y >>> 8, y & 0xff]), this.robin.scroll, 1);
		this.robin.scroll = (this.robin.scroll + 1) % Fortuna.NUM_POOLS;
	}

	private collectorMotion(ev: Event): void {
		const motion = ev as DeviceMotionEvent;
		const orient = ev as DeviceOrientationEvent;
		if (motion.accelerationIncludingGravity) {
			const a = motion.accelerationIncludingGravity;
			const x = a.x || 0, y = a.y || 0, z = a.z || 0;
			this.addRandomEvent(new Uint8Array([(x * 100) & 0xff, (y * 100) & 0xff, (z * 100) & 0xff]), this.robin.motion, 3);
		}
		if (typeof orient.alpha === 'number' && typeof orient.beta === 'number' && typeof orient.gamma === 'number') {
			this.addRandomEvent(utf8ToBytes(orient.alpha.toString() + orient.beta.toString() + orient.gamma.toString()), this.robin.motion, 3);
		}
		this.robin.motion = (this.robin.motion + 1) % Fortuna.NUM_POOLS;
	}

	private collectorTime(): void {
		if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
			this.addRandomEvent(utf8ToBytes(performance.now().toString()), this.robin.time, 2);
		} else {
			const t = Date.now();
			const b = new Uint8Array(4);
			b[0] = t & 0xff; b[1] = (t >>> 8) & 0xff;
			b[2] = (t >>> 16) & 0xff; b[3] = (t >>> 24) & 0xff;
			this.addRandomEvent(b, this.robin.time, 2);
		}
		this.robin.time = (this.robin.time + 1) % Fortuna.NUM_POOLS;
	}

	private collectorDom(): void {
		if (typeof document !== 'undefined' && document.documentElement) {
			this.addRandomEvent(this.hash.digest(utf8ToBytes(document.documentElement.innerHTML)), this.robin.dom, 2);
			this.robin.dom = (this.robin.dom + 1) % Fortuna.NUM_POOLS;
		}
	}

	private collectorCryptoRandom(): void {
		try {
			const rnd = new Uint8Array(128);
			if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
				globalThis.crypto.getRandomValues(rnd);
			} else if (isNode) {
				// eslint-disable-next-line @typescript-eslint/no-require-imports
				const nodeCrypto = require('node:crypto');
				const buf = nodeCrypto.randomBytes(128);
				rnd.set(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
			} else {
				return; // no crypto source available
			}
			this.addRandomEvent(rnd, this.robin.rnd, 1024);
			this.robin.rnd = (this.robin.rnd + 1) % Fortuna.NUM_POOLS;
		} catch { /* crypto may not be available */ }
	}

	private captureHrtime(): void {
		try {
			const hr = process.hrtime.bigint();
			const hrBytes = new Uint8Array(8);
			for (let i = 0; i < 8; i++) hrBytes[i] = Number((hr >> BigInt(i * 8)) & 0xffn);
			this.addRandomEvent(hrBytes, this.robin.time, 8);
			this.robin.time = (this.robin.time + 1) % Fortuna.NUM_POOLS;
		} catch { /* hrtime may not be available */ }
	}

	private collectNodeStats(): void {
		try {
			// hrtime — nanosecond scheduling jitter
			const hr = process.hrtime.bigint();
			const hrBytes = new Uint8Array(8);
			for (let i = 0; i < 8; i++) hrBytes[i] = Number((hr >> BigInt(i * 8)) & 0xffn);
			this.addRandomEvent(hrBytes, this.robin.time, 8);
			this.robin.time = (this.robin.time + 1) % Fortuna.NUM_POOLS;

			// cpuUsage — user + system CPU microseconds
			const cpu = process.cpuUsage();
			const cpuBytes = new Uint8Array(8);
			cpuBytes[0] = cpu.user & 0xff; cpuBytes[1] = (cpu.user >>> 8) & 0xff;
			cpuBytes[2] = (cpu.user >>> 16) & 0xff; cpuBytes[3] = (cpu.user >>> 24) & 0xff;
			cpuBytes[4] = cpu.system & 0xff; cpuBytes[5] = (cpu.system >>> 8) & 0xff;
			cpuBytes[6] = (cpu.system >>> 16) & 0xff; cpuBytes[7] = (cpu.system >>> 24) & 0xff;
			this.addRandomEvent(cpuBytes, this.robin.rnd, 2);
			this.robin.rnd = (this.robin.rnd + 1) % Fortuna.NUM_POOLS;

			// memoryUsage — heapUsed changes constantly
			const mem = process.memoryUsage();
			const memVal = mem.heapUsed;
			const memBytes = new Uint8Array(4);
			memBytes[0] = memVal & 0xff; memBytes[1] = (memVal >>> 8) & 0xff;
			memBytes[2] = (memVal >>> 16) & 0xff; memBytes[3] = (memVal >>> 24) & 0xff;
			this.addRandomEvent(memBytes, this.robin.rnd, 1);
			this.robin.rnd = (this.robin.rnd + 1) % Fortuna.NUM_POOLS;

			// loadavg — slow-changing but real system state
			// eslint-disable-next-line @typescript-eslint/no-require-imports
			const os = require('node:os');
			const la: number[] = os.loadavg();
			const laStr = la.map((n: number) => Math.round(n * 1000).toString()).join('');
			this.addRandomEvent(utf8ToBytes(laStr), this.robin.time, 1);
			this.robin.time = (this.robin.time + 1) % Fortuna.NUM_POOLS;

			// freemem — changes with allocation activity
			const fm: number = os.freemem();
			const fmBytes = new Uint8Array(4);
			fmBytes[0] = fm & 0xff; fmBytes[1] = (fm >>> 8) & 0xff;
			fmBytes[2] = (fm >>> 16) & 0xff; fmBytes[3] = (fm >>> 24) & 0xff;
			this.addRandomEvent(fmBytes, this.robin.rnd, 1);
			this.robin.rnd = (this.robin.rnd + 1) % Fortuna.NUM_POOLS;
		} catch { /* Node APIs may not be available */ }
	}
}
