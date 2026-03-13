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
// Backed by WASM Serpent-256 ECB (generator) and WASM SHA-256 (accumulator pools).
// Requires init(['serpent', 'sha2']) before Fortuna.create().

import { isInitialized } from './init.js';
import { Serpent } from './serpent/index.js';
import { SHA256 } from './sha2/index.js';
import { wipe, utf8ToBytes, concat } from './utils.js';

const isBrowser = typeof window !== 'undefined';
const isNode = typeof process !== 'undefined' && typeof process.pid === 'number';

/**
 * Fortuna CSPRNG — spec §9.3–§9.5
 *
 * Use `Fortuna.create()` to instantiate. Direct construction is not allowed.
 */
export class Fortuna {
	// ── Constants ──────────────────────────────────────────────────────────
	private static readonly NUM_POOLS = 32;
	private static readonly RESEED_LIMIT = 64;          // bits — pool 0 threshold (spec §9.5)
	private static readonly MS_PER_RESEED = 100;        // ms — minimum reseed interval (spec §9.5)
	private static readonly NODE_STATS_INTERVAL = 1000; // ms — OS stats collector interval
	private static readonly CRYPTO_INTERVAL = 3000;     // ms — crypto.randomBytes interval

	// ── State ─────────────────────────────────────────────────────────────
	private serpent: Serpent;
	private sha: SHA256;
	private poolHash: Uint8Array[];       // 32 running SHA-256 chain hashes (32 bytes each)
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

	static async create(opts?: { msPerReseed?: number; entropy?: Uint8Array }): Promise<Fortuna> {
		if (!isInitialized('serpent'))
			throw new Error('leviathan-crypto: call init([\'serpent\', \'sha2\']) before using Fortuna');
		if (!isInitialized('sha2'))
			throw new Error('leviathan-crypto: call init([\'serpent\', \'sha2\']) before using Fortuna');

		const f = new Fortuna(opts?.msPerReseed ?? Fortuna.MS_PER_RESEED);
		f.initialize(opts?.entropy);
		return f;
	}

	private constructor(msPerReseed: number) {
		this.serpent = new Serpent();
		this.sha = new SHA256();
		this.poolHash = [];
		this.poolEntropy = [];
		this.genKey = new Uint8Array(32);
		this.genCnt = new Uint8Array(16);
		this.reseedCnt = 0;
		this.lastReseed = 0;
		this.entropyLevel = 0;
		this.eventId = 0;
		this.active = false;
		this.disposed = false;
		this.msPerReseed = msPerReseed;
		this.robin = { kbd: 0, mouse: 0, scroll: 0, touch: 0, motion: 0, time: 0, rnd: 0, dom: 0 };

		for (let i = 0; i < Fortuna.NUM_POOLS; i++) {
			this.poolHash.push(new Uint8Array(32)); // zero-initialized chain value
			this.poolEntropy.push(0);
		}
	}

	// ── Public API ────────────────────────────────────────────────────────

	/** Get n random bytes. Returns undefined if not yet seeded (reseedCnt === 0). */
	get(length: number): Uint8Array | undefined {
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
				if ((this.reseedCnt & (1 << i)) !== 0) {
					// Pool digest = current chain hash
					seed = concat(seed, this.poolHash[i]);
					strength += this.poolEntropy[i];
					// Reset pool
					this.poolHash[i] = new Uint8Array(32);
					this.poolEntropy[i] = 0;
				}
			}
			this.entropyLevel -= strength;
			this.reseed(seed);
		}

		if (this.reseedCnt === 0) return undefined;
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
		this.stopCollectors();
		wipe(this.genKey);
		wipe(this.genCnt);
		this.reseedCnt = 0;
		this.disposed = true;
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

	// ── Generator (spec §9.4) ─────────────────────────────────────────────

	/** Generate n blocks of 16 bytes each. — spec §9.4 */
	private generateBlocks(n: number): Uint8Array {
		const out = new Uint8Array(n * 16);
		for (let i = 0; i < n; i++) {
			// Encrypt genCnt with Serpent-256 ECB
			this.serpent.loadKey(this.genKey);
			out.set(this.serpent.encryptBlock(this.genCnt), i * 16);
			this.incrementCounter();
		}
		return out;
	}

	/** Get length pseudo-random bytes. — spec §9.4 */
	private pseudoRandomData(length: number): Uint8Array {
		// Generate ceil(length/16) + 1 blocks — +1 ensures extra block before key replacement
		const blocks = Math.ceil(length / 16) + 1;
		const raw = this.generateBlocks(blocks);
		const output = raw.slice(0, length);

		// Key replacement — mandatory forward secrecy (spec §9.4)
		this.genKey = this.generateBlocks(2);
		return output;
	}

	/** Reseed the generator — spec §9.4 */
	private reseed(seed: Uint8Array): void {
		// genKey = SHA256(genKey ‖ seed)
		this.genKey = this.sha.hash(concat(this.genKey, seed));

		// Increment counter — makes it nonzero on first reseed, marking generator as seeded
		this.incrementCounter();
		this.lastReseed = Date.now();
	}

	/** Increment 16-byte little-endian counter. — spec §9.4 */
	private incrementCounter(): void {
		for (let i = 0; i < 16; i++) {
			if (++this.genCnt[i] !== 0) break;
		}
	}

	// ── Accumulator (spec §9.5) ───────────────────────────────────────────

	/** Add an event to a pool via hash chaining: poolHash[i] = SHA256(poolHash[i] ‖ eventId ‖ data). */
	private addRandomEvent(data: Uint8Array, poolIdx: number, entropyBits: number): void {
		// Encode eventId as 4 bytes little-endian
		const id = new Uint8Array(4);
		id[0] = this.eventId & 0xff;
		id[1] = (this.eventId >>> 8) & 0xff;
		id[2] = (this.eventId >>> 16) & 0xff;
		id[3] = (this.eventId >>> 24) & 0xff;
		this.eventId = (this.eventId + 1) >>> 0; // u32 wrap

		// Chain: poolHash[i] = SHA256(poolHash[i] ‖ id ‖ data)
		this.poolHash[poolIdx] = this.sha.hash(concat(concat(this.poolHash[poolIdx], id), data));

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
			this.addRandomEvent(this.sha.hash(utf8ToBytes(document.documentElement.innerHTML)), this.robin.dom, 2);
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
