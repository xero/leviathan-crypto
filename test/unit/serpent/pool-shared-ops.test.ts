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
 * Cross-check that the pure-function `shared-ops.ts` primitives produce
 * byte-identical output to the main-thread class wrappers. These functions
 * are used by both `SerpentCipher.sealChunk`/`openChunk` and the
 * `SealStreamPool` worker — drift between them breaks pool / main parity,
 * so the guards live here.
 *
 * Also covers PKCS7 normalisation end to end in the shared module: every
 * failure mode must throw `RangeError('invalid ciphertext')` with no
 * numeric leaks. The main-thread `pkcs7-oracle.test.ts` covers SerpentCbc;
 * this file covers `shared-ops.pkcs7Strip` directly so the pool-worker
 * path has its own regression guard.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, HMAC_SHA256, SerpentCbc } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { hmacSha256Vectors } from '../../vectors/sha2.js';
import {
	hmacSha256,
	cbcEncryptChunk,
	cbcDecryptChunk,
	pkcs7Pad,
	pkcs7Strip,
	PKCS7_INVALID,
	type Sha2OpsExports,
	type SerpentOpsExports,
} from '../../../src/ts/serpent/shared-ops.js';

function hex(s: string): Uint8Array {
	if (s.length % 2 !== 0) throw new Error('bad hex length');
	const out = new Uint8Array(s.length >>> 1);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
	return out;
}

function bytesToHex(b: Uint8Array): string {
	return [...b].map(v => v.toString(16).padStart(2, '0')).join('');
}

function getSha2Ops(): Sha2OpsExports {
	return getInstance('sha2').exports as unknown as Sha2OpsExports;
}
function getSerpentOps(): SerpentOpsExports {
	return getInstance('serpent').exports as unknown as SerpentOpsExports;
}

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm });
});

// ── 1. hmacSha256 vs main-thread HMAC_SHA256.hash (RFC 4231) ────────────────

describe('shared-ops.hmacSha256 — RFC 4231 + main-thread parity', () => {
	for (const v of hmacSha256Vectors) {
		it(`RFC 4231 ${v.description} — matches spec output`, () => {
			const key = hex(v.key);
			const msg = hex(v.input);
			const out = hmacSha256(getSha2Ops(), key, msg);
			expect(bytesToHex(out)).toBe(v.expected);
		});
	}

	it('matches HMAC_SHA256.hash for an assorted corpus', () => {
		const cases = [
			{ key: new Uint8Array(0),          msg: new Uint8Array(0) },
			{ key: new Uint8Array(16).fill(1), msg: new Uint8Array(1) },
			{ key: new Uint8Array(32).fill(2), msg: new TextEncoder().encode('a') },
			{ key: new Uint8Array(64).fill(3), msg: new Uint8Array(64).fill(0xAA) },
			{ key: new Uint8Array(128).fill(4), msg: new Uint8Array(1000).fill(0xBB) }, // > block-size key
		];
		for (const c of cases) {
			// Compute via pure fn first (leaves sha2 buffer contents behind, but
			// the next class construction calls sha2Init which resets state).
			const viaShared = hmacSha256(getSha2Ops(), c.key, c.msg);
			const hm = new HMAC_SHA256();
			try {
				const viaClass = hm.hash(c.key, c.msg);
				expect(Array.from(viaShared)).toEqual(Array.from(viaClass));
			} finally {
				hm.dispose();
			}
		}
	});
});

// ── 2. cbcEncryptChunk matches SerpentCbc.encrypt ───────────────────────────

describe('shared-ops.cbcEncryptChunk — main-thread parity', () => {
	it('matches SerpentCbc.encrypt for fixed triples across size buckets', () => {
		const key = new Uint8Array(32);
		for (let i = 0; i < 32; i++) key[i] = (i * 3 + 7) & 0xff;
		const iv = new Uint8Array(16);
		for (let i = 0; i < 16; i++) iv[i]  = (i * 5 + 11) & 0xff;

		const sizes = [0, 1, 15, 16, 17, 31, 32, 64, 1000, 65536];
		for (const n of sizes) {
			const pt = new Uint8Array(n);
			for (let i = 0; i < n; i++) pt[i] = (i * 13) & 0xff;

			// Pure path first — uses raw exports.
			const viaShared = cbcEncryptChunk(getSerpentOps(), key, iv, pt);

			// Class path second — class exclusivity guard requires no owner here.
			const cbc = new SerpentCbc({ dangerUnauthenticated: true });
			try {
				const viaClass = cbc.encrypt(key, iv, pt);
				expect(viaShared.length).toBe(viaClass.length);
				expect(Array.from(viaShared)).toEqual(Array.from(viaClass));
			} finally {
				cbc.dispose();
			}
		}
	});
});

// ── 3. cbcDecryptChunk uses SIMD, matches SerpentCbc.decrypt ────────────────

describe('shared-ops.cbcDecryptChunk — SIMD path + main-thread parity', () => {
	it('round-trips with cbcEncryptChunk for sizes 0..65536', () => {
		const key = new Uint8Array(32).fill(0x44);
		const iv  = new Uint8Array(16).fill(0x77);
		const sizes = [0, 1, 15, 16, 17, 31, 32, 64, 1000, 65536];
		for (const n of sizes) {
			const pt = new Uint8Array(n);
			for (let i = 0; i < n; i++) pt[i] = (i * 17) & 0xff;
			const ct = cbcEncryptChunk(getSerpentOps(), key, iv, pt);
			const rt = cbcDecryptChunk(getSerpentOps(), key, iv, ct);
			expect(rt.length).toBe(pt.length);
			expect(Array.from(rt)).toEqual(Array.from(pt));
		}
	});

	it('matches SerpentCbc.decrypt output for fixed triples', () => {
		const key = new Uint8Array(32).fill(0x55);
		const iv  = new Uint8Array(16).fill(0x66);
		// Build a ciphertext via the class path, decrypt via the shared path.
		const pt = new Uint8Array(48);
		for (let i = 0; i < 48; i++) pt[i] = (i * 19) & 0xff;
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		let ct: Uint8Array;
		let viaClass: Uint8Array;
		try {
			ct = cbc.encrypt(key, iv, pt);
			viaClass = cbc.decrypt(key, iv, ct);
		} finally {
			cbc.dispose();
		}
		const viaShared = cbcDecryptChunk(getSerpentOps(), key, iv, ct);
		expect(Array.from(viaShared)).toEqual(Array.from(viaClass));
		expect(Array.from(viaShared)).toEqual(Array.from(pt));
	});

	it('uses cbcDecryptChunk_simd — counted via a wrapped-exports spy', () => {
		// Behavioural probe: build a plain object that re-exports the real
		// serpent methods with counter wrappers around both decrypt paths.
		// If a future refactor swaps to the scalar cbcDecryptChunk, this fails.
		const real = getInstance('serpent').exports as unknown as SerpentOpsExports & {
			cbcDecryptChunk?: (n: number) => number;
		};
		let simdCalls = 0;
		let scalarCalls = 0;
		const wrapped = {
			memory: real.memory,
			getKeyOffset: real.getKeyOffset.bind(real),
			getChunkPtOffset: real.getChunkPtOffset.bind(real),
			getChunkCtOffset: real.getChunkCtOffset.bind(real),
			getChunkSize: real.getChunkSize.bind(real),
			getCbcIvOffset: real.getCbcIvOffset.bind(real),
			loadKey: real.loadKey.bind(real),
			cbcEncryptChunk: real.cbcEncryptChunk.bind(real),
			cbcDecryptChunk_simd(n: number): number {
				simdCalls++;
				return real.cbcDecryptChunk_simd(n);
			},
			cbcDecryptChunk(n: number): number {
				scalarCalls++;
				return (real.cbcDecryptChunk as (x: number) => number).call(real, n);
			},
		} as unknown as SerpentOpsExports;

		const key = new Uint8Array(32).fill(0x11);
		const iv  = new Uint8Array(16).fill(0x22);
		const pt  = new Uint8Array(100);
		for (let i = 0; i < pt.length; i++) pt[i] = (i * 23) & 0xff;
		const ct = cbcEncryptChunk(wrapped, key, iv, pt);
		const rt = cbcDecryptChunk(wrapped, key, iv, ct);
		expect(Array.from(rt)).toEqual(Array.from(pt));
		expect(simdCalls).toBe(1);
		expect(scalarCalls).toBe(0);
	});
});

// ── 4. pkcs7Pad / pkcs7Strip round-trip for lengths 0..17 ───────────────────

describe('shared-ops pkcs7 round-trip', () => {
	for (let len = 0; len <= 17; len++) {
		it(`lengths ${len} round-trip`, () => {
			const data = new Uint8Array(len);
			for (let i = 0; i < len; i++) data[i] = (i * 29 + 3) & 0xff;
			const padded = pkcs7Pad(data);
			expect(padded.length % 16).toBe(0);
			expect(padded.length).toBeGreaterThanOrEqual(len + 1);
			expect(padded.length).toBeLessThanOrEqual(len + 16);
			const stripped = pkcs7Strip(padded);
			expect(stripped.length).toBe(len);
			expect(Array.from(stripped)).toEqual(Array.from(data));
		});
	}
});

// ── 5. pkcs7Strip normalised failure modes ──────────────────────────────────

describe('shared-ops.pkcs7Strip — branch-free padding check', () => {
	function capture(fn: () => unknown): Error {
		try {
			fn();
		} catch (e) {
			return e as Error;
		}
		throw new Error('expected pkcs7Strip to throw');
	}

	it('empty input throws RangeError("invalid ciphertext")', () => {
		const err = capture(() => pkcs7Strip(new Uint8Array(0)));
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('non-multiple-of-16 length throws RangeError("invalid ciphertext")', () => {
		const err = capture(() => pkcs7Strip(new Uint8Array(17)));
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('final byte = 0 (padLen=0) throws RangeError("invalid ciphertext")', () => {
		const data = new Uint8Array(16); // all zeros
		const err = capture(() => pkcs7Strip(data));
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('final byte = 17 (padLen out of range) throws RangeError("invalid ciphertext")', () => {
		const data = new Uint8Array(16);
		data[15] = 17;
		const err = capture(() => pkcs7Strip(data));
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('padLen=5 but preceding pad bytes mismatched throws RangeError("invalid ciphertext")', () => {
		const data = new Uint8Array(16);
		data[15] = 5;          // padLen=5
		// leave data[11..14] as 0 — those should be 5 for valid PKCS7
		const err = capture(() => pkcs7Strip(data));
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('all failure modes produce strictly identical error message — no leaks', () => {
		const cases: Uint8Array[] = [
			new Uint8Array(0),
			new Uint8Array(17),
			new Uint8Array(16),                        // padLen=0
			(() => {
				const d = new Uint8Array(16); d[15] = 17; return d;
			})(), // padLen=17
			(() => {
				const d = new Uint8Array(16); d[15] = 5;  return d;
			})(), // padLen=5 mismatch
		];
		const messages = cases.map(c => capture(() => pkcs7Strip(c)).message);
		for (const m of messages) {
			expect(m).toBe(PKCS7_INVALID);
			expect(m).not.toMatch(/\d/); // no numeric leaks
		}
		expect(new Set(messages).size).toBe(1);
	});
});
