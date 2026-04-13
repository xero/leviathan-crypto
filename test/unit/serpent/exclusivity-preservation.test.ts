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
 * SerpentCipher seal/open must preserve exclusivity.
 *
 * `SerpentCipher.sealChunk` / `openChunk` call pure `shared-ops` functions
 * directly on the WASM exports without going through `_acquireModule`. The
 * exclusivity guarantee is enforced by explicit `_assertNotOwned('serpent')`
 * and `_assertNotOwned('sha2')` calls at the top of each method. A live
 * `SerpentCtr` / `SerpentCbc` / `SHAKE128` / etc. must block seal/open
 * with a loud throw — silent module sharing would clobber the owner's
 * state. These tests lock in the guard so a future regression (removed
 * assertion) fails loudly.
 */
import '@vitest/web-worker';
import { describe, it, expect, beforeAll } from 'vitest';
import {
	init,
	Seal, SerpentCtr, SerpentCbc, SHAKE128,
} from '../../../src/ts/index.js';
import { SealStream } from '../../../src/ts/stream/index.js';
import { TestSerpentCipher as SerpentCipher } from '../stream/_test-ciphers.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm, sha3: sha3Wasm });
});

// ── Seal.encrypt(SerpentCipher, ...) — guard preservation ───────────────────

describe('exclusivity-preservation — Seal.encrypt(SerpentCipher)', () => {
	it('live SerpentCtr blocks Seal.encrypt — throws mentioning serpent', () => {
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		ctr.beginEncrypt(new Uint8Array(32), new Uint8Array(16));
		const key = SerpentCipher.keygen();
		try {
			expect(() => Seal.encrypt(SerpentCipher, key, new Uint8Array([1, 2, 3])))
				.toThrow(/serpent/);
		} finally {
			ctr.dispose();
		}
	});

	it('live SerpentCbc blocks Seal.encrypt — throws mentioning serpent', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		const key = SerpentCipher.keygen();
		try {
			expect(() => Seal.encrypt(SerpentCipher, key, new Uint8Array([1, 2, 3])))
				.toThrow(/serpent/);
		} finally {
			cbc.dispose();
		}
	});

	it('live SHAKE128 does NOT block Seal.encrypt (cross-module independence)', () => {
		// SHAKE128 holds sha3; SerpentCipher needs serpent + sha2. No conflict.
		const s = new SHAKE128();
		s.absorb(new TextEncoder().encode('independent'));
		const key = SerpentCipher.keygen();
		const pt  = new TextEncoder().encode('hello world');
		try {
			const blob = Seal.encrypt(SerpentCipher, key, pt);
			const rt   = Seal.decrypt(SerpentCipher, key, blob);
			expect(Array.from(rt)).toEqual(Array.from(pt));
		} finally {
			s.dispose();
		}
	});

	it('after SerpentCtr.dispose() Seal.encrypt succeeds', () => {
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		ctr.dispose();
		const key = SerpentCipher.keygen();
		const pt  = new Uint8Array([9, 8, 7]);
		const blob = Seal.encrypt(SerpentCipher, key, pt);
		const rt   = Seal.decrypt(SerpentCipher, key, blob);
		expect(Array.from(rt)).toEqual(Array.from(pt));
	});
});

// ── SealStream.push — same guard preservation on the streaming path ─────────

describe('exclusivity-preservation — SealStream.push(SerpentCipher)', () => {
	it('live SerpentCtr blocks SealStream.push — throws mentioning serpent', () => {
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		ctr.beginEncrypt(new Uint8Array(32), new Uint8Array(16));
		const key = SerpentCipher.keygen();
		try {
			const ss = new SealStream(SerpentCipher, key);
			expect(() => ss.push(new Uint8Array([4, 5, 6]))).toThrow(/serpent/);
		} finally {
			ctr.dispose();
		}
	});

	it('live SerpentCbc blocks SealStream.push — throws mentioning serpent', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		const key = SerpentCipher.keygen();
		try {
			const ss = new SealStream(SerpentCipher, key);
			expect(() => ss.push(new Uint8Array([4, 5, 6]))).toThrow(/serpent/);
		} finally {
			cbc.dispose();
		}
	});

	it('live SHAKE128 does NOT block SealStream.push (cross-module independence)', () => {
		const s = new SHAKE128();
		s.absorb(new TextEncoder().encode('holding sha3'));
		const key = SerpentCipher.keygen();
		try {
			const ss = new SealStream(SerpentCipher, key);
			const ct = ss.finalize(new Uint8Array([1, 2, 3, 4]));
			expect(ct.length).toBeGreaterThan(0);
		} finally {
			s.dispose();
		}
	});
});

// ── Seal.decrypt mirrors the guard on the opening side ──────────────────────

describe('exclusivity-preservation — Seal.decrypt(SerpentCipher)', () => {
	it('live SerpentCtr blocks Seal.decrypt — throws mentioning serpent', () => {
		// Build a valid blob first, with no owner live.
		const key = SerpentCipher.keygen();
		const blob = Seal.encrypt(SerpentCipher, key, new Uint8Array([7, 7, 7]));
		// Now acquire serpent via SerpentCtr and attempt to decrypt.
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		ctr.beginEncrypt(new Uint8Array(32), new Uint8Array(16));
		try {
			expect(() => Seal.decrypt(SerpentCipher, key, blob)).toThrow(/serpent/);
		} finally {
			ctr.dispose();
		}
	});

	it('after SerpentCtr.dispose() Seal.decrypt succeeds', () => {
		const key = SerpentCipher.keygen();
		const pt  = new Uint8Array([1, 2, 3, 4]);
		const blob = Seal.encrypt(SerpentCipher, key, pt);
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		ctr.dispose();
		const rt = Seal.decrypt(SerpentCipher, key, blob);
		expect(Array.from(rt)).toEqual(Array.from(pt));
	});
});
