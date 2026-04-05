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
 * SerpentSeal unit tests + constructor gate tests for SerpentCbc/SerpentCtr
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	init, _resetForTesting,
	SerpentSeal, SerpentCbc, SerpentCtr,
} from '../../../src/ts/index.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

let seal: SerpentSeal;
const key = new Uint8Array(64);
for (let i = 0; i < 64; i++) key[i] = i;

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm });
	seal = new SerpentSeal();
});

// ── SerpentSeal ──────────────────────────────────────────────────────────────

describe('SerpentSeal', () => {
	it('encrypt() → decrypt() round-trips correctly', () => {
		const pt = new Uint8Array(100);
		for (let i = 0; i < 100; i++) pt[i] = i & 0xFF;
		const ct = seal.encrypt(key, pt);
		const recovered = seal.decrypt(key, ct);
		expect(Array.from(recovered)).toEqual(Array.from(pt));
	});

	it('decrypt() throws on tag corruption', () => {
		const pt = new Uint8Array(32).fill(0x42);
		const ct = seal.encrypt(key, pt).slice();
		// Flip a byte in the tag (last 32 bytes)
		ct[ct.length - 1] ^= 0x01;
		expect(() => seal.decrypt(key, ct)).toThrow('serpent: authentication failed');
	});

	it('decrypt() throws on ciphertext corruption', () => {
		const pt = new Uint8Array(32).fill(0x42);
		const ct = seal.encrypt(key, pt).slice();
		// Flip a byte in the ciphertext portion (between iv and tag)
		ct[20] ^= 0x01;
		expect(() => seal.decrypt(key, ct)).toThrow('serpent: authentication failed');
	});

	it('decrypt() throws on iv corruption', () => {
		const pt = new Uint8Array(32).fill(0x42);
		const ct = seal.encrypt(key, pt).slice();
		// Flip a byte in the IV (first 16 bytes)
		ct[0] ^= 0x01;
		expect(() => seal.decrypt(key, ct)).toThrow('serpent: authentication failed');
	});

	it('two encrypt() calls with same key and plaintext produce different output', () => {
		const pt = new Uint8Array(48).fill(0xAA);
		const out1 = seal.encrypt(key, pt);
		const out2 = seal.encrypt(key, pt);
		// IV is random — outputs must differ
		let same = true;
		for (let i = 0; i < out1.length; i++) {
			if (out1[i] !== out2[i]) {
				same = false; break;
			}
		}
		expect(same).toBe(false);
	});

	it('encrypt() throws RangeError on 32-byte key', () => {
		expect(() => seal.encrypt(new Uint8Array(32), new Uint8Array(16)))
			.toThrow(RangeError);
		expect(() => seal.encrypt(new Uint8Array(32), new Uint8Array(16)))
			.toThrow('SerpentSeal key must be 64 bytes (got 32)');
	});

	it('encrypt() throws RangeError on 0-byte key', () => {
		expect(() => seal.encrypt(new Uint8Array(0), new Uint8Array(16)))
			.toThrow(RangeError);
		expect(() => seal.encrypt(new Uint8Array(0), new Uint8Array(16)))
			.toThrow('SerpentSeal key must be 64 bytes (got 0)');
	});

	it('decrypt() throws RangeError on data too short', () => {
		expect(() => seal.decrypt(key, new Uint8Array(63)))
			.toThrow(RangeError);
		expect(() => seal.decrypt(key, new Uint8Array(63)))
			.toThrow('SerpentSeal ciphertext too short');
	});

	it('dispose() calls dispose on both internal instances', () => {
		const s = new SerpentSeal();
		// Should not throw
		s.dispose();
	});
});

// ── SerpentSeal init guard ───────────────────────────────────────────────────

describe('SerpentSeal — init guards', () => {
	it('constructor throws if serpent not initialized', async () => {
		_resetForTesting();
		await init({ sha2: sha2Wasm });
		expect(() => new SerpentSeal()).toThrow(
			'leviathan-crypto: call init({ serpent: ..., sha2: ... }) before using SerpentSeal'
		);
		// Restore
		await init({ serpent: serpentWasm, sha2: sha2Wasm });
	});

	it('constructor throws if sha2 not initialized', async () => {
		_resetForTesting();
		await init({ serpent: serpentWasm });
		expect(() => new SerpentSeal()).toThrow(
			'leviathan-crypto: call init({ serpent: ..., sha2: ... }) before using SerpentSeal'
		);
		// Restore
		await init({ serpent: serpentWasm, sha2: sha2Wasm });
	});
});

// ── SerpentCbc/SerpentCtr constructor gate ───────────────────────────────────

describe('SerpentCbc — dangerUnauthenticated gate', () => {
	it('new SerpentCbc() throws without dangerUnauthenticated flag', () => {
		expect(() => new SerpentCbc()).toThrow(
			'leviathan-crypto: SerpentCbc is unauthenticated — use SerpentSeal instead.'
		);
	});

	it('new SerpentCbc({ dangerUnauthenticated: true }) constructs successfully', () => {
		expect(() => new SerpentCbc({ dangerUnauthenticated: true })).not.toThrow();
	});
});

describe('SerpentCtr — dangerUnauthenticated gate', () => {
	it('new SerpentCtr() throws without dangerUnauthenticated flag', () => {
		expect(() => new SerpentCtr()).toThrow(
			'leviathan-crypto: SerpentCtr is unauthenticated — use SerpentSeal instead.'
		);
	});

	it('new SerpentCtr({ dangerUnauthenticated: true }) constructs successfully', () => {
		expect(() => new SerpentCtr({ dangerUnauthenticated: true })).not.toThrow();
	});
});
