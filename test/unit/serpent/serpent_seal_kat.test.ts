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
 * SerpentSeal KAT tests — known-answer and authentication property tests.
 * Vectors are self-generated with IV injection seam, verified against primitives.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, SerpentSeal, AuthenticationError, hexToBytes, bytesToHex } from '../../../src/ts/index.js';
import { getWasm, readBytes } from '../helpers';
import { sealTC1, sealTC2 } from '../../vectors/serpent_composition.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

let seal: SerpentSeal;

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm });
	seal = new SerpentSeal();
});

// ── TC1 known-answer ────────────────────────────────────────────────────────

/* eslint-disable @typescript-eslint/no-explicit-any */
describe('SerpentSeal KAT — TC1', () => {
	// GATE
	it('TC1 known-answer: encrypt with injected IV matches expected output', () => {
		const key = hexToBytes(sealTC1.key);
		const pt = hexToBytes(sealTC1.plaintext);
		const iv = hexToBytes(sealTC1.iv);
		const out = (seal as any).encrypt(key, pt, undefined, iv);
		expect(bytesToHex(out)).toBe(sealTC1.ciphertext);
	});

	it('TC1 auth: flip byte in ciphertext body → throws', () => {
		const ct = hexToBytes(sealTC1.ciphertext).slice();
		ct[20] ^= 0x01; // flip a byte in the CBC ciphertext region
		const key = hexToBytes(sealTC1.key);
		expect(() => seal.decrypt(key, ct)).toThrow('serpent: authentication failed');
	});

	it('TC1 auth: flip byte in tag → throws', () => {
		const ct = hexToBytes(sealTC1.ciphertext).slice();
		ct[ct.length - 1] ^= 0x01; // flip last byte (tag region)
		const key = hexToBytes(sealTC1.key);
		expect(() => seal.decrypt(key, ct)).toThrow('serpent: authentication failed');
	});

	it('TC1 round-trip: encrypt then decrypt returns original plaintext', () => {
		const key = hexToBytes(sealTC1.key);
		const pt = hexToBytes(sealTC1.plaintext);
		const iv = hexToBytes(sealTC1.iv);
		const ct = (seal as any).encrypt(key, pt, undefined, iv);
		const recovered = seal.decrypt(key, ct);
		expect(bytesToHex(recovered)).toBe(sealTC1.plaintext);
	});
});

// ── TC2 known-answer ────────────────────────────────────────────────────────

describe('SerpentSeal KAT — TC2', () => {
	it('TC2 known-answer: empty plaintext, compare full output hex', () => {
		const key = hexToBytes(sealTC2.key);
		const pt = hexToBytes(sealTC2.plaintext);
		const iv = hexToBytes(sealTC2.iv);
		const out = (seal as any).encrypt(key, pt, undefined, iv);
		expect(bytesToHex(out)).toBe(sealTC2.ciphertext);
	});

	it('TC2 round-trip: decrypt TC2 output returns empty Uint8Array', () => {
		const key = hexToBytes(sealTC2.key);
		const ct = hexToBytes(sealTC2.ciphertext);
		const recovered = seal.decrypt(key, ct);
		expect(recovered.length).toBe(0);
	});
});

// ── Hidden IV validation ──────────────────────────────────────────────────────

describe('SerpentSeal — hidden IV validation', () => {
	it('wrong _iv length throws RangeError', () => {
		const key = hexToBytes(sealTC1.key);
		const pt = hexToBytes(sealTC1.plaintext);
		const badIv = new Uint8Array(8);
		expect(() => (seal as any).encrypt(key, pt, undefined, badIv))
			.toThrow(/_iv must be 16 bytes/);
	});
});

// ── Wipe-before-throw ─────────────────────────────────────────────────────────

describe('SerpentSeal — wipe-before-throw', () => {
	it('dispose() on auth failure wipes plaintext left by prior successful decrypt', () => {
		const key = hexToBytes(sealTC1.key);
		const goodCt = hexToBytes(sealTC1.ciphertext);

		// Step 1: successful decrypt — PT buffer now holds real plaintext
		const pt = seal.decrypt(key, goodCt);
		expect(pt.length).toBeGreaterThan(0);

		// Step 2: verify PT buffer in WASM is non-zero (contains prior plaintext)
		const ptOff = getWasm().getChunkPtOffset();
		const before = readBytes(ptOff, pt.length);
		expect(Array.from(before).some(b => b !== 0)).toBe(true);

		// Step 3: tampered decrypt — auth fails, dispose() wipes buffers
		const bad = goodCt.slice();
		bad[20] ^= 0x01;
		let caught: unknown;
		try {
			seal.decrypt(key, bad);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(AuthenticationError);

		// Step 4: verify PT buffer is now zeroed — prior plaintext wiped
		const after = readBytes(ptOff, pt.length);
		expect(Array.from(after).every(b => b === 0)).toBe(true);
	});
});

// ── No single-use guard on SerpentSeal ───────────────────────────────────────

describe('SerpentSeal — no encrypt guard (auto-nonce)', () => {
	it('encrypt() can be called multiple times — each call generates a fresh nonce', () => {
		const key = hexToBytes(sealTC1.key);
		const pt  = hexToBytes(sealTC1.plaintext);
		// Two encrypts on the same instance must both succeed
		const ct1 = seal.encrypt(key, pt);
		const ct2 = seal.encrypt(key, pt);
		// Both must decrypt correctly
		expect(bytesToHex(seal.decrypt(key, ct1))).toBe(sealTC1.plaintext);
		expect(bytesToHex(seal.decrypt(key, ct2))).toBe(sealTC1.plaintext);
	});
});
