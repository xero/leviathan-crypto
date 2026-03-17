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
import { init, SerpentSeal, hexToBytes, bytesToHex } from '../../../src/ts/index.js';
import { sealTC1, sealTC2 } from '../../vectors/serpent_composition.js';

let seal: SerpentSeal;

beforeAll(async () => {
	await init(['serpent', 'sha2']);
	seal = new SerpentSeal();
});

// ── TC1 known-answer ────────────────────────────────────────────────────────

describe('SerpentSeal KAT — TC1', () => {
	// GATE
	it('TC1 known-answer: encrypt with injected IV matches expected output', () => {
		const key = hexToBytes(sealTC1.key);
		const pt = hexToBytes(sealTC1.plaintext);
		const iv = hexToBytes(sealTC1.iv);
		const out = seal.encrypt(key, pt, iv);
		expect(bytesToHex(out)).toBe(sealTC1.ciphertext);
	});

	it('TC1 auth: flip byte in ciphertext body → throws', () => {
		const ct = hexToBytes(sealTC1.ciphertext).slice();
		ct[20] ^= 0x01; // flip a byte in the CBC ciphertext region
		const key = hexToBytes(sealTC1.key);
		expect(() => seal.decrypt(key, ct)).toThrow('SerpentSeal: authentication failed');
	});

	it('TC1 auth: flip byte in tag → throws', () => {
		const ct = hexToBytes(sealTC1.ciphertext).slice();
		ct[ct.length - 1] ^= 0x01; // flip last byte (tag region)
		const key = hexToBytes(sealTC1.key);
		expect(() => seal.decrypt(key, ct)).toThrow('SerpentSeal: authentication failed');
	});

	it('TC1 round-trip: encrypt then decrypt returns original plaintext', () => {
		const key = hexToBytes(sealTC1.key);
		const pt = hexToBytes(sealTC1.plaintext);
		const iv = hexToBytes(sealTC1.iv);
		const ct = seal.encrypt(key, pt, iv);
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
		const out = seal.encrypt(key, pt, iv);
		expect(bytesToHex(out)).toBe(sealTC2.ciphertext);
	});

	it('TC2 round-trip: decrypt TC2 output returns empty Uint8Array', () => {
		const key = hexToBytes(sealTC2.key);
		const ct = hexToBytes(sealTC2.ciphertext);
		const recovered = seal.decrypt(key, ct);
		expect(recovered.length).toBe(0);
	});
});
