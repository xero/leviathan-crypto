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
// XChaCha20Seal unit tests.
//
import { describe, it, expect, beforeAll } from 'vitest';
import { init, XChaCha20Seal, randomBytes } from '../../../src/ts/index.js';

const toHex = (b: Uint8Array): string =>
	Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

beforeAll(async () => {
	await init('chacha20');
});

// ── Gate ──────────────────────────────────────────────────────────────────────
// GATE

describe('XChaCha20Seal — gate', () => {
	it('encrypt() → decrypt() round-trip returns original plaintext', () => {
		const key = randomBytes(32);
		const seal = new XChaCha20Seal(key);
		const pt   = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
		const ct   = seal.encrypt(pt);
		const rt   = seal.decrypt(ct);
		expect(rt).toEqual(pt);
		seal.dispose();
	});
});

// ── Wire format ───────────────────────────────────────────────────────────────

describe('XChaCha20Seal — wire format', () => {
	it('ciphertext length is plaintext.length + 40 (nonce + tag)', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const pt   = new Uint8Array(100);
		const ct   = seal.encrypt(pt);
		expect(ct.length).toBe(140); // 100 + 24 + 16
		seal.dispose();
	});

	it('empty plaintext produces 40-byte ciphertext (nonce + tag only)', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const ct   = seal.encrypt(new Uint8Array(0));
		expect(ct.length).toBe(40);
		seal.dispose();
	});

	it('first 24 bytes of ciphertext are the nonce', () => {
		// Inject a known nonce via test seam and verify it appears in wire output
		const key   = new Uint8Array(32);
		const nonce = new Uint8Array(24).fill(0xab);
		const seal  = new XChaCha20Seal(key);
		const ct    = seal.encrypt(new Uint8Array([0x01, 0x02]), new Uint8Array(0), nonce);
		expect(toHex(ct.subarray(0, 24))).toBe('ab'.repeat(24));
		seal.dispose();
	});

	it('two encrypt() calls produce different nonces', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const ct1  = seal.encrypt(new Uint8Array([0x01]));
		const ct2  = seal.encrypt(new Uint8Array([0x01]));
		// Nonces (first 24 bytes) must differ
		expect(toHex(ct1.subarray(0, 24))).not.toBe(toHex(ct2.subarray(0, 24)));
		seal.dispose();
	});
});

// ── AAD ───────────────────────────────────────────────────────────────────────

describe('XChaCha20Seal — AAD', () => {
	it('AAD is authenticated: wrong AAD on decrypt throws', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const pt   = new Uint8Array([0xde, 0xad]);
		const aad  = new Uint8Array([0x01, 0x02, 0x03]);
		const ct   = seal.encrypt(pt, aad);
		expect(() => seal.decrypt(ct, new Uint8Array([0xff]))).toThrow();
		seal.dispose();
	});

	it('correct AAD allows decryption', () => {
		const key  = randomBytes(32);
		const seal = new XChaCha20Seal(key);
		const pt   = new Uint8Array([0xca, 0xfe]);
		const aad  = new Uint8Array([0x01, 0x02]);
		const ct   = seal.encrypt(pt, aad);
		const rt   = seal.decrypt(ct, aad);
		expect(rt).toEqual(pt);
		seal.dispose();
	});

	it('no AAD matches empty AAD', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const pt   = new Uint8Array([0x11, 0x22]);
		const ct   = seal.encrypt(pt);
		const rt   = seal.decrypt(ct, new Uint8Array(0));
		expect(rt).toEqual(pt);
		seal.dispose();
	});
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('XChaCha20Seal — authentication', () => {
	it('tampered ciphertext body throws', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const ct   = seal.encrypt(new Uint8Array([0x01, 0x02, 0x03, 0x04]));
		const bad  = ct.slice();
		bad[24] ^= 0x01; // flip a byte in the ciphertext region (after nonce)
		expect(() => seal.decrypt(bad)).toThrow();
		seal.dispose();
	});

	it('tampered tag throws', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const ct   = seal.encrypt(new Uint8Array([0x01, 0x02]));
		const bad  = ct.slice();
		bad[bad.length - 1] ^= 0x01; // flip last byte (tag)
		expect(() => seal.decrypt(bad)).toThrow();
		seal.dispose();
	});

	it('tampered nonce throws (derives wrong key)', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const ct   = seal.encrypt(new Uint8Array([0x01, 0x02]));
		const bad  = ct.slice();
		bad[0] ^= 0x01; // flip a byte in the nonce
		expect(() => seal.decrypt(bad)).toThrow();
		seal.dispose();
	});
});

// ── Input validation ──────────────────────────────────────────────────────────

describe('XChaCha20Seal — input validation', () => {
	it('constructor throws on wrong key length', () => {
		expect(() => new XChaCha20Seal(new Uint8Array(16))).toThrow(RangeError);
		expect(() => new XChaCha20Seal(new Uint8Array(31))).toThrow(RangeError);
		expect(() => new XChaCha20Seal(new Uint8Array(33))).toThrow(RangeError);
	});

	it('decrypt() throws on ciphertext shorter than 40 bytes', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		expect(() => seal.decrypt(new Uint8Array(39))).toThrow(RangeError);
		expect(() => seal.decrypt(new Uint8Array(0))).toThrow(RangeError);
		seal.dispose();
	});

	it('decrypt() accepts exactly 40 bytes (empty plaintext case)', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		const ct   = seal.encrypt(new Uint8Array(0));
		expect(ct.length).toBe(40);
		const rt = seal.decrypt(ct);
		expect(rt.length).toBe(0);
		seal.dispose();
	});
});

// ── Key isolation ─────────────────────────────────────────────────────────────

describe('XChaCha20Seal — key isolation', () => {
	it('different keys produce different ciphertext', () => {
		const seal1 = new XChaCha20Seal(new Uint8Array(32).fill(0x01));
		const seal2 = new XChaCha20Seal(new Uint8Array(32).fill(0x02));
		const pt    = new Uint8Array(16).fill(0xaa);
		// Use same injected nonce so only key differs
		const nonce = new Uint8Array(24);
		const ct1   = seal1.encrypt(pt, new Uint8Array(0), nonce);
		const ct2   = seal2.encrypt(pt, new Uint8Array(0), nonce);
		// Nonces are equal, ciphertext bodies must differ
		expect(toHex(ct1.subarray(24))).not.toBe(toHex(ct2.subarray(24)));
		seal1.dispose(); seal2.dispose();
	});

	it('wrong key on decrypt throws', () => {
		const seal1 = new XChaCha20Seal(randomBytes(32));
		const seal2 = new XChaCha20Seal(randomBytes(32));
		const ct    = seal1.encrypt(new Uint8Array([0x01, 0x02]));
		expect(() => seal2.decrypt(ct)).toThrow();
		seal1.dispose(); seal2.dispose();
	});
});

// ── Lifecycle ─────────────────────────────────────────────────────────────────

describe('XChaCha20Seal — lifecycle', () => {
	it('dispose() does not throw', () => {
		const seal = new XChaCha20Seal(randomBytes(32));
		expect(() => seal.dispose()).not.toThrow();
	});
});
