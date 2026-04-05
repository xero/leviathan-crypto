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
 * Seal — unified single-shot encrypt/decrypt tests.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { Seal, OpenStream, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { SerpentCipher } from '../../../src/ts/serpent/cipher-suite.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, serpent: serpentWasm, sha2: sha2Wasm });
});

// ── Symmetric round-trips ────────────────────────────────────────────────────

describe('Seal symmetric round-trips', () => {
	for (const [name, suite] of [
		['XChaCha20', XChaCha20Cipher] as const,
		['Serpent', SerpentCipher] as const,
	]) {
		describe(name, () => {
			const key = randomBytes(32);

			it('encrypt/decrypt round-trip', () => {
				const pt = randomBytes(256);
				const blob = Seal.encrypt(suite, key, pt);
				const out = Seal.decrypt(suite, key, blob);
				expect(out).toEqual(pt);
			});

			it('encrypt/decrypt with AAD', () => {
				const pt = randomBytes(128);
				const aad = new TextEncoder().encode('seal-test-aad');
				const blob = Seal.encrypt(suite, key, pt, { aad });
				const out = Seal.decrypt(suite, key, blob, { aad });
				expect(out).toEqual(pt);
			});

			it('empty plaintext round-trip', () => {
				const blob = Seal.encrypt(suite, key, new Uint8Array(0));
				const out = Seal.decrypt(suite, key, blob);
				expect(out).toEqual(new Uint8Array(0));
			});

			it('blob = preamble(20B) || ciphertext', () => {
				const pt = randomBytes(64);
				const blob = Seal.encrypt(suite, key, pt);
				// preamble is HEADER_SIZE for symmetric
				expect(blob.length).toBeGreaterThan(HEADER_SIZE);
				const preamble = blob.subarray(0, HEADER_SIZE);
				// preamble byte[0] encodes formatEnum (lower 6 bits)
				expect(preamble[0] & 0x3f).toBe(suite.formatEnum);
			});
		});
	}
});

// ── KAT: _fromNonce is deterministic ────────────────────────────────────────

describe('Seal._fromNonce determinism', () => {
	it('XChaCha20 — same inputs produce same blob twice', () => {
		const key   = randomBytes(32);
		const pt    = randomBytes(64);
		const nonce = randomBytes(16);
		const b1 = Seal._fromNonce(XChaCha20Cipher, key, pt, nonce);
		const b2 = Seal._fromNonce(XChaCha20Cipher, key, pt, nonce);
		expect(b1).toEqual(b2);
	});

	it('Serpent — same inputs produce same blob twice', () => {
		const key   = randomBytes(32);
		const pt    = randomBytes(64);
		const nonce = randomBytes(16);
		const b1 = Seal._fromNonce(SerpentCipher, key, pt, nonce);
		const b2 = Seal._fromNonce(SerpentCipher, key, pt, nonce);
		expect(b1).toEqual(b2);
	});

	it('different nonces produce different blobs', () => {
		const key = randomBytes(32);
		const pt  = randomBytes(64);
		const b1 = Seal._fromNonce(XChaCha20Cipher, key, pt, randomBytes(16));
		const b2 = Seal._fromNonce(XChaCha20Cipher, key, pt, randomBytes(16));
		expect(b1).not.toEqual(b2);
	});
});

// ── OpenStream can decrypt a Seal blob ───────────────────────────────────────

describe('Seal blob is OpenStream-compatible', () => {
	for (const [name, suite] of [
		['XChaCha20', XChaCha20Cipher] as const,
		['Serpent', SerpentCipher] as const,
	]) {
		it(`${name}: OpenStream.finalize decrypts Seal.encrypt output`, () => {
			const key  = randomBytes(32);
			const pt   = randomBytes(128);
			const blob = Seal.encrypt(suite, key, pt);
			const preamble = blob.subarray(0, HEADER_SIZE + suite.kemCtSize);
			const opener   = new OpenStream(suite, key, preamble);
			const out = opener.finalize(blob.subarray(HEADER_SIZE + suite.kemCtSize));
			expect(out).toEqual(pt);
		});
	}
});

// ── Error cases ──────────────────────────────────────────────────────────────

describe('Seal error handling', () => {
	it('truncated blob throws RangeError', () => {
		const key = randomBytes(32);
		const tooShort = new Uint8Array(HEADER_SIZE - 1);
		expect(() => Seal.decrypt(XChaCha20Cipher, key, tooShort)).toThrow(RangeError);
	});

	it('wrong suite throws format mismatch error', () => {
		const key  = randomBytes(32);
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(XChaCha20Cipher, key, pt);
		expect(() => Seal.decrypt(SerpentCipher, key, blob))
			.toThrow(/expected format/);
	});

	it('wrong key → authentication failure', () => {
		const key     = randomBytes(32);
		const wrongKey = randomBytes(32);
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(XChaCha20Cipher, key, pt);
		expect(() => Seal.decrypt(XChaCha20Cipher, wrongKey, blob)).toThrow();
	});

	it('tampered blob → authentication failure', () => {
		const key  = randomBytes(32);
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(XChaCha20Cipher, key, pt).slice();
		blob[blob.length - 1] ^= 0xff;
		expect(() => Seal.decrypt(XChaCha20Cipher, key, blob)).toThrow();
	});
});

// ── Cipher suite keygen() ────────────────────────────────────────────────────

describe('Regression: cipher keygen()', () => {
	it('XChaCha20Cipher.keygen() returns 32 bytes', () => {
		const k = XChaCha20Cipher.keygen();
		expect(k).toBeInstanceOf(Uint8Array);
		expect(k.length).toBe(32);
	});

	it('SerpentCipher.keygen() returns 32 bytes', () => {
		const k = SerpentCipher.keygen();
		expect(k).toBeInstanceOf(Uint8Array);
		expect(k.length).toBe(32);
	});

	it('XChaCha20Cipher.keygen() produces different keys each call', () => {
		const k1 = XChaCha20Cipher.keygen();
		const k2 = XChaCha20Cipher.keygen();
		expect(k1).not.toEqual(k2);
	});
});

// ── New CipherSuite properties ───────────────────────────────────────────────

describe('CipherSuite new properties', () => {
	it('XChaCha20Cipher.formatName', () => {
		expect(XChaCha20Cipher.formatName).toBe('xchacha20');
	});

	it('SerpentCipher.formatName', () => {
		expect(SerpentCipher.formatName).toBe('serpent');
	});

	it('XChaCha20Cipher.kemCtSize is 0', () => {
		expect(XChaCha20Cipher.kemCtSize).toBe(0);
	});

	it('SerpentCipher.kemCtSize is 0', () => {
		expect(SerpentCipher.kemCtSize).toBe(0);
	});

	it('symmetric suites have no decKeySize', () => {
		expect(XChaCha20Cipher.decKeySize).toBeUndefined();
		expect(SerpentCipher.decKeySize).toBeUndefined();
	});
});
