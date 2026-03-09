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
 * ChaCha20-Poly1305 AEAD test vectors
 *
 * Source: RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols", May 2018
 * URL: https://www.rfc-editor.org/rfc/rfc8439
 * Sections: §2.8 (AEAD construction), §2.8.2 (sunscreen example)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, ChaCha20Poly1305 } from '../../../src/ts/index.js';
import { chacha20Poly1305Vectors } from '../../vectors/chacha20.js';

const toHex = (b: Uint8Array): string =>
	Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

const fromHex = (hex: string): Uint8Array =>
	Uint8Array.from(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));

beforeAll(async () => {
	await init('chacha20');
});

// RFC 8439 §2.8.2 test vector
const TV       = chacha20Poly1305Vectors[0];
const RFC_KEY   = fromHex(TV.key);
const RFC_NONCE = fromHex(TV.nonce);
const RFC_AAD   = fromHex(TV.aad);
const RFC_PT    = new TextEncoder().encode(TV.ptText!);
const RFC_CT    = fromHex(TV.ct);
const RFC_TAG   = fromHex(TV.tag);

describe('ChaCha20-Poly1305 AEAD — RFC 8439', () => {

	// GATE — §2.8.2 sunscreen vector
	it('encrypt — RFC 8439 §2.8.2 sunscreen vector', () => {
		const aead = new ChaCha20Poly1305();
		const { ciphertext, tag } = aead.encrypt(RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD);
		expect(toHex(ciphertext)).toBe(toHex(RFC_CT));
		expect(toHex(tag)).toBe(toHex(RFC_TAG));
		aead.dispose();
	});

	it('decrypt — RFC 8439 §2.8.2 sunscreen vector recovers plaintext', () => {
		const aead = new ChaCha20Poly1305();
		const pt = aead.decrypt(RFC_KEY, RFC_NONCE, RFC_CT, RFC_TAG, RFC_AAD);
		expect(new TextDecoder().decode(pt)).toBe(TV.ptText);
		aead.dispose();
	});

	// Round-trips
	it('round-trip: 64-byte plaintext with AAD', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const aad   = crypto.getRandomValues(new Uint8Array(20));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt, aad);
		const recovered = aead.decrypt(key, nonce, ciphertext, tag, aad);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
	});

	it('round-trip: 100-byte plaintext (non-block-aligned)', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(100));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
		const recovered = aead.decrypt(key, nonce, ciphertext, tag);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
	});

	it('round-trip: 128-byte plaintext (2 ChaCha20 blocks)', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(128));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
		const recovered = aead.decrypt(key, nonce, ciphertext, tag);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
	});

	it('round-trip: empty plaintext with AAD', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const aad   = fromHex('deadbeef');
		const pt    = new Uint8Array(0);

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt, aad);
		expect(ciphertext.length).toBe(0);
		expect(tag.length).toBe(16);
		const recovered = aead.decrypt(key, nonce, ciphertext, tag, aad);
		expect(recovered.length).toBe(0);
		aead.dispose();
	});

	it('round-trip: plaintext with empty AAD', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(32));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
		const recovered = aead.decrypt(key, nonce, ciphertext, tag);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
	});

	// Tamper detection
	it('rejects tampered ciphertext', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
		const tampered = ciphertext.slice();
		tampered[0] ^= 0x01;

		expect(() => aead.decrypt(key, nonce, tampered, tag)).toThrow(
			'ChaCha20Poly1305: authentication failed',
		);
		aead.dispose();
	});

	it('rejects tampered tag', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
		const tampered = tag.slice();
		tampered[15] ^= 0xff;

		expect(() => aead.decrypt(key, nonce, ciphertext, tampered)).toThrow(
			'ChaCha20Poly1305: authentication failed',
		);
		aead.dispose();
	});

	it('rejects tampered AAD', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const aad   = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt, aad);
		const badAad = aad.slice();
		badAad[0] ^= 0x01;

		expect(() => aead.decrypt(key, nonce, ciphertext, tag, badAad)).toThrow(
			'ChaCha20Poly1305: authentication failed',
		);
		aead.dispose();
	});

	it('rejects wrong key on decrypt', () => {
		const aead   = new ChaCha20Poly1305();
		const key    = crypto.getRandomValues(new Uint8Array(32));
		const key2   = crypto.getRandomValues(new Uint8Array(32));
		const nonce  = crypto.getRandomValues(new Uint8Array(12));
		const pt     = crypto.getRandomValues(new Uint8Array(64));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
		expect(() => aead.decrypt(key2, nonce, ciphertext, tag)).toThrow(
			'ChaCha20Poly1305: authentication failed',
		);
		aead.dispose();
	});

	it('rejects wrong nonce on decrypt', () => {
		const aead   = new ChaCha20Poly1305();
		const key    = crypto.getRandomValues(new Uint8Array(32));
		const nonce  = crypto.getRandomValues(new Uint8Array(12));
		const nonce2 = crypto.getRandomValues(new Uint8Array(12));
		const pt     = crypto.getRandomValues(new Uint8Array(64));

		const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
		expect(() => aead.decrypt(key, nonce2, ciphertext, tag)).toThrow(
			'ChaCha20Poly1305: authentication failed',
		);
		aead.dispose();
	});

	// Input validation
	it('throws RangeError for non-32-byte key', () => {
		const aead  = new ChaCha20Poly1305();
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		expect(() => aead.encrypt(new Uint8Array(16), nonce, new Uint8Array(1))).toThrow(RangeError);
		expect(() => aead.encrypt(new Uint8Array(31), nonce, new Uint8Array(1))).toThrow(RangeError);
		aead.dispose();
	});

	it('throws RangeError for non-12-byte nonce', () => {
		const aead = new ChaCha20Poly1305();
		const key  = crypto.getRandomValues(new Uint8Array(32));
		expect(() => aead.encrypt(key, new Uint8Array(8),  new Uint8Array(1))).toThrow(RangeError);
		expect(() => aead.encrypt(key, new Uint8Array(24), new Uint8Array(1))).toThrow(RangeError);
		aead.dispose();
	});

	it('throws RangeError for non-16-byte tag on decrypt', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		expect(() => aead.decrypt(key, nonce, new Uint8Array(1), new Uint8Array(8))).toThrow(RangeError);
		aead.dispose();
	});

	// dispose
	it('dispose() then re-create works', () => {
		const aead = new ChaCha20Poly1305();
		aead.encrypt(RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD);
		aead.dispose();

		const aead2 = new ChaCha20Poly1305();
		const { ciphertext, tag } = aead2.encrypt(RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD);
		expect(toHex(ciphertext)).toBe(toHex(RFC_CT));
		expect(toHex(tag)).toBe(toHex(RFC_TAG));
		aead2.dispose();
	});
});
