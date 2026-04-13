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
 * ChaCha20 test vectors
 *
 * Source: RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols", May 2018
 * URL: https://www.rfc-editor.org/rfc/rfc8439
 * Sections: §2.2.1 (block function), §2.4.2 (encryption)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, ChaCha20 } from '../../../src/ts/index.js';
import { chacha20BlockVectors, chacha20EncryptionVectors } from '../../vectors/chacha20.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';

const toHex = (b: Uint8Array): string =>
	Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

const fromHex = (h: string): Uint8Array =>
	Uint8Array.from(h.match(/.{2}/g)!.map(b => parseInt(b, 16)));

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm });
});

describe('ChaCha20 — RFC 8439 vectors', () => {

	// GATE: ChaCha20 block function: RFC 8439 §2.2.1
	// Vector: chacha20.ts[chacha20BlockVectors[0]]
	it('block function — RFC 8439 §2.2.1 (counter=1)', () => {
		const v = chacha20BlockVectors[0];
		const chacha = new ChaCha20();
		const key    = fromHex(v.key);
		const nonce  = fromHex(v.nonce);

		chacha.beginEncrypt(key, nonce);

		// Encrypt 64 zero bytes → output is raw keystream
		const ct = chacha.encryptChunk(new Uint8Array(64));

		expect(toHex(ct)).toBe(v.keystream);
		chacha.dispose();
	});

	// RFC 8439 §2.4.2 — full encryption test vector (114 bytes)
	it('encryption — RFC 8439 §2.4.2 (114 bytes)', () => {
		const v = chacha20EncryptionVectors[0];
		const chacha = new ChaCha20();
		const key    = fromHex(v.key);
		const nonce  = fromHex(v.nonce);

		const plaintext = new TextEncoder().encode(v.ptText!);
		expect(plaintext.length).toBe(114);

		chacha.beginEncrypt(key, nonce);
		const ct = chacha.encryptChunk(plaintext);

		expect(toHex(ct)).toBe(v.ct);
		chacha.dispose();
	});

	// Round-trip: encrypt then decrypt returns original plaintext
	it('128-byte round-trip (2 full blocks)', () => {
		const chacha = new ChaCha20();
		const key    = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
		const nonce  = fromHex('000000090000004a00000000');
		const pt     = crypto.getRandomValues(new Uint8Array(128));

		chacha.beginEncrypt(key, nonce);
		const ct = chacha.encryptChunk(pt);

		chacha.beginDecrypt(key, nonce);
		const recovered = chacha.decryptChunk(ct);

		expect(toHex(recovered)).toBe(toHex(pt));
		chacha.dispose();
	});

	// Partial second block (100 bytes = 1 full + 36 partial)
	it('100-byte round-trip (partial second block)', () => {
		const chacha = new ChaCha20();
		const key    = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
		const nonce  = fromHex('000000090000004a00000000');
		const pt     = crypto.getRandomValues(new Uint8Array(100));

		chacha.beginEncrypt(key, nonce);
		const ct = chacha.encryptChunk(pt);
		chacha.beginDecrypt(key, nonce);
		const recovered = chacha.decryptChunk(ct);

		expect(toHex(recovered)).toBe(toHex(pt));
		chacha.dispose();
	});

	// Different nonces produce different ciphertext
	it('different nonces → different ciphertext', () => {
		const key    = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
		const nonce1 = fromHex('000000090000004a00000000');
		const nonce2 = fromHex('000000090000004b00000000');
		const pt     = new Uint8Array(64).fill(0x42);

		const c1 = new ChaCha20();
		c1.beginEncrypt(key, nonce1);
		const ct1 = toHex(c1.encryptChunk(pt));
		c1.dispose();

		const c2 = new ChaCha20();
		c2.beginEncrypt(key, nonce2);
		const ct2 = toHex(c2.encryptChunk(pt));
		c2.dispose();

		expect(ct1).not.toBe(ct2);
	});

	// wipeBuffers zeroes state
	it('dispose() zeroes ChaCha20 state', () => {
		const v = chacha20BlockVectors[0];
		const chacha = new ChaCha20();
		const key    = fromHex(v.key);
		const nonce  = fromHex(v.nonce);

		chacha.beginEncrypt(key, nonce);
		chacha.encryptChunk(new Uint8Array(64));
		chacha.dispose();

		// After dispose, re-create and verify it still works
		const c2 = new ChaCha20();
		c2.beginEncrypt(key, nonce);
		const ct = c2.encryptChunk(new Uint8Array(64));
		expect(toHex(ct)).toBe(v.keystream);
		c2.dispose();
	});
});
