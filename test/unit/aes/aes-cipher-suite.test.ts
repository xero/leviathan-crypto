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
// test/unit/aes/aes-cipher-suite.test.ts
//
// AESGCMSIVCipher coverage at the cipher-suite layer. Pins the public
// CipherSuite contract values, exercises end-to-end Seal round-trips
// for every plaintext-size class, and asserts the HtE explicit
// commitment + header binding properties that close the Invisible
// Salamanders surface for AES-GCM-SIV.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { Seal, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { AESGCMSIVCipher } from '../../../src/ts/aes/cipher-suite.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ aes: aesWasm, sha2: sha2Wasm });
});

describe('AESGCMSIVCipher — CipherSuite contract', () => {
	it('keygen() returns 32 bytes', () => {
		const k = AESGCMSIVCipher.keygen();
		expect(k).toBeInstanceOf(Uint8Array);
		expect(k.length).toBe(32);
	});

	it('keygen() produces independent keys', () => {
		const k1 = AESGCMSIVCipher.keygen();
		const k2 = AESGCMSIVCipher.keygen();
		expect(k1).not.toEqual(k2);
	});

	it('public field values are pinned (formatEnum, sizes, modules)', () => {
		expect(AESGCMSIVCipher.formatEnum).toBe(0x04);
		expect(AESGCMSIVCipher.formatName).toBe('aes-gcm-siv');
		expect(AESGCMSIVCipher.hkdfInfo).toBe('aes-gcm-siv-sealstream-v3');
		expect(AESGCMSIVCipher.keySize).toBe(32);
		expect(AESGCMSIVCipher.kemCtSize).toBe(0);
		expect(AESGCMSIVCipher.commitmentSize).toBe(32);
		expect(AESGCMSIVCipher.tagSize).toBe(16);
		expect(AESGCMSIVCipher.padded).toBe(false);
		expect(AESGCMSIVCipher.wasmChunkSize).toBe(65536);
		expect(AESGCMSIVCipher.wasmModules).toEqual(['aes', 'sha2']);
		expect(AESGCMSIVCipher.decKeySize).toBeUndefined();
	});
});

describe('AESGCMSIVCipher.deriveKeys', () => {
	it('returns 32-byte bytes + 32-byte commitment with independent backing', () => {
		const key = randomBytes(32);
		const nonce = randomBytes(16);
		const blob = Seal._fromNonce(AESGCMSIVCipher, key, new Uint8Array(0), nonce);
		const header = blob.subarray(0, HEADER_SIZE);

		const dk = AESGCMSIVCipher.deriveKeys(key, nonce, undefined, header);
		try {
			expect(dk.bytes).toBeInstanceOf(Uint8Array);
			expect(dk.bytes.length).toBe(32);
			expect(dk.commitment).toBeInstanceOf(Uint8Array);
			expect(dk.commitment!.length).toBe(32);

			// Independent backing — mutating bytes does not affect commitment.
			const commitmentCopy = new Uint8Array(dk.commitment!);
			dk.bytes.fill(0xff);
			expect(Array.from(dk.commitment!)).toEqual(Array.from(commitmentCopy));
		} finally {
			AESGCMSIVCipher.wipeKeys(dk);
		}
	});

	it('throws when header is undefined', () => {
		const key = randomBytes(32);
		const nonce = randomBytes(16);
		expect(() => AESGCMSIVCipher.deriveKeys(key, nonce))
			.toThrow(/header binding required/);
	});

	it('throws when header is the wrong length', () => {
		const key = randomBytes(32);
		const nonce = randomBytes(16);
		expect(() => AESGCMSIVCipher.deriveKeys(key, nonce, undefined, new Uint8Array(HEADER_SIZE - 1)))
			.toThrow(/header binding required/);
		expect(() => AESGCMSIVCipher.deriveKeys(key, nonce, undefined, new Uint8Array(HEADER_SIZE + 1)))
			.toThrow(/header binding required/);
	});

	it('different nonces produce different derived keys + commitments', () => {
		const key = randomBytes(32);
		const header = new Uint8Array(HEADER_SIZE);
		header[0] = AESGCMSIVCipher.formatEnum;

		const dk1 = AESGCMSIVCipher.deriveKeys(key, new Uint8Array(16).fill(1), undefined, header);
		const dk2 = AESGCMSIVCipher.deriveKeys(key, new Uint8Array(16).fill(2), undefined, header);
		try {
			expect(Array.from(dk1.bytes)).not.toEqual(Array.from(dk2.bytes));
			expect(Array.from(dk1.commitment!)).not.toEqual(Array.from(dk2.commitment!));
		} finally {
			AESGCMSIVCipher.wipeKeys(dk1);
			AESGCMSIVCipher.wipeKeys(dk2);
		}
	});
});

describe('Seal round-trips with AESGCMSIVCipher', () => {
	const key = AESGCMSIVCipher.keygen();
	const SIZES = [0, 1, 16, 1024, 65535];

	for (const n of SIZES) {
		it(`plaintext size ${n}: encrypt → decrypt round-trips`, () => {
			const pt = randomBytes(n);
			const blob = Seal.encrypt(AESGCMSIVCipher, key, pt);
			const out = Seal.decrypt(AESGCMSIVCipher, key, blob);
			expect(Array.from(out)).toEqual(Array.from(pt));
		});
	}

	it('encrypt with AAD then decrypt with same AAD round-trips', () => {
		const pt  = randomBytes(64);
		const aad = new TextEncoder().encode('aes-gcm-siv-aad');
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt, { aad });
		const out  = Seal.decrypt(AESGCMSIVCipher, key, blob, { aad });
		expect(Array.from(out)).toEqual(Array.from(pt));
	});

	it('decrypt with mismatched AAD throws AuthenticationError', () => {
		const pt = randomBytes(64);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt, { aad: new TextEncoder().encode('a') });
		expect(() => Seal.decrypt(AESGCMSIVCipher, key, blob, { aad: new TextEncoder().encode('b') }))
			.toThrow(/aes-gcm-siv/);
	});
});

describe('Seal failure modes with AESGCMSIVCipher', () => {
	it('wrong key fails on commitment first (commitment-aes-gcm-siv discriminator)', () => {
		const key      = AESGCMSIVCipher.keygen();
		const wrongKey = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt);
		let caught: Error | null = null;
		try {
			Seal.decrypt(AESGCMSIVCipher, wrongKey, blob);
		} catch (e) {
			caught = e as Error;
		}
		expect(caught).not.toBeNull();
		expect(caught!.message).toContain('commitment-aes-gcm-siv');
	});

	it('tampered tag throws AuthenticationError(aes-gcm-siv)', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(128);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// flip a byte in the trailing 16-byte tag (last 16 bytes of the blob).
		blob[blob.length - 4] ^= 0xff;
		let caught: Error | null = null;
		try {
			Seal.decrypt(AESGCMSIVCipher, key, blob);
		} catch (e) {
			caught = e as Error;
		}
		expect(caught).not.toBeNull();
		// Discriminator is 'aes-gcm-siv' (without the 'commitment-' prefix);
		// this is the AEAD tag mismatch, not the commitment.
		expect(caught!.message).toContain('aes-gcm-siv');
	});

	it('tampered ciphertext throws AuthenticationError(aes-gcm-siv)', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(128);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// flip a byte in the middle of the ciphertext region (after preamble,
		// before the trailing 16-byte tag)
		const ctOffset = HEADER_SIZE + 32 + 10;   // header + commitment + a few bytes in
		blob[ctOffset] ^= 0xff;
		expect(() => Seal.decrypt(AESGCMSIVCipher, key, blob)).toThrow();
	});
});

describe('Header binding (deriveKeys info = INFO || header)', () => {
	it('flipping the framed-flag bit in the header causes decrypt failure', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// formatEnum + framed flag occupies header byte 0. Flip the FLAG_FRAMED
		// bit (0x80). If Seal stores framed off (it does), this flips it on
		// without touching the cipher nibble.
		blob[0] ^= 0x80;
		expect(() => Seal.decrypt(AESGCMSIVCipher, key, blob)).toThrow();
	});

	it('flipping a byte in the chunkSize portion of the header causes decrypt failure', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// chunkSize is bytes 17..20 of the header.
		blob[18] ^= 0x01;
		expect(() => Seal.decrypt(AESGCMSIVCipher, key, blob)).toThrow();
	});

	it('flipping a byte in the nonce portion of the header causes decrypt failure', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// Nonce occupies header bytes 1..17 (16 bytes after formatEnum byte).
		blob[5] ^= 0x40;
		expect(() => Seal.decrypt(AESGCMSIVCipher, key, blob)).toThrow();
	});
});

