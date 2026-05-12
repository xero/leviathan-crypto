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
 * AES-GCM-SIV cipher-suite contract tests, per-cipher behaviors that
 * vary in shape across ciphers (header binding, commitment field, native
 * key-committing properties).
 *
 * Cipher-agnostic stream contract tests (round-trip, AAD, blob format,
 * OpenStream-compat, error handling, wrong-key/tampered-tag/tampered-ct
 * failure modes) live in test/unit/stream/seal.test.ts and run for every
 * cipher in test/unit/stream/_cipher-spec.ts via parameterization.
 *
 * Every <cipher>-cipher-suite.test.ts file in this directory implements
 * the following describe blocks. Where the cipher's behavior differs in
 * shape (e.g., Serpent does not header-bind), the describe block is
 * still present, but the assertions are the inverse: the test name
 * describes what is being verified, and the body asserts the relevant
 * property holds.
 *
 *   - 'deriveKeys', commitment-or-no-commitment shape, plus header-
 *     binding effect on derived keys (or absence thereof for Serpent).
 *   - 'Header binding', header tamper effect on decrypt (failure for
 *     v3, no-effect for v2).
 *   - 'Commitment', flipping a byte in the commitment region rejects
 *     on decrypt (v3 only; Serpent's describe block asserts the
 *     preamble has no commitment region).
 *   - Cipher-specific behaviors below the shared describe blocks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { Seal, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { AESGCMSIVCipher } from '../../../src/ts/aes/cipher-suite.js';
import { aesWasm }  from '../../../src/ts/aes/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ aes: aesWasm, sha2: sha2Wasm });
});

describe('AES-GCM-SIV deriveKeys', () => {
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

			// Independent backing, mutating bytes does not affect commitment.
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

describe('AES-GCM-SIV header binding', () => {
	it('flipping the framed-flag bit in the header causes decrypt failure', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// formatEnum + framed flag occupies header byte 0. Flip the FLAG_FRAMED
		// bit (0x80). Tampering the header changes the HKDF info string, so
		// deriveKeys returns a different commitment, fails at the commitment
		// check before AEAD touches anything.
		blob[0] ^= 0x80;
		let caught: Error | null = null;
		try {
			Seal.decrypt(AESGCMSIVCipher, key, blob);
		} catch (e) {
			caught = e as Error;
		}
		expect(caught).not.toBeNull();
		expect(caught!.message).toContain('commitment-aes-gcm-siv');
	});

	it('flipping a byte in the chunkSize portion of the header causes decrypt failure', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// chunkSize is bytes 17..20 of the header.
		blob[18] ^= 0x01;
		let caught: Error | null = null;
		try {
			Seal.decrypt(AESGCMSIVCipher, key, blob);
		} catch (e) {
			caught = e as Error;
		}
		expect(caught).not.toBeNull();
		expect(caught!.message).toContain('commitment-aes-gcm-siv');
	});

	it('flipping a byte in the nonce portion of the header causes decrypt failure', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// Nonce occupies header bytes 1..17 (16 bytes after formatEnum byte).
		blob[5] ^= 0x40;
		let caught: Error | null = null;
		try {
			Seal.decrypt(AESGCMSIVCipher, key, blob);
		} catch (e) {
			caught = e as Error;
		}
		expect(caught).not.toBeNull();
		expect(caught!.message).toContain('commitment-aes-gcm-siv');
	});
});

describe('AES-GCM-SIV commitment', () => {
	it('flipping a byte in the commitment region throws AuthenticationError(commitment-aes-gcm-siv)', () => {
		const key  = AESGCMSIVCipher.keygen();
		const pt   = randomBytes(128);
		const blob = Seal.encrypt(AESGCMSIVCipher, key, pt).slice();
		// Commitment region is bytes [HEADER_SIZE .. HEADER_SIZE + 32).
		blob[HEADER_SIZE + 5] ^= 0xff;
		let caught: Error | null = null;
		try {
			Seal.decrypt(AESGCMSIVCipher, key, blob);
		} catch (e) {
			caught = e as Error;
		}
		expect(caught).not.toBeNull();
		expect(caught!.message).toContain('commitment-aes-gcm-siv');
	});
});
