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
 * Serpent cipher-suite contract tests — per-cipher behaviors that vary
 * in shape across ciphers (header binding, commitment field, native
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
 *   - 'deriveKeys' — commitment-or-no-commitment shape, plus header-
 *     binding effect on derived keys (or absence thereof for Serpent).
 *   - 'Header binding' — header tamper effect on decrypt (failure for
 *     v3, no-effect for v2).
 *   - 'Commitment' — flipping a byte in the commitment region rejects
 *     on decrypt (v3 only; Serpent's describe block asserts the
 *     preamble has no commitment region).
 *   - Cipher-specific behaviors below the shared describe blocks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { Seal, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { writeHeader } from '../../../src/ts/stream/header.js';
import { SerpentCipher } from '../../../src/ts/serpent/cipher-suite.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm }    from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm });
});

describe('Serpent deriveKeys', () => {
	it('returns 96-byte bytes (enc_key + mac_key + iv_key), no commitment field', () => {
		const key = SerpentCipher.keygen();
		const nonce = randomBytes(16);
		const dk = SerpentCipher.deriveKeys(key, nonce);
		try {
			expect(dk.bytes).toBeInstanceOf(Uint8Array);
			expect(dk.bytes.length).toBe(96);
			expect(dk.commitment).toBeUndefined();
		} finally {
			SerpentCipher.wipeKeys(dk);
		}
	});

	it('different nonces produce different derived keys', () => {
		const key = SerpentCipher.keygen();
		const dk1 = SerpentCipher.deriveKeys(key, new Uint8Array(16).fill(1));
		const dk2 = SerpentCipher.deriveKeys(key, new Uint8Array(16).fill(2));
		try {
			expect(Array.from(dk1.bytes)).not.toEqual(Array.from(dk2.bytes));
		} finally {
			SerpentCipher.wipeKeys(dk1);
			SerpentCipher.wipeKeys(dk2);
		}
	});

	it('does not throw when header is undefined', () => {
		// Inverse of v3 ciphers: Serpent ignores the header argument in
		// deriveKeys (no header-binding). The call must succeed.
		const key = SerpentCipher.keygen();
		const nonce = randomBytes(16);
		const dk = SerpentCipher.deriveKeys(key, nonce);
		try {
			expect(dk.bytes.length).toBe(96);
		} finally {
			SerpentCipher.wipeKeys(dk);
		}
	});

	it('produces identical derived keys for different headers (Serpent does not header-bind)', () => {
		// Pin the not-header-binding contract: same key+nonce, two different
		// headers → identical bytes. Regression for "Serpent stays unbound".
		const key = SerpentCipher.keygen();
		const nonce = randomBytes(16);
		const headerA = writeHeader(SerpentCipher.formatEnum, false, nonce, 1024);
		const headerB = writeHeader(SerpentCipher.formatEnum, true,  nonce, 1024);
		const dkA = SerpentCipher.deriveKeys(key, nonce, undefined, headerA);
		const dkB = SerpentCipher.deriveKeys(key, nonce, undefined, headerB);
		try {
			expect(Array.from(dkA.bytes)).toEqual(Array.from(dkB.bytes));
		} finally {
			SerpentCipher.wipeKeys(dkA);
			SerpentCipher.wipeKeys(dkB);
		}
	});
});

describe('Serpent header binding', () => {
	// Inverse of AES/XChaCha20: header tampering does NOT break decryption
	// for Serpent. The contract here is "decryption succeeds when header is
	// tampered post-encryption, modulo structurally-validated fields."
	//
	// Note: byte 0 (formatEnum/framed) IS structurally validated by
	// OpenStream — flipping cipher nibble triggers format-mismatch, flipping
	// FLAG_FRAMED makes the decoder strip a length prefix that isn't there.
	// So we tamper bytes that are NOT structurally validated (chunkSize) and
	// nonce (which DOES feed deriveKeys via HKDF salt → HMAC fails).

	it('flipping a byte in the chunkSize portion of the header does NOT cause decrypt failure', () => {
		// Serpent does not bind chunkSize into deriveKeys, and Seal.encrypt
		// chooses chunkSize = max(pt.length, CHUNK_MIN=1024). For pt.length=64
		// the original chunkSize is 1024 (bytes 17..19 = 0x00 0x04 0x00).
		// Flipping byte 18 from 0x04 to 0x05 raises chunkSize to 1280 — still
		// in [CHUNK_MIN, CHUNK_MAX], and the wire chunk fits inside the
		// expanded maxWireChunk. The HMAC was computed over the actual
		// ciphertext (not the header), so the tag still verifies.
		const key  = SerpentCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(SerpentCipher, key, pt).slice();
		blob[18] ^= 0x01;
		const out = Seal.decrypt(SerpentCipher, key, blob);
		expect(Array.from(out)).toEqual(Array.from(pt));
	});

	it('flipping a byte in the nonce portion of the header DOES cause decrypt failure (HMAC, not commitment)', () => {
		// Even without header binding, the nonce IS used in deriveKeys (HKDF
		// salt). Tampering the header's nonce produces different derived
		// keys → HMAC fails. So this test asserts FAILURE for Serpent too,
		// but the discriminator is 'serpent' (HMAC tag mismatch), NOT
		// 'commitment-' anything.
		const key  = SerpentCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(SerpentCipher, key, pt).slice();
		blob[5] ^= 0x40;
		let caught: Error | null = null;
		try {
			Seal.decrypt(SerpentCipher, key, blob);
		} catch (e) {
			caught = e as Error;
		}
		expect(caught).not.toBeNull();
		expect(caught!.message).toContain('serpent');
		expect(caught!.message).not.toContain('commitment-');
	});
});

describe('Serpent commitment', () => {
	it('preamble has no commitment region (commitmentSize === 0)', () => {
		// Pin the contract that Serpent's preamble length === HEADER_SIZE
		// (no extra 32 bytes). Distinguishes Serpent from AES + XChaCha20,
		// which carry a 32-byte commitment between header and ciphertext.
		expect(SerpentCipher.commitmentSize).toBe(0);

		// Cross-check: a Serpent blob's first ciphertext byte appears at
		// offset HEADER_SIZE, with no 32-byte commitment in between. We
		// verify the preamble length used by OpenStream's reader matches
		// HEADER_SIZE + 0 (no commitment) + 0 (no kemCt).
		const key  = SerpentCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(SerpentCipher, key, pt);
		const expectedPreambleLen = HEADER_SIZE + SerpentCipher.kemCtSize + SerpentCipher.commitmentSize;
		expect(expectedPreambleLen).toBe(HEADER_SIZE);
		// Round-trip through that preamble length.
		expect(blob.length).toBeGreaterThan(expectedPreambleLen);
	});

	it('is natively key-committing via HMAC-SHA-256 (wrong key → tag mismatch with serpent discriminator)', () => {
		// Serpent's "key commitment" property is intrinsic to its
		// encrypt-then-MAC construction with HMAC. Wrong key → different
		// mac_key → HMAC tag mismatch for any ct. This is the analogue of
		// the v3 commitment-fast-fail, just using a different mechanism
		// (HMAC vs explicit 32-byte commitment field). The failure surface:
		// 'serpent' discriminator, NOT 'commitment-' anything.
		const key      = SerpentCipher.keygen();
		const wrongKey = SerpentCipher.keygen();
		const pt   = randomBytes(64);
		const blob = Seal.encrypt(SerpentCipher, key, pt);
		let caught: Error | null = null;
		try {
			Seal.decrypt(SerpentCipher, wrongKey, blob);
		} catch (e) {
			caught = e as Error;
		}
		expect(caught).not.toBeNull();
		expect(caught!.message).toContain('serpent');
		expect(caught!.message).not.toContain('commitment-');
	});
});
