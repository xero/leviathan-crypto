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
 * Seal — cipher-agnostic stream contract tests, parameterized over
 * `_cipher-spec.ts`. Per-cipher behaviors that vary in shape (header
 * binding, commitment field, native key-committing properties) live in
 * test/unit/stream/<cipher>-cipher-suite.test.ts.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { Seal, OpenStream, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { aesWasm }     from '../../../src/ts/aes/embedded.js';
import { sha2Wasm }    from '../../../src/ts/sha2/embedded.js';
import { CIPHER_SPECS } from './_cipher-spec.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, serpent: serpentWasm, aes: aesWasm, sha2: sha2Wasm });
});

// ── CipherSuite contract pinning ────────────────────────────────────────────

describe('CipherSuite contract pinning', () => {
	for (const spec of CIPHER_SPECS) {
		describe(spec.name, () => {
			it('keygen() returns a 32-byte Uint8Array', () => {
				const k = spec.suite.keygen();
				expect(k).toBeInstanceOf(Uint8Array);
				expect(k.length).toBe(spec.keySize);
			});

			it('keygen() produces independent keys', () => {
				const k1 = spec.suite.keygen();
				const k2 = spec.suite.keygen();
				expect(k1).not.toEqual(k2);
			});

			it('public field values are pinned', () => {
				expect(spec.suite.formatEnum).toBe(spec.formatEnum);
				expect(spec.suite.formatName).toBe(spec.formatName);
				expect(spec.suite.hkdfInfo).toBe(spec.hkdfInfo);
				expect(spec.suite.keySize).toBe(spec.keySize);
				expect(spec.suite.kemCtSize).toBe(spec.kemCtSize);
				expect(spec.suite.commitmentSize).toBe(spec.commitmentSize);
				expect(spec.suite.tagSize).toBe(spec.tagSize);
				expect(spec.suite.padded).toBe(spec.padded);
				expect(spec.suite.wasmChunkSize).toBe(spec.wasmChunkSize);
				expect(Array.from(spec.suite.wasmModules)).toEqual(Array.from(spec.wasmModules));
				expect(spec.suite.decKeySize).toBeUndefined();
			});
		});
	}
});

// ── Seal round-trips ────────────────────────────────────────────────────────

describe('Seal round-trips', () => {
	for (const spec of CIPHER_SPECS) {
		describe(spec.name, () => {
			it('encrypt/decrypt round-trip', () => {
				const key = spec.suite.keygen();
				const pt = randomBytes(256);
				const blob = Seal.encrypt(spec.suite, key, pt);
				const out  = Seal.decrypt(spec.suite, key, blob);
				expect(out).toEqual(pt);
			});

			it('encrypt/decrypt with AAD', () => {
				const key = spec.suite.keygen();
				const pt  = randomBytes(128);
				const aad = new TextEncoder().encode('seal-test-aad');
				const blob = Seal.encrypt(spec.suite, key, pt, { aad });
				const out  = Seal.decrypt(spec.suite, key, blob, { aad });
				expect(out).toEqual(pt);
			});

			it('decrypt with mismatched AAD throws with tag discriminator', () => {
				const key  = spec.suite.keygen();
				const pt   = randomBytes(64);
				const blob = Seal.encrypt(spec.suite, key, pt, { aad: new TextEncoder().encode('a') });
				let caught: Error | null = null;
				try {
					Seal.decrypt(spec.suite, key, blob, { aad: new TextEncoder().encode('b') });
				} catch (e) {
					caught = e as Error;
				}
				expect(caught).not.toBeNull();
				expect(caught!.message).toContain(spec.tagDiscriminator);
				expect(caught!.message).not.toContain('commitment-');
			});

			it('empty plaintext round-trip', () => {
				const key = spec.suite.keygen();
				const blob = Seal.encrypt(spec.suite, key, new Uint8Array(0));
				const out  = Seal.decrypt(spec.suite, key, blob);
				expect(out).toEqual(new Uint8Array(0));
			});

			it('blob = preamble || ciphertext, preamble byte[0] encodes formatEnum', () => {
				const key = spec.suite.keygen();
				const pt  = randomBytes(64);
				const blob = Seal.encrypt(spec.suite, key, pt);
				expect(blob.length).toBeGreaterThan(HEADER_SIZE + spec.commitmentSize);
				expect(blob[0] & 0x3f).toBe(spec.formatEnum);
			});
		});
	}
});

// ── Size-sweep round-trips (parameterized) ─────────────────────────────────
//
// Boundary-size regression test: every cipher must round-trip across the
// full range of plaintext sizes Seal supports, from empty (0) through
// the per-chunk WASM cap (65535). Catches regressions where a cipher
// mishandles edge sizes — empty input, single byte, exact block size,
// or sizes near the chunk boundary.

describe('Seal round-trips across plaintext sizes', () => {
	const SIZES = [0, 1, 16, 1024, 65535];
	for (const spec of CIPHER_SPECS) {
		describe(spec.name, () => {
			const key = spec.suite.keygen();
			for (const n of SIZES) {
				it(`plaintext size ${n}: encrypt → decrypt round-trips`, () => {
					const pt = randomBytes(n);
					const blob = Seal.encrypt(spec.suite, key, pt);
					const out = Seal.decrypt(spec.suite, key, blob);
					expect(Array.from(out)).toEqual(Array.from(pt));
				});
			}
		});
	}
});

// ── Seal._fromNonce determinism ─────────────────────────────────────────────

describe('Seal._fromNonce determinism', () => {
	for (const spec of CIPHER_SPECS) {
		describe(spec.name, () => {
			it('same inputs produce same blob twice', () => {
				const key   = spec.suite.keygen();
				const pt    = randomBytes(64);
				const nonce = randomBytes(16);
				const b1 = Seal._fromNonce(spec.suite, key, pt, nonce);
				const b2 = Seal._fromNonce(spec.suite, key, pt, nonce);
				expect(b1).toEqual(b2);
			});

			it('different nonces produce different blobs', () => {
				const key = spec.suite.keygen();
				const pt  = randomBytes(64);
				const b1 = Seal._fromNonce(spec.suite, key, pt, randomBytes(16));
				const b2 = Seal._fromNonce(spec.suite, key, pt, randomBytes(16));
				expect(b1).not.toEqual(b2);
			});
		});
	}
});

// ── Seal blob is OpenStream-compatible ──────────────────────────────────────

describe('Seal blob is OpenStream-compatible', () => {
	for (const spec of CIPHER_SPECS) {
		it(`${spec.name}: OpenStream.finalize decrypts Seal.encrypt output`, () => {
			const key  = spec.suite.keygen();
			const pt   = randomBytes(128);
			const blob = Seal.encrypt(spec.suite, key, pt);
			const preambleLen = HEADER_SIZE + spec.kemCtSize + spec.commitmentSize;
			const preamble = blob.subarray(0, preambleLen);
			const opener   = new OpenStream(spec.suite, key, preamble);
			const out = opener.finalize(blob.subarray(preambleLen));
			expect(out).toEqual(pt);
		});
	}
});

// ── Seal error handling — input validation ──────────────────────────────────

describe('Seal error handling', () => {
	for (const spec of CIPHER_SPECS) {
		describe(spec.name, () => {
			it('truncated blob throws RangeError', () => {
				const key = spec.suite.keygen();
				const tooShort = new Uint8Array(HEADER_SIZE - 1);
				expect(() => Seal.decrypt(spec.suite, key, tooShort)).toThrow(RangeError);
			});

			it('wrong suite throws format mismatch error', () => {
				// Pick the first OTHER cipher spec for the cross-decrypt attempt.
				const other = CIPHER_SPECS.find(s => s !== spec)!;
				const key  = spec.suite.keygen();
				const pt   = randomBytes(64);
				const blob = Seal.encrypt(spec.suite, key, pt);
				expect(() => Seal.decrypt(other.suite, key, blob))
					.toThrow(/expected format/);
			});
		});
	}
});

// ── Seal failure modes — discriminator-asserted ─────────────────────────────

describe('Seal failure modes', () => {
	for (const spec of CIPHER_SPECS) {
		describe(spec.name, () => {
			it('wrong key throws AuthenticationError', () => {
				const key      = spec.suite.keygen();
				const wrongKey = spec.suite.keygen();
				const pt   = randomBytes(64);
				const blob = Seal.encrypt(spec.suite, key, pt);
				let caught: Error | null = null;
				try {
					Seal.decrypt(spec.suite, wrongKey, blob);
				} catch (e) {
					caught = e as Error;
				}
				expect(caught).not.toBeNull();
				if (spec.commitDiscriminator) {
					// v3 ciphers fail at commitment check before AEAD touches anything.
					expect(caught!.message).toContain(spec.commitDiscriminator);
				} else {
					// Serpent has no commitment; wrong key surfaces as HMAC tag mismatch.
					expect(caught!.message).toContain(spec.tagDiscriminator);
					expect(caught!.message).not.toContain('commitment-');
				}
			});

			it('tampered tag throws AuthenticationError with tag discriminator', () => {
				const key  = spec.suite.keygen();
				const pt   = randomBytes(128);
				const blob = Seal.encrypt(spec.suite, key, pt).slice();
				// Tag is at the end. Flip a byte inside the trailing tag region.
				blob[blob.length - 4] ^= 0xff;
				let caught: Error | null = null;
				try {
					Seal.decrypt(spec.suite, key, blob);
				} catch (e) {
					caught = e as Error;
				}
				expect(caught).not.toBeNull();
				expect(caught!.message).toContain(spec.tagDiscriminator);
				// AEAD/HMAC tag mismatch, NOT commitment.
				expect(caught!.message).not.toContain('commitment-');
			});

			it('tampered ciphertext throws AuthenticationError with tag discriminator', () => {
				const key  = spec.suite.keygen();
				const pt   = randomBytes(128);
				const blob = Seal.encrypt(spec.suite, key, pt).slice();
				// Flip a byte in the middle of the ciphertext region: after the
				// preamble (header + commitment), before the trailing tag.
				const ctOffset = HEADER_SIZE + spec.commitmentSize + 10;
				blob[ctOffset] ^= 0xff;
				let caught: Error | null = null;
				try {
					Seal.decrypt(spec.suite, key, blob);
				} catch (e) {
					caught = e as Error;
				}
				expect(caught).not.toBeNull();
				expect(caught!.message).toContain(spec.tagDiscriminator);
				expect(caught!.message).not.toContain('commitment-');
			});
		});
	}
});
