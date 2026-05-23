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
 * MlKemSuite, commitmentSize forwarding and end-to-end commitment round-trip.
 *
 * MlKemSuite wraps a KEM around an inner symmetric CipherSuite. Salamander
 * mitigation is provided by the inner cipher (via commitmentSize > 0); the
 * wrapper just forwards. KEM-bound HKDF info already includes kemCt, so
 * for MlKemSuite + XChaCha20 the commitment indirectly depends on kemCt
 * too, multi-recipient KEM envelopes get salamander resistance for free.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { MlKemSuite } from '../../../src/ts/mlkem/suite.js';
import { MlKem512, MlKem768, MlKem1024 } from '../../../src/ts/mlkem/index.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { SerpentCipher } from '../../../src/ts/serpent/cipher-suite.js';
import { AESGCMSIVCipher } from '../../../src/ts/aes/cipher-suite.js';
import { Seal, SealStream, OpenStream, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { AuthenticationError } from '../../../src/ts/errors.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { mlkemWasm } from '../../../src/ts/mlkem/embedded.js';

beforeAll(async () => {
	await init({
		chacha20: chacha20Wasm,
		serpent: serpentWasm,
		aes: aesWasm,
		sha2: sha2Wasm,
		sha3: sha3Wasm,
		mlkem: mlkemWasm,
	});
});

describe('MlKemSuite, commitmentSize forwarding', () => {
	it('MlKemSuite(MlKem768, XChaCha20Cipher).commitmentSize === 32', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, XChaCha20Cipher);
			expect(suite.commitmentSize).toBe(32);
		} finally {
			kem.dispose();
		}
	});

	it('MlKemSuite(MlKem768, SerpentCipher).commitmentSize === 0', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, SerpentCipher);
			expect(suite.commitmentSize).toBe(0);
		} finally {
			kem.dispose();
		}
	});

	it('MlKemSuite(MlKem768, AESGCMSIVCipher).commitmentSize === 32', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			expect(suite.commitmentSize).toBe(32);
		} finally {
			kem.dispose();
		}
	});

	it('MlKemSuite(MlKem768, AESGCMSIVCipher).formatEnum === 0x24', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			expect(suite.formatEnum).toBe(0x24);
		} finally {
			kem.dispose();
		}
	});

	it('MlKemSuite(MlKem512, AESGCMSIVCipher).formatEnum === 0x14', () => {
		const kem = new MlKem512();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			expect(suite.formatEnum).toBe(0x14);
		} finally {
			kem.dispose();
		}
	});

	it('MlKemSuite(MlKem1024, AESGCMSIVCipher).formatEnum === 0x34', () => {
		const kem = new MlKem1024();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			expect(suite.formatEnum).toBe(0x34);
		} finally {
			kem.dispose();
		}
	});

	it('MlKemSuite(MlKem768, AESGCMSIVCipher).wasmModules covers aes, mlkem, sha3', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			const set = new Set(suite.wasmModules);
			expect(set.has('aes')).toBe(true);
			expect(set.has('mlkem')).toBe(true);
			expect(set.has('sha3')).toBe(true);
			// sha2 is a stream-layer (HKDF) dependency, not declared per-cipher.
			// MlKemSuite combines its inner cipher's wasmModules with mlkem+sha3;
			// sha2 is NOT in the set. Defense-in-depth pin so a future regression
			// that re-adds sha2 to AES's wasmModules trips this test.
			expect(set.has('sha2')).toBe(false);
		} finally {
			kem.dispose();
		}
	});

	it('MlKemSuite(MlKem768, AESGCMSIVCipher).kemCtSize === MlKem768 ct size (1088)', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			expect(suite.kemCtSize).toBe(1088);
		} finally {
			kem.dispose();
		}
	});
});

describe('MlKemSuite + XChaCha20, commitment round-trip', () => {
	it('Seal.encrypt produces a blob whose preamble carries the inner commitment, decrypt verifies', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, XChaCha20Cipher);
			const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen();
			const pt   = randomBytes(128);
			const blob = Seal.encrypt(suite, ek, pt);

			// Preamble layout: header(20) || kemCt(suite.kemCtSize) || commitment(32)
			const preambleLen = HEADER_SIZE + suite.kemCtSize + suite.commitmentSize;
			expect(blob.length).toBeGreaterThan(preambleLen);

			// Round-trip succeeds with correct dk
			const out = Seal.decrypt(suite, dk, blob);
			expect(out).toEqual(pt);
		} finally {
			kem.dispose();
		}
	});

	it('flipping a byte in the commitment region of a MlKemSuite blob fails fast with AuthenticationError', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, XChaCha20Cipher);
			const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen();
			const pt   = randomBytes(64);
			const blob = Seal.encrypt(suite, ek, pt).slice();

			// Commitment region: [HEADER_SIZE + kemCtSize, +32). Flip a byte.
			const commitOffset = HEADER_SIZE + suite.kemCtSize;
			blob[commitOffset + 4] ^= 0xff;

			let caught: Error | null = null;
			try {
				Seal.decrypt(suite, dk, blob);
			} catch (e) {
				caught = e as Error;
			}
			expect(caught).toBeInstanceOf(AuthenticationError);
			expect(caught!.message).toContain('commitment-mlkem768+xchacha20');
		} finally {
			kem.dispose();
		}
	});

	it('OpenStream over a MlKemSuite preamble verifies commitment before chunk processing', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, XChaCha20Cipher);
			const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen();
			const sealer = new SealStream(suite, ek);
			const preamble = sealer.preamble.slice();
			const ct = sealer.finalize(randomBytes(32));

			// Tamper one byte in commitment.
			preamble[HEADER_SIZE + suite.kemCtSize + 1] ^= 0x80;
			expect(() => new OpenStream(suite, dk, preamble))
				.toThrow(/commitment-mlkem768\+xchacha20/);

			// Untouched preamble: opener constructs cleanly.
			const cleanSealer = new SealStream(suite, ek);
			const cleanPreamble = cleanSealer.preamble;
			const cleanCt = cleanSealer.finalize(randomBytes(32));
			const opener = new OpenStream(suite, dk, cleanPreamble);
			expect(opener.finalize(cleanCt).length).toBe(32);
			void ct; // silence unused
		} finally {
			kem.dispose();
		}
	});
});

describe('MlKemSuite + AES-GCM-SIV, commitment round-trip', () => {
	it('Seal.encrypt produces a blob whose preamble carries the inner commitment, decrypt verifies', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen();
			const pt   = randomBytes(128);
			const blob = Seal.encrypt(suite, ek, pt);

			const preambleLen = HEADER_SIZE + suite.kemCtSize + suite.commitmentSize;
			expect(blob.length).toBeGreaterThan(preambleLen);

			const out = Seal.decrypt(suite, dk, blob);
			expect(out).toEqual(pt);
		} finally {
			kem.dispose();
		}
	});

	it('flipping a byte in the commitment region of a MlKemSuite blob fails fast with AuthenticationError', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen();
			const pt   = randomBytes(64);
			const blob = Seal.encrypt(suite, ek, pt).slice();

			const commitOffset = HEADER_SIZE + suite.kemCtSize;
			blob[commitOffset + 4] ^= 0xff;

			let caught: Error | null = null;
			try {
				Seal.decrypt(suite, dk, blob);
			} catch (e) {
				caught = e as Error;
			}
			expect(caught).toBeInstanceOf(AuthenticationError);
			expect(caught!.message).toContain('commitment-mlkem768+aes-gcm-siv');
		} finally {
			kem.dispose();
		}
	});

	it('OpenStream over a MlKemSuite preamble verifies commitment before chunk processing', () => {
		const kem = new MlKem768();
		try {
			const suite = MlKemSuite(kem, AESGCMSIVCipher);
			const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen();
			const sealer = new SealStream(suite, ek);
			const preamble = sealer.preamble.slice();
			const ct = sealer.finalize(randomBytes(32));

			preamble[HEADER_SIZE + suite.kemCtSize + 1] ^= 0x80;
			expect(() => new OpenStream(suite, dk, preamble))
				.toThrow(/commitment-mlkem768\+aes-gcm-siv/);

			const cleanSealer = new SealStream(suite, ek);
			const cleanPreamble = cleanSealer.preamble;
			const cleanCt = cleanSealer.finalize(randomBytes(32));
			const opener = new OpenStream(suite, dk, cleanPreamble);
			expect(opener.finalize(cleanCt).length).toBe(32);
			void ct;
		} finally {
			kem.dispose();
		}
	});

	it('cross-suite negative test: a blob sealed under MlKem768+xchacha20 does not decrypt under MlKem768+aes-gcm-siv', () => {
		const kem  = new MlKem768();
		const kem2 = new MlKem768();
		try {
			const suiteX = MlKemSuite(kem,  XChaCha20Cipher);
			const suiteA = MlKemSuite(kem2, AESGCMSIVCipher);
			const { encapsulationKey: ek, decapsulationKey: dk } = suiteX.keygen();
			const blob = Seal.encrypt(suiteX, ek, randomBytes(64));

			expect(() => Seal.decrypt(suiteA, dk, blob)).toThrow(/expected format/);
		} finally {
			kem.dispose();
			kem2.dispose();
		}
	});
});
