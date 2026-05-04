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
 * KyberSuite — commitmentSize forwarding and end-to-end commitment round-trip.
 *
 * KyberSuite wraps a KEM around an inner symmetric CipherSuite. Salamander
 * mitigation is provided by the inner cipher (via commitmentSize > 0); the
 * wrapper just forwards. KEM-bound HKDF info already includes kemCt, so
 * for KyberSuite + XChaCha20 the commitment indirectly depends on kemCt
 * too — multi-recipient KEM envelopes get salamander resistance for free.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { KyberSuite } from '../../../src/ts/kyber/suite.js';
import { MlKem768 } from '../../../src/ts/kyber/index.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { SerpentCipher } from '../../../src/ts/serpent/cipher-suite.js';
import { Seal, SealStream, OpenStream, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { AuthenticationError } from '../../../src/ts/errors.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { kyberWasm } from '../../../src/ts/kyber/embedded.js';

beforeAll(async () => {
	await init({
		chacha20: chacha20Wasm,
		serpent: serpentWasm,
		sha2: sha2Wasm,
		sha3: sha3Wasm,
		kyber: kyberWasm,
	});
});

describe('KyberSuite — commitmentSize forwarding', () => {
	it('KyberSuite(MlKem768, XChaCha20Cipher).commitmentSize === 32', () => {
		const kem = new MlKem768();
		try {
			const suite = KyberSuite(kem, XChaCha20Cipher);
			expect(suite.commitmentSize).toBe(32);
		} finally {
			kem.dispose();
		}
	});

	it('KyberSuite(MlKem768, SerpentCipher).commitmentSize === 0', () => {
		const kem = new MlKem768();
		try {
			const suite = KyberSuite(kem, SerpentCipher);
			expect(suite.commitmentSize).toBe(0);
		} finally {
			kem.dispose();
		}
	});
});

describe('KyberSuite + XChaCha20 — commitment round-trip', () => {
	it('Seal.encrypt produces a blob whose preamble carries the inner commitment, decrypt verifies', () => {
		const kem = new MlKem768();
		try {
			const suite = KyberSuite(kem, XChaCha20Cipher);
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

	it('flipping a byte in the commitment region of a KyberSuite blob fails fast with AuthenticationError', () => {
		const kem = new MlKem768();
		try {
			const suite = KyberSuite(kem, XChaCha20Cipher);
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

	it('OpenStream over a KyberSuite preamble verifies commitment before chunk processing', () => {
		const kem = new MlKem768();
		try {
			const suite = KyberSuite(kem, XChaCha20Cipher);
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
