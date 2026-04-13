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
 * KyberSuite — hybrid KEM + symmetric AEAD cipher suite tests.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { KyberSuite } from '../../../src/ts/kyber/suite.js';
import { MlKem512, MlKem768, MlKem1024 } from '../../../src/ts/kyber/index.js';
import { MLKEM512, MLKEM768, MLKEM1024 } from '../../../src/ts/kyber/params.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { SerpentCipher } from '../../../src/ts/serpent/cipher-suite.js';
import { Seal, SealStream, OpenStream, HEADER_SIZE } from '../../../src/ts/stream/index.js';
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

// ── Round-trip: 3 param sets × 2 inner ciphers ──────────────────────────────

const PARAM_SETS = [
	['MlKem512',  () => new MlKem512(),  MLKEM512,  0x10] as const,
	['MlKem768',  () => new MlKem768(),  MLKEM768,  0x20] as const,
	['MlKem1024', () => new MlKem1024(), MLKEM1024, 0x30] as const,
];

const INNER_CIPHERS = [
	['XChaCha20', XChaCha20Cipher, 0x01] as const,
	['Serpent',   SerpentCipher,   0x02] as const,
];

for (const [kemName, mkKem, params, kemNibble] of PARAM_SETS) {
	for (const [cipherName, inner, cipherNibble] of INNER_CIPHERS) {
		describe(`KyberSuite: ${kemName} + ${cipherName}`, () => {
			it('Seal encrypt/decrypt round-trip', () => {
				const kem = mkKem();
				const suite = KyberSuite(kem, inner);
				const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen();
				const pt   = randomBytes(128);
				const blob = Seal.encrypt(suite, ek, pt);
				const out  = Seal.decrypt(suite, dk, blob);
				expect(out).toEqual(pt);
				kem.dispose();
			});

			it('preamble length is HEADER_SIZE + kemCtSize', () => {
				const kem = mkKem();
				const suite = KyberSuite(kem, inner);
				const { encapsulationKey: ek } = suite.keygen();
				const pt    = randomBytes(64);
				const blob  = Seal.encrypt(suite, ek, pt);
				const expectedPreambleLen = HEADER_SIZE + params.ctBytes;
				expect(suite.kemCtSize).toBe(params.ctBytes);
				expect(blob.length).toBeGreaterThan(expectedPreambleLen);
				// First expectedPreambleLen bytes are preamble
				const preamble = blob.subarray(0, expectedPreambleLen);
				expect(preamble.length).toBe(expectedPreambleLen);
				kem.dispose();
			});

			it('format enum = KEM nibble | cipher nibble', () => {
				const kem = mkKem();
				const suite = KyberSuite(kem, inner);
				expect(suite.formatEnum).toBe(kemNibble | cipherNibble);
				kem.dispose();
			});

			it('formatName', () => {
				const kem = mkKem();
				const suite = KyberSuite(kem, inner);
				const kemLabel = kemName === 'MlKem512' ? 'mlkem512' : kemName === 'MlKem768' ? 'mlkem768' : 'mlkem1024';
				const innerLabel = cipherName === 'XChaCha20' ? 'xchacha20' : 'serpent';
				expect(suite.formatName).toBe(`${kemLabel}+${innerLabel}`);
				kem.dispose();
			});

			it('keygen() returns correct key sizes', () => {
				const kem = mkKem();
				const suite = KyberSuite(kem, inner);
				const kp = suite.keygen();
				expect(kp.encapsulationKey.length).toBe(params.ekBytes);
				expect(kp.decapsulationKey.length).toBe(params.dkBytes);
				expect(suite.keySize).toBe(params.ekBytes);
				expect(suite.decKeySize).toBe(params.dkBytes);
				kem.dispose();
			});

			it('SealStream / OpenStream streaming round-trip', () => {
				const kem = mkKem();
				const suite = KyberSuite(kem, inner);
				const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen();
				const chunks = [randomBytes(128), randomBytes(256), randomBytes(64)];

				const sealer = new SealStream(suite, ek);
				const preamble = sealer.preamble;
				const ct0 = sealer.push(chunks[0]);
				const ct1 = sealer.push(chunks[1]);
				const ctF = sealer.finalize(chunks[2]);

				const opener = new OpenStream(suite, dk, preamble);
				expect(opener.pull(ct0)).toEqual(chunks[0]);
				expect(opener.pull(ct1)).toEqual(chunks[1]);
				expect(opener.finalize(ctF)).toEqual(chunks[2]);
				kem.dispose();
			});

			it('SealStream preamble includes KEM ciphertext', () => {
				const kem = mkKem();
				const suite = KyberSuite(kem, inner);
				const { encapsulationKey: ek } = suite.keygen();
				const sealer = new SealStream(suite, ek);
				sealer.finalize(new Uint8Array(0));
				expect(sealer.preamble.length).toBe(HEADER_SIZE + params.ctBytes);
				kem.dispose();
			});
		});
	}
}

// ── Wrong key (dk vs ek swapped) ────────────────────────────────────────────

describe('KyberSuite error cases', () => {
	it('OpenStream with ek instead of dk throws', () => {
		const kem = new MlKem512();
		const suite = KyberSuite(kem, XChaCha20Cipher);
		const { encapsulationKey: ek } = suite.keygen();
		const blob = Seal.encrypt(suite, ek, randomBytes(64));
		// Try to decrypt with ek (wrong — should use dk)
		expect(() => Seal.decrypt(suite, ek, blob)).toThrow(RangeError);
		kem.dispose();
	});

	it('Seal.decrypt with wrong suite throws format mismatch', () => {
		const kem = new MlKem512();
		const suite512x = KyberSuite(kem, XChaCha20Cipher);
		const suite512s = KyberSuite(kem, SerpentCipher);
		const { encapsulationKey: ek, decapsulationKey: dk } = suite512x.keygen();
		const blob = Seal.encrypt(suite512x, ek, randomBytes(64));
		expect(() => Seal.decrypt(suite512s, dk, blob)).toThrow(/expected format/);
		kem.dispose();
	});
});

// ── MlKem keygen key sizes are what params say ──────────────────────────────

describe('KyberSuite param set key sizes', () => {
	it('MlKem512 key sizes', () => {
		const kem = new MlKem512();
		const suite = KyberSuite(kem, XChaCha20Cipher);
		expect(suite.keySize).toBe(MLKEM512.ekBytes);
		expect(suite.decKeySize).toBe(MLKEM512.dkBytes);
		expect(suite.kemCtSize).toBe(MLKEM512.ctBytes);
		kem.dispose();
	});

	it('MlKem768 key sizes', () => {
		const kem = new MlKem768();
		const suite = KyberSuite(kem, XChaCha20Cipher);
		expect(suite.keySize).toBe(MLKEM768.ekBytes);
		expect(suite.decKeySize).toBe(MLKEM768.dkBytes);
		expect(suite.kemCtSize).toBe(MLKEM768.ctBytes);
		kem.dispose();
	});

	it('MlKem1024 key sizes', () => {
		const kem = new MlKem1024();
		const suite = KyberSuite(kem, XChaCha20Cipher);
		expect(suite.keySize).toBe(MLKEM1024.ekBytes);
		expect(suite.decKeySize).toBe(MLKEM1024.dkBytes);
		expect(suite.kemCtSize).toBe(MLKEM1024.ctBytes);
		kem.dispose();
	});
});
