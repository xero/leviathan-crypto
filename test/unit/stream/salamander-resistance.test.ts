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
 * Invisible Salamanders mitigation — attack-shape regression test.
 *
 * Background: ChaCha20-Poly1305 and AES-256-GCM-SIV are not key-committing
 * on their own; an adversary with control over two master keys can craft
 * a single ciphertext + tag that decrypts validly under both. The classic
 * exploitation is multi-recipient envelope encryption or sender-keys
 * group messaging.
 *
 * Mitigation in this library: each XChaCha20 v3 and AES-GCM-SIV v3
 * preamble carries a 32-byte key commitment (HKDF bytes 32..64), which
 * OpenStream verifies before any chunk is processed. Wrong key fails
 * fast with AuthenticationError, before the AEAD is consulted.
 *
 * The full attack would require a synthesized Poly1305/POLYVAL
 * collision, which is out of scope for unit tests. The properties tested
 * here are the essential preconditions for the mitigation to work:
 * distinct master keys produce distinct commitments under the same
 * nonce + INFO + header, and tampered headers produce different
 * commitments. The construction-time fail-fast property is also pinned
 * — wrong key throws at OpenStream construction, not at the first
 * chunk.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes, HKDF_SHA256, bytesToHex, utf8ToBytes, concat, AuthenticationError } from '../../../src/ts/index.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { AESGCMSIVCipher } from '../../../src/ts/aes/cipher-suite.js';
import { Seal, SealStream, OpenStream, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { writeHeader } from '../../../src/ts/stream/header.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, aes: aesWasm, sha2: sha2Wasm });
});

interface SuiteEntry {
	name: string;
	cipher: typeof XChaCha20Cipher;
	infoLabel: string;
	commitDiscriminator: string;
}

const suites: SuiteEntry[] = [
	{ name: 'XChaCha20',   cipher: XChaCha20Cipher, infoLabel: 'xchacha20-sealstream-v3',   commitDiscriminator: 'commitment-xchacha20' },
	{ name: 'AES-GCM-SIV', cipher: AESGCMSIVCipher, infoLabel: 'aes-gcm-siv-sealstream-v3', commitDiscriminator: 'commitment-aes-gcm-siv' },
];

for (const { name, cipher, infoLabel, commitDiscriminator } of suites) {
	describe(`Invisible Salamanders mitigation — commitment divergence (${name})`, () => {
		it('two distinct master keys produce distinct 32-byte commitments under identical nonce + header', () => {
			const m1 = new Uint8Array(32); m1.fill(0xa1);
			const m2 = new Uint8Array(32); m2.fill(0xb2);
			const nonce = new Uint8Array(16); nonce.fill(0xcd);
			const header = writeHeader(cipher.formatEnum, false, nonce, 1024);
			const INFO = utf8ToBytes(infoLabel);

			const hkdf = new HKDF_SHA256();
			try {
				const info = concat(INFO, header);
				const okm1 = hkdf.derive(m1, nonce, info, 64);
				const okm2 = hkdf.derive(m2, nonce, info, 64);

				const commit1 = okm1.subarray(32, 64);
				const commit2 = okm2.subarray(32, 64);

				expect(bytesToHex(commit1)).not.toBe(bytesToHex(commit2));
			} finally {
				hkdf.dispose();
			}
		});

		it('identical key, identical nonce, but different headers produce different commitments', () => {
			// Header binding: tampering with the framed flag, chunkSize, or even
			// formatEnum produces a different commitment, so OpenStream rejects.
			const key   = randomBytes(32);
			const nonce = randomBytes(16);
			const headerA = writeHeader(cipher.formatEnum, false, nonce, 1024);
			const headerB = writeHeader(cipher.formatEnum, true,  nonce, 1024); // framed flipped

			const dkA = cipher.deriveKeys(key, nonce, undefined, headerA);
			const dkB = cipher.deriveKeys(key, nonce, undefined, headerB);
			try {
				expect(bytesToHex(dkA.commitment!)).not.toBe(bytesToHex(dkB.commitment!));
			} finally {
				cipher.wipeKeys(dkA);
				cipher.wipeKeys(dkB);
			}
		});

		it('OpenStream construction with the wrong master key throws AuthenticationError before any chunk is processed', () => {
			const right = cipher.keygen();
			const wrong = cipher.keygen();
			const sealer = new SealStream(cipher, right, { chunkSize: 1024 });
			const preamble = sealer.preamble;
			// Construct an OpenStream with a key that does not match the commitment.
			let caught: Error | null = null;
			try {
				new OpenStream(cipher, wrong, preamble);
			} catch (e) {
				caught = e as Error;
			}
			expect(caught).toBeInstanceOf(AuthenticationError);
			expect(caught!.message).toContain(commitDiscriminator);
			// finalize the sealer to clean up keys.
			sealer.finalize(new Uint8Array(0));
		});

		it('Seal.decrypt with the wrong master key throws AuthenticationError carrying the commitment discriminator', () => {
			const right = cipher.keygen();
			const wrong = cipher.keygen();
			const blob  = Seal.encrypt(cipher, right, randomBytes(64));
			let caught: Error | null = null;
			try {
				Seal.decrypt(cipher, wrong, blob);
			} catch (e) {
				caught = e as Error;
			}
			expect(caught).toBeInstanceOf(AuthenticationError);
			expect(caught!.message).toContain(commitDiscriminator);
		});

		it('OpenStream commitment fail-fast precedes the first chunk decode (timing-anchor regression)', () => {
			// If the commitment check were ever delayed to the first chunk, an
			// attacker could probe AEAD state per chunk. The construction-time
			// throw is the contractual fail-fast guarantee. We verify by
			// constructing an OpenStream with a tampered commitment (a single
			// flipped bit) and asserting the throw fires at construction time
			// — the OpenStream variable never binds.
			const key  = cipher.keygen();
			const sealer = new SealStream(cipher, key, { chunkSize: 1024 });
			const preamble = sealer.preamble.slice();
			const commitOff = HEADER_SIZE + cipher.kemCtSize + 5;
			preamble[commitOff] ^= 0x01;
			expect(() => new OpenStream(cipher, key, preamble))
				.toThrow(new RegExp(commitDiscriminator));
			sealer.finalize(new Uint8Array(0));
		});
	});
}
