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
 * Background: ChaCha20-Poly1305 is not key-committing on its own; an
 * adversary with control over two master keys can craft a single
 * ciphertext + tag that decrypts validly under both. The classic
 * exploitation is multi-recipient envelope encryption or sender-keys
 * group messaging.
 *
 * Mitigation in this library: each XChaCha20 v3 preamble carries a
 * 32-byte key commitment (HKDF bytes 32..64), which OpenStream verifies
 * before any chunk is processed. Wrong key fails fast with
 * AuthenticationError, before Poly1305 is consulted.
 *
 * The full attack would require a synthesized Poly1305 collision, which
 * is out of scope for unit tests. The property tested here is the
 * essential precondition for the mitigation to work: distinct master
 * keys produce distinct commitments under the same nonce + INFO + header.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes, HKDF_SHA256, bytesToHex, utf8ToBytes, concat } from '../../../src/ts/index.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { writeHeader } from '../../../src/ts/stream/header.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
});

describe('Invisible Salamanders mitigation — commitment divergence', () => {
	it('two distinct master keys produce distinct 32-byte commitments under identical nonce + header', () => {
		const m1 = new Uint8Array(32); m1.fill(0xa1);
		const m2 = new Uint8Array(32); m2.fill(0xb2);
		const nonce = new Uint8Array(16); nonce.fill(0xcd);
		const header = writeHeader(XChaCha20Cipher.formatEnum, false, nonce, 1024);
		const INFO = utf8ToBytes('xchacha20-sealstream-v3');

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
		const headerA = writeHeader(XChaCha20Cipher.formatEnum, false, nonce, 1024);
		const headerB = writeHeader(XChaCha20Cipher.formatEnum, true,  nonce, 1024); // framed flipped

		const dkA = XChaCha20Cipher.deriveKeys(key, nonce, undefined, headerA);
		const dkB = XChaCha20Cipher.deriveKeys(key, nonce, undefined, headerB);
		try {
			expect(bytesToHex(dkA.commitment!)).not.toBe(bytesToHex(dkB.commitment!));
		} finally {
			XChaCha20Cipher.wipeKeys(dkA);
			XChaCha20Cipher.wipeKeys(dkB);
		}
	});
});
