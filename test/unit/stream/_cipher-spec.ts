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
// test/unit/stream/_cipher-spec.ts
//
// Per-cipher spec table for stream-layer contract tests. The leading
// underscore signals to vitest that this is a helper, not a test file
// (same convention as _test-ciphers.ts).
//
// Adding a new symmetric cipher to the library:
//   1. Append a row to CIPHER_SPECS below.
//   2. Create test/unit/stream/<cipher>-cipher-suite.test.ts with the
//      per-cipher describe blocks listed in each existing per-cipher
//      file's header comment.
//   3. The parameterized generic tests in seal.test.ts pick up the new
//      row automatically.
//
// Spec values follow the cipher-suite source. If a cipher's contract
// changes (e.g. a different formatEnum or hkdfInfo), update the row;
// the contract-pinning tests in seal.test.ts will fail until you do.

import type { CipherSuite } from '../../../src/ts/stream/types.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { SerpentCipher } from '../../../src/ts/serpent/cipher-suite.js';
import { AESGCMSIVCipher } from '../../../src/ts/aes/cipher-suite.js';

export interface CipherSpec {
	/** Display name used in describe blocks. */
	name: string;
	/** The CipherSuite under test. */
	suite: CipherSuite & { keygen(): Uint8Array };
	/** Pinned formatEnum byte. */
	formatEnum: number;
	/** Pinned formatName string. */
	formatName: string;
	/** Pinned hkdfInfo string. */
	hkdfInfo: string;
	/** Pinned wasmModules array — the EXACT runtime module set the cipher needs.
	 *  Note: sha2 is a stream-layer dependency (HKDF), not declared per-cipher;
	 *  Serpent is the exception because HMAC-SHA-256 is also a per-chunk dep. */
	wasmModules: readonly string[];
	/** Pinned commitmentSize. 32 for v3 ciphers (XChaCha20, AES-GCM-SIV);
	 *  0 for Serpent (natively key-committing via HMAC-SHA-256). */
	commitmentSize: number;
	/** Pinned tagSize. */
	tagSize: number;
	/** Pinned wasmChunkSize. */
	wasmChunkSize: number;
	/** Pinned padded flag. */
	padded: boolean;
	/** Pinned keySize. */
	keySize: number;
	/** Pinned kemCtSize (always 0 for symmetric ciphers). */
	kemCtSize: number;
	/** True iff the cipher header-binds (deriveKeys info includes the header).
	 *  False for Serpent; true for XChaCha20 v3 + AES-GCM-SIV v3. */
	headerBinds: boolean;
	/** Discriminator embedded in AuthenticationError messages on commitment
	 *  mismatch. Null if the cipher has no commitment field (Serpent). */
	commitDiscriminator: string | null;
	/** Discriminator embedded in AuthenticationError messages on tag mismatch
	 *  (the AEAD- or HMAC-level auth fail, not commitment). */
	tagDiscriminator: string;
}

export const CIPHER_SPECS: readonly CipherSpec[] = [
	{
		name: 'XChaCha20',
		suite: XChaCha20Cipher,
		formatEnum: 0x03,
		formatName: 'xchacha20',
		hkdfInfo: 'xchacha20-sealstream-v3',
		wasmModules: ['chacha20'],
		commitmentSize: 32,
		tagSize: 16,
		wasmChunkSize: 65536,
		padded: false,
		keySize: 32,
		kemCtSize: 0,
		headerBinds: true,
		commitDiscriminator: 'commitment-xchacha20',
		tagDiscriminator: 'xchacha20-poly1305',
	},
	{
		name: 'Serpent',
		suite: SerpentCipher,
		formatEnum: 0x02,
		formatName: 'serpent',
		hkdfInfo: 'serpent-sealstream-v3',
		wasmModules: ['serpent', 'sha2'],
		commitmentSize: 0,
		tagSize: 32,                      // HMAC-SHA-256 tag
		wasmChunkSize: 65552,             // CHUNK_SIZE (65536 + 16 PKCS7 max overhead)
		padded: true,                     // Serpent CBC + PKCS7
		keySize: 32,
		kemCtSize: 0,
		headerBinds: false,               // Serpent does NOT header-bind
		commitDiscriminator: null,        // no commitment field
		tagDiscriminator: 'serpent',
	},
	{
		name: 'AES-GCM-SIV',
		suite: AESGCMSIVCipher,
		formatEnum: 0x04,
		formatName: 'aes-gcm-siv',
		hkdfInfo: 'aes-gcm-siv-sealstream-v3',
		wasmModules: ['aes'],             // sha2 is HKDF, not per-cipher
		commitmentSize: 32,
		tagSize: 16,
		wasmChunkSize: 65536,
		padded: false,
		keySize: 32,
		kemCtSize: 0,
		headerBinds: true,
		commitDiscriminator: 'commitment-aes-gcm-siv',
		tagDiscriminator: 'aes-gcm-siv',
	},
] as const;
