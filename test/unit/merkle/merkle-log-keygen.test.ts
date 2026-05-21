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
// `MerkleLog.generate` keygen contract: the returned signing key
// matches `suite.skSize`, the returned pubkey matches `suite.pkSize`,
// and the log is usable end-to-end with the returned identity. Also
// covers the unsupported-suite construction throw path for both
// `create` and `generate`, which is the documented failure mode for
// suites outside the c2sp.org/tlog-cosignature §Format algorithm-byte
// registry.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	utf8ToBytes,
	MerkleLog,
	MerkleVerifier,
	MerkleLogError,
	Ed25519Suite,
	MlDsa44Suite,
	MlDsa65Suite,
	EcdsaP256Suite,
	SlhDsa128fSuite,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const ORIGIN = 'leviathan.example/v1/log/keygen';

beforeAll(async () => {
	_resetForTesting();
	const sha2    = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	const sha3    = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
	const ed25519 = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	const mldsa   = readFileSync(join(__dirname, '../../../build/mldsa.wasm'));
	await init({ sha2, sha3, ed25519, mldsa });
});

describe('MerkleLog.generate keypair shape', () => {
	it('returns Ed25519 keys with the catalog-locked sizes', async () => {
		const { log, signingKey, pubkey } = await MerkleLog.generate({
			origin: ORIGIN, suite: Ed25519Suite,
		});
		try {
			expect(signingKey.length).toBe(Ed25519Suite.skSize);
			expect(pubkey.length).toBe(Ed25519Suite.pkSize);
			// Smoke-check that the returned keys actually drive the log:
			// append one leaf and verify the head envelope.
			log.append(utf8ToBytes('first-leaf'));
			const env = log.head({ timestamp: 1740000000 });
			const verifier = new MerkleVerifier({
				origin: ORIGIN, pubkey, hashing: 'sha256', suite: Ed25519Suite,
			});
			expect(verifier.verifyCheckpoint(env)).toBe(true);
		} finally {
			log.dispose();
		}
	});

	it('returns MlDsa44 keys with the catalog-locked sizes', async () => {
		const { log, signingKey, pubkey } = await MerkleLog.generate({
			origin: ORIGIN, suite: MlDsa44Suite,
		});
		try {
			expect(signingKey.length).toBe(MlDsa44Suite.skSize);
			expect(pubkey.length).toBe(MlDsa44Suite.pkSize);
			log.append(utf8ToBytes('first-leaf'));
			const env = log.head({ timestamp: 1740000000 });
			const verifier = new MerkleVerifier({
				origin: ORIGIN, pubkey, hashing: 'sha256', suite: MlDsa44Suite,
			});
			expect(verifier.verifyCheckpoint(env)).toBe(true);
		} finally {
			log.dispose();
		}
	});

	it('default suite is MlDsa44Suite (C2SP-recommended PQ default)', async () => {
		// Property: `generate` with no `suite` resolves to MlDsa44Suite.
		// We do not export a default-suite constant; the user pins by
		// passing the explicit value. The default is observable through
		// the returned pubkey size (1312 bytes for MlDsa44 vs 32 for
		// Ed25519).
		const { log, pubkey } = await MerkleLog.generate({ origin: ORIGIN });
		try {
			expect(pubkey.length).toBe(MlDsa44Suite.pkSize);
		} finally {
			log.dispose();
		}
	});

	it('default hashing is sha256 (C2SP-interop default)', async () => {
		const { log } = await MerkleLog.generate({
			origin: ORIGIN, suite: Ed25519Suite,
		});
		try {
			expect(log.hasher.name).toBe('sha256');
		} finally {
			log.dispose();
		}
	});
});

describe('MerkleLog.create + MerkleLog.generate: unsupported-suite throws', () => {
	const fakeSk = new Uint8Array(64);
	const fakePk = new Uint8Array(32);

	it('create() with EcdsaP256Suite throws MerkleLogError', async () => {
		await expect(MerkleLog.create({
			origin: ORIGIN,
			signingKey: new Uint8Array(EcdsaP256Suite.skSize),
			pubkey: new Uint8Array(EcdsaP256Suite.pkSize),
			suite: EcdsaP256Suite,
		})).rejects.toBeInstanceOf(MerkleLogError);
	});

	it('create() with MlDsa65Suite throws MerkleLogError (not currently registered)', async () => {
		await expect(MerkleLog.create({
			origin: ORIGIN,
			signingKey: new Uint8Array(MlDsa65Suite.skSize),
			pubkey: new Uint8Array(MlDsa65Suite.pkSize),
			suite: MlDsa65Suite,
		})).rejects.toBeInstanceOf(MerkleLogError);
	});

	it('generate() with EcdsaP256Suite throws MerkleLogError', async () => {
		await expect(MerkleLog.generate({
			origin: ORIGIN, suite: EcdsaP256Suite,
		})).rejects.toBeInstanceOf(MerkleLogError);
	});

	it('create() with an SLH-DSA suite throws MerkleLogError (hybrids and SLH-DSA out of registry)', async () => {
		await expect(MerkleLog.create({
			origin: ORIGIN,
			signingKey: new Uint8Array(SlhDsa128fSuite.skSize),
			pubkey: new Uint8Array(SlhDsa128fSuite.pkSize),
			suite: SlhDsa128fSuite,
		})).rejects.toBeInstanceOf(MerkleLogError);
	});

	it('create() with an unsupported hashing value throws MerkleLogError', async () => {
		await expect(MerkleLog.create({
			origin: ORIGIN,
			signingKey: fakeSk,
			pubkey: fakePk,
			suite: Ed25519Suite,
			// @ts-expect-error: not a valid Hashing literal
			hashing: 'md5',
		})).rejects.toBeInstanceOf(MerkleLogError);
	});
});
