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
// `SignedLog` constructor rejects every leviathan SignatureSuite
// whose `formatEnum` lacks an entry in the C2SP cosignature
// algorithm-byte registry (c2sp.org/tlog-cosignature §Format). The
// currently-registered suites are `Ed25519Suite` (0x01 → 0x04) and
// `MlDsa44Suite` (0x03 → 0x06). Everything else throws
// `SigningError('sig-unsupported-suite')` at construction; the
// generic `<S extends SignatureSuite>` parameter stays open so the
// runtime check is the gate.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	SignedLog,
	Sha256Tree,
	MemoryStorage,
	SigningError,
	EcdsaP256Suite,
	Ed25519PreHashSuite,
	MlDsa44PreHashSuite,
	MlDsa65Suite,
	MlDsa87Suite,
	SlhDsa128fSuite,
	MlDsa44SlhDsa128fSuite,
	MlDsa44Ed25519Suite,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import type { SignatureSuite } from '../../../src/ts/sign/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	// SignedLog construction validates module init for the suite's
	// wasmModules; load all of them so the only reason a construction
	// throws is the registry check, not a missing module.
	const sha2 = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	const sha3 = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
	const ed25519 = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	const p256 = readFileSync(join(__dirname, '../../../build/p256.wasm'));
	const mldsa = readFileSync(join(__dirname, '../../../build/mldsa.wasm'));
	const slhdsa = readFileSync(join(__dirname, '../../../build/slhdsa.wasm'));
	await init({ sha2, sha3, ed25519, p256, mldsa, slhdsa });
});

function expectUnsupported(suite: SignatureSuite): void {
	const tree = new Sha256Tree(new MemoryStorage());
	const signingKey = new Uint8Array(suite.skSize);
	const pubkey = new Uint8Array(suite.pkSize);
	try {
		new SignedLog({
			tree,
			suite,
			origin: 'leviathan.test/log',
			signingKey,
			pubkey,
		});
		throw new Error(`expected SigningError('sig-unsupported-suite') for ${suite.formatName}, no throw`);
	} catch (err) {
		expect(err).toBeInstanceOf(SigningError);
		expect((err as SigningError).discriminator).toBe('sig-unsupported-suite');
		// Surface text mentions the suite by name + format byte.
		const msg = (err as SigningError).message;
		expect(msg).toContain(suite.formatName);
		expect(msg).toContain('c2sp.org/tlog-cosignature');
	}
}

describe('SignedLog construction rejects suites without a C2SP cosignature byte', () => {
	it('rejects EcdsaP256Suite (catalog 0x02; C2SP 0x02 is ECDSA-witness with DER encoding, not P1363 r||s)', () => {
		expectUnsupported(EcdsaP256Suite);
	});

	it('rejects Ed25519PreHashSuite (catalog 0x11; no C2SP cosig byte for Ed25519ph)', () => {
		expectUnsupported(Ed25519PreHashSuite);
	});

	it('rejects MlDsa44PreHashSuite (catalog 0x13; no C2SP cosig byte for HashML-DSA)', () => {
		expectUnsupported(MlDsa44PreHashSuite);
	});

	it('rejects MlDsa65Suite (catalog 0x04; no C2SP cosig byte for ML-DSA-65)', () => {
		expectUnsupported(MlDsa65Suite);
	});

	it('rejects MlDsa87Suite (catalog 0x05; no C2SP cosig byte for ML-DSA-87)', () => {
		expectUnsupported(MlDsa87Suite);
	});

	it('rejects SlhDsa128fSuite (catalog 0x06; no C2SP cosig byte for any SLH-DSA variant)', () => {
		expectUnsupported(SlhDsa128fSuite);
	});

	it('rejects PQ-only hybrid MlDsa44SlhDsa128fSuite (catalog 0x30; hybrids unregistered)', () => {
		expectUnsupported(MlDsa44SlhDsa128fSuite);
	});

	it('rejects classical+PQ hybrid MlDsa44Ed25519Suite (catalog 0x20; hybrids unregistered)', () => {
		expectUnsupported(MlDsa44Ed25519Suite);
	});
});
