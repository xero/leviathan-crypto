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
// Cartesian-product roundtrip for the MerkleLog + MerkleVerifier
// normie surfaces: two hashers ({sha256, blake3}) by two supported
// suites ({Ed25519Suite, MlDsa44Suite}) by two tree sizes ({small,
// medium}). The supported-suite set is the c2sp.org/tlog-cosignature
// §Format algorithm-byte registry; unregistered suites are covered
// by a separate construction-throw test.
//
// Every case appends leaves, captures the head and inclusion proofs
// for every leaf, captures a consistency proof between two snapshots,
// then verifies through a fresh MerkleVerifier built with the same
// trusted identity. All verification calls must return true. The
// product is small (8 cases total) so spell out the matrix rather
// than collapse via Math.cartesian.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	utf8ToBytes,
	MerkleLog,
	MerkleVerifier,
	Ed25519Suite,
	MlDsa44Suite,
} from '../../../src/ts/index.js';
import type { SignatureSuite } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const ORIGIN = 'leviathan.example/v1/log/roundtrip';
const SMALL_LEAVES = ['alpha', 'bravo', 'charlie'];
const MEDIUM_LEAVES = [
	'a', 'b', 'c', 'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k', 'l', 'm',
];

beforeAll(async () => {
	_resetForTesting();
	const sha2    = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	const sha3    = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
	const blake3  = readFileSync(join(__dirname, '../../../build/blake3.wasm'));
	const ed25519 = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	const mldsa   = readFileSync(join(__dirname, '../../../build/mldsa.wasm'));
	await init({ sha2, sha3, blake3, ed25519, mldsa });
});

type Hashing = 'sha256' | 'blake3';

async function runRoundtrip(opts: {
	hashing: Hashing;
	suite: SignatureSuite;
	leaves: string[];
}): Promise<void> {
	const { hashing, suite, leaves } = opts;
	const { log, signingKey, pubkey } = await MerkleLog.generate({
		origin: ORIGIN,
		hashing,
		suite,
	});
	// signingKey is returned for the persistence path. We don't
	// persist here; just hold a reference so the variable is used and
	// the wipe-on-dispose contract is exercised.
	expect(signingKey.length).toBe(suite.skSize);

	let envelopeAtSmall: Uint8Array;
	let envelopeFull: Uint8Array;
	let consistencyProof: Uint8Array[];
	const inclusionProofs: Uint8Array[][] = [];
	try {
		// Append small slice first so a consistency proof is meaningful.
		const halfPoint = Math.max(1, Math.floor(leaves.length / 3));
		for (let i = 0; i < halfPoint; i++) log.append(utf8ToBytes(leaves[i]));
		envelopeAtSmall = log.head({ timestamp: 1740000000 });
		const sizeAtSmall = log.size();

		// Append the rest.
		for (let i = halfPoint; i < leaves.length; i++) log.append(utf8ToBytes(leaves[i]));
		envelopeFull = log.head({ timestamp: 1740000001 });

		// One inclusion proof per leaf.
		for (let i = 0; i < leaves.length; i++)
			inclusionProofs.push(log.inclusionProof(i, log.size()));

		consistencyProof = log.consistencyProof(sizeAtSmall, log.size());
	} finally {
		log.dispose();
	}

	const verifier = new MerkleVerifier({
		origin: ORIGIN,
		pubkey,
		hashing,
		suite,
	});

	expect(verifier.verifyCheckpoint(envelopeAtSmall)).toBe(true);
	expect(verifier.verifyCheckpoint(envelopeFull)).toBe(true);

	for (let i = 0; i < leaves.length; i++) {
		const ok = verifier.verifyInclusion({
			envelopeBytes: envelopeFull,
			leafBytes: utf8ToBytes(leaves[i]),
			leafIndex: i,
			proof: inclusionProofs[i],
		});
		expect(ok, `inclusion ${i} of ${leaves.length} under ${hashing}/${suite.formatName}`).toBe(true);
	}

	expect(verifier.verifyConsistency({
		oldEnvelopeBytes: envelopeAtSmall,
		newEnvelopeBytes: envelopeFull,
		proof: consistencyProof,
	})).toBe(true);
}

describe('MerkleLog + MerkleVerifier roundtrip across hashings and suites', () => {
	for (const hashing of ['sha256', 'blake3'] as const) {
		for (const suite of [Ed25519Suite, MlDsa44Suite]) {
			for (const size of ['small', 'medium'] as const) {
				const leaves = size === 'small' ? SMALL_LEAVES : MEDIUM_LEAVES;
				it(`${hashing} x ${suite.formatName} x ${size} (${leaves.length} leaves)`, async () => {
					await runRoundtrip({ hashing, suite, leaves });
				});
			}
		}
	}
});
