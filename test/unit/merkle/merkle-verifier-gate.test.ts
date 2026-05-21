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
// GATE: end-to-end MerkleLog + MerkleVerifier handshake. Builds a
// fresh MerkleLog under a fixed Ed25519 keypair, appends three
// deterministic leaves, captures the head envelope and an inclusion
// proof for the middle leaf, then verifies through a freshly
// constructed MerkleVerifier with the same identity. All three
// verify methods must return true. Any byte drift in checkpoint
// serialization, cosignature signed-message construction, signed-note
// emit, key-ID derivation, or RFC 9162 §2.1.3 inclusion-proof
// verification breaks this gate.

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
} from '../../../src/ts/index.js';
import { Ed25519 } from '../../../src/ts/ed25519/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const ORIGIN = 'leviathan.example/v1/log/test';
const LEAVES = ['alpha', 'bravo', 'charlie'];
// Fixed 32-byte seed; deriving the Ed25519 keypair locally via
// keygenDerand keeps the gate self-contained: the keypair is recorded
// here in the test file, no external vector needed.
const SEED = new Uint8Array([
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
]);
const TIMESTAMP = 1740000000;

beforeAll(async () => {
	_resetForTesting();
	const sha2    = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	const ed25519 = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	await init({ sha2, ed25519 });
});

function deriveEd25519(): { sk: Uint8Array; pk: Uint8Array } {
	const ed = new Ed25519();
	try {
		const kp = ed.keygenDerand(SEED);
		return { sk: kp.secretKey, pk: kp.publicKey };
	} finally {
		ed.dispose();
	}
}

describe('MerkleVerifier gate, end-to-end with MerkleLog<Ed25519Suite>', () => {
	it('GATE: verifyCheckpoint and verifyInclusion both accept a fresh log envelope', async () => {
		const { sk, pk } = deriveEd25519();
		const log = await MerkleLog.create({
			origin: ORIGIN,
			signingKey: sk,
			pubkey: pk,
			hashing: 'sha256',
			suite: Ed25519Suite,
		});
		let head: Uint8Array;
		let middleProof: Uint8Array[];
		try {
			for (const leaf of LEAVES) log.append(utf8ToBytes(leaf));
			expect(log.size()).toBe(LEAVES.length);
			head = log.head({ timestamp: TIMESTAMP });
			// Inclusion proof for the middle leaf (index 1) in a tree
			// of size 3. RFC 9162 §2.1.3.
			middleProof = log.inclusionProof(1, log.size());
		} finally {
			log.dispose();
		}

		const verifier = new MerkleVerifier({
			origin: ORIGIN,
			pubkey: pk,
			hashing: 'sha256',
			suite: Ed25519Suite,
		});
		// Property 1: the envelope verifies under the trusted identity.
		expect(verifier.verifyCheckpoint(head)).toBe(true);
		// Property 2: the inclusion proof verifies after the checkpoint
		// verifies. verifyInclusion runs verifyCheckpoint first, then
		// re-derives the leaf hash from the raw leaf bytes via the
		// configured Hasher.
		expect(verifier.verifyInclusion({
			envelopeBytes: head,
			leafBytes: utf8ToBytes(LEAVES[1]),
			leafIndex: 1,
			proof: middleProof,
		})).toBe(true);
	});

	it('GATE: verifyConsistency accepts a proof between two checkpoints from the same log', async () => {
		const { sk, pk } = deriveEd25519();
		const log = await MerkleLog.create({
			origin: ORIGIN,
			signingKey: sk,
			pubkey: pk,
			hashing: 'sha256',
			suite: Ed25519Suite,
		});
		let oldHead: Uint8Array;
		let newHead: Uint8Array;
		let proof: Uint8Array[];
		try {
			log.append(utf8ToBytes(LEAVES[0]));
			oldHead = log.head({ timestamp: TIMESTAMP });
			const oldSize = log.size();
			log.append(utf8ToBytes(LEAVES[1]));
			log.append(utf8ToBytes(LEAVES[2]));
			newHead = log.head({ timestamp: TIMESTAMP + 1 });
			proof = log.consistencyProof(oldSize, log.size());
		} finally {
			log.dispose();
		}

		const verifier = new MerkleVerifier({
			origin: ORIGIN,
			pubkey: pk,
			hashing: 'sha256',
			suite: Ed25519Suite,
		});
		expect(verifier.verifyConsistency({
			oldEnvelopeBytes: oldHead,
			newEnvelopeBytes: newHead,
			proof,
		})).toBe(true);
	});
});
