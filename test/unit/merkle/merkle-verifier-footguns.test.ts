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
// Footgun coverage for `MerkleVerifier`. Every documented failure
// mode returns `false`, never throws. The class returns boolean to
// match `SignatureSuite.verify`; the only path that throws is the
// construction-time contract violation (invalid origin, wrong pubkey
// size, unsupported suite, uninitialised module), and those are
// covered in a separate construction-error test surface.

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
	EcdsaP256Suite,
} from '../../../src/ts/index.js';
import { Ed25519 } from '../../../src/ts/ed25519/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const ORIGIN = 'leviathan.example/v1/log/footgun';
const LEAVES = ['alpha', 'bravo', 'charlie'];
const SEED_A = new Uint8Array(32).fill(0xa1);
const SEED_B = new Uint8Array(32).fill(0xb2);

beforeAll(async () => {
	_resetForTesting();
	const sha2    = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	const ed25519 = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	const p256    = readFileSync(join(__dirname, '../../../build/p256.wasm'));
	await init({ sha2, ed25519, p256 });
});

function deriveEd25519(seed: Uint8Array): { sk: Uint8Array; pk: Uint8Array } {
	const ed = new Ed25519();
	try {
		const kp = ed.keygenDerand(seed);
		return { sk: kp.secretKey, pk: kp.publicKey };
	} finally {
		ed.dispose();
	}
}

async function buildLog(): Promise<{
	envelope: Uint8Array;
	inclusionProof: Uint8Array[];
	pk: Uint8Array;
}> {
	const { sk, pk } = deriveEd25519(SEED_A);
	const log = await MerkleLog.create({
		origin: ORIGIN,
		signingKey: sk,
		pubkey: pk,
		hashing: 'sha256',
		suite: Ed25519Suite,
	});
	try {
		for (const leaf of LEAVES) log.append(utf8ToBytes(leaf));
		const envelope = log.head({ timestamp: 1740000000 });
		const inclusionProof = log.inclusionProof(1, log.size());
		return { envelope, inclusionProof, pk };
	} finally {
		log.dispose();
	}
}

describe('MerkleVerifier footguns return false (never throw on verify content)', () => {
	it('verifyCheckpoint returns false on wrong pubkey (keyId mismatch suppresses the line)', async () => {
		// Security property: keyId binds (origin, algoByte, pubkey).
		// A verifier built with a different pubkey derives a different
		// keyId, so no signature line in the envelope matches and the
		// verifier never reaches suite.verify.
		const { envelope } = await buildLog();
		const { pk: wrongPk } = deriveEd25519(SEED_B);
		const verifier = new MerkleVerifier({
			origin: ORIGIN, pubkey: wrongPk, hashing: 'sha256', suite: Ed25519Suite,
		});
		expect(verifier.verifyCheckpoint(envelope)).toBe(false);
	});

	it('verifyCheckpoint returns false on wrong origin (body origin line mismatch)', async () => {
		// Security property: origin is the first line of the signed
		// body. A verifier expecting a different origin refuses the
		// envelope before signature check.
		const { envelope, pk } = await buildLog();
		const verifier = new MerkleVerifier({
			origin: 'leviathan.example/v1/log/other',
			pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		});
		expect(verifier.verifyCheckpoint(envelope)).toBe(false);
	});

	it('verifyCheckpoint returns false on a tampered envelope byte', async () => {
		// Security property: every byte of the signed body is covered
		// by the cosignature signed message. Flipping any body byte
		// breaks signature verification.
		const { envelope, pk } = await buildLog();
		const tampered = envelope.slice();
		tampered[0] ^= 0x01; // flip a bit inside the origin line
		const verifier = new MerkleVerifier({
			origin: ORIGIN, pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		});
		expect(verifier.verifyCheckpoint(tampered)).toBe(false);
	});

	it('verifyInclusion returns false on a tampered proof byte', async () => {
		// Security property: the proof is bound to the root hash inside
		// the signed body. Mutating a proof element produces a
		// reconstructed root that no longer matches.
		const { envelope, inclusionProof, pk } = await buildLog();
		const tamperedProof = inclusionProof.map(h => h.slice());
		tamperedProof[0][0] ^= 0x01;
		const verifier = new MerkleVerifier({
			origin: ORIGIN, pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		});
		expect(verifier.verifyInclusion({
			envelopeBytes: envelope,
			leafBytes: utf8ToBytes(LEAVES[1]),
			leafIndex: 1,
			proof: tamperedProof,
		})).toBe(false);
	});

	it('verifyInclusion returns false on an off-by-one leafIndex (chain bits dispatch wrong sibling order)', async () => {
		// Security property: the proof verifier RFC 9162 §2.1.3 chains
		// inner siblings on the (index >> i) & 1 bit. A different
		// leafIndex flips the chain bits and reconstructs a different
		// root.
		const { envelope, inclusionProof, pk } = await buildLog();
		const verifier = new MerkleVerifier({
			origin: ORIGIN, pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		});
		expect(verifier.verifyInclusion({
			envelopeBytes: envelope,
			leafBytes: utf8ToBytes(LEAVES[1]),
			leafIndex: 0, // claim it's the first leaf, but the proof was for index 1
			proof: inclusionProof,
		})).toBe(false);
	});

	it('verifyInclusion returns false on wrong leaf bytes (re-hashed leaf does not match position)', async () => {
		// Security property: the verifier hashes leaf bytes itself with
		// the configured Hasher (`leafHash = hasher.hashLeaf(leafBytes)`)
		// before feeding the inclusion-proof verifier. Caller-supplied
		// leaf bytes that differ from what was appended produce a
		// different leaf hash, which the proof's inner chain cannot
		// reconstruct back to the signed root.
		const { envelope, inclusionProof, pk } = await buildLog();
		const verifier = new MerkleVerifier({
			origin: ORIGIN, pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		});
		expect(verifier.verifyInclusion({
			envelopeBytes: envelope,
			leafBytes: utf8ToBytes('not the original bravo'),
			leafIndex: 1,
			proof: inclusionProof,
		})).toBe(false);
	});

	it('verifyInclusion returns false when the underlying envelope itself fails verification', async () => {
		// Security property: verifyInclusion runs verifyCheckpoint
		// first. If the checkpoint is rejected the proof is never
		// examined, even if the proof would otherwise compute back to
		// some root.
		const { envelope, inclusionProof, pk } = await buildLog();
		const tampered = envelope.slice();
		tampered[0] ^= 0x01;
		const verifier = new MerkleVerifier({
			origin: ORIGIN, pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		});
		expect(verifier.verifyInclusion({
			envelopeBytes: tampered,
			leafBytes: utf8ToBytes(LEAVES[1]),
			leafIndex: 1,
			proof: inclusionProof,
		})).toBe(false);
	});

	it('verifyCheckpoint returns false on wholly malformed input', async () => {
		// Security property: bad bytes are rejected silently, never
		// crash the verifier.
		const { pk } = await buildLog();
		const verifier = new MerkleVerifier({
			origin: ORIGIN, pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		});
		expect(verifier.verifyCheckpoint(new Uint8Array(0))).toBe(false);
		expect(verifier.verifyCheckpoint(new Uint8Array([0x00, 0x01, 0x02]))).toBe(false);
		expect(verifier.verifyCheckpoint(utf8ToBytes('not a signed note\n'))).toBe(false);
	});

	it('constructor throws MerkleLogError on an unregistered suite (EcdsaP256Suite)', () => {
		// Construction-time contract violation. The c2sp.org/tlog-cosignature
		// §Format algo-byte registry currently lists only Ed25519 (0x04)
		// and ML-DSA-44 (0x06); EcdsaP256Suite has no entry and the
		// MerkleVerifier surface refuses to instantiate.
		const fakePk = new Uint8Array(EcdsaP256Suite.pkSize);
		expect(() => new MerkleVerifier({
			origin: ORIGIN, pubkey: fakePk, hashing: 'sha256', suite: EcdsaP256Suite,
		})).toThrow(MerkleLogError);
	});

	it('constructor throws MerkleLogError on a wrong-length pubkey', () => {
		// Construction-time contract violation: a 16-byte buffer cannot
		// be an Ed25519 public key.
		expect(() => new MerkleVerifier({
			origin: ORIGIN, pubkey: new Uint8Array(16), hashing: 'sha256', suite: Ed25519Suite,
		})).toThrow(MerkleLogError);
	});

	it('constructor throws MerkleLogError on origin with whitespace or plus characters', () => {
		// c2sp.org/tlog-checkpoint §Note text MUSTs.
		const { pk } = deriveEd25519(SEED_A);
		expect(() => new MerkleVerifier({
			origin: 'has space', pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		})).toThrow(MerkleLogError);
		expect(() => new MerkleVerifier({
			origin: 'has+plus', pubkey: pk, hashing: 'sha256', suite: Ed25519Suite,
		})).toThrow(MerkleLogError);
	});
});
