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
// SignedLog<Ed25519Suite> sign + verify roundtrip across every record
// in sign_sth_ed25519.ts. For each record: rebuild the Sha256Tree
// from the recorded leaves, derive (sk, pk) from the recorded seed,
// run signCheckpoint with the recorded timestamp, byte-compare the
// envelope, then verifyCheckpoint to confirm the recorded envelope
// validates. Byte equality is meaningful for Ed25519 because RFC
// 8032 §5.1.6 sign is deterministic.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	hexToBytes,
	bytesToHex,
	utf8ToBytes,
	SignedLog,
	Sha256Tree,
	MemoryStorage,
	Ed25519Suite,
	parseSignedNote,
	parseCheckpointBody,
	parseCosigSignaturePayload,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { signSthEd25519Vectors } from '../../vectors/sign_sth_ed25519.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const sha2 = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	const ed25519 = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	await init({ sha2, ed25519 });
});

function buildLog(v: typeof signSthEd25519Vectors[number]): SignedLog<typeof Ed25519Suite> {
	const tree = new Sha256Tree(new MemoryStorage());
	for (const leaf of v.leaves) tree.append(utf8ToBytes(leaf));
	return new SignedLog({
		tree,
		suite: Ed25519Suite,
		origin: v.origin,
		signingKey: hexToBytes(v.skHex),
		pubkey: hexToBytes(v.pkHex),
	});
}

describe('SignedLog<Ed25519Suite> roundtrip, c2sp.org/tlog-cosignature §"Ed25519 signed message"', () => {
	for (const v of signSthEd25519Vectors) {
		it(`sign reproduces recorded envelope bytes: ${v.id}`, () => {
			const log = buildLog(v);
			try {
				const envelope = log.signCheckpoint({ timestamp: v.timestamp });
				expect(bytesToHex(envelope)).toBe(v.envelopeHex);
			} finally {
				log.dispose();
			}
		});

		it(`verify accepts recorded envelope: ${v.id}`, () => {
			const log = buildLog(v);
			try {
				expect(log.verifyCheckpoint(hexToBytes(v.envelopeHex))).toBe(true);
			} finally {
				log.dispose();
			}
		});

		it(`parseCheckpoint surfaces the recorded timestamp: ${v.id}`, () => {
			const log = buildLog(v);
			try {
				const sth = log.parseCheckpoint(hexToBytes(v.envelopeHex));
				expect(sth.checkpoint.origin).toBe(v.origin);
				expect(sth.checkpoint.treeSize).toBe(v.treeSize);
				expect(bytesToHex(sth.checkpoint.rootHash)).toBe(v.rootHashHex);
				expect(sth.timestamp).toBe(v.timestamp);
				expect(sth.signatures.length).toBe(1);
			} finally {
				log.dispose();
			}
		});

		it(`envelope decomposes into recorded body + cosigPayload: ${v.id}`, () => {
			// Independent reading of the envelope at the signed-note
			// + cosig-payload layer; confirms the recorded intermediate
			// values are wire-consistent with the envelope.
			const env = parseSignedNote(hexToBytes(v.envelopeHex));
			expect(bytesToHex(env.body)).toBe(v.bodyHex);
			expect(env.signatures.length).toBe(1);
			const sig = env.signatures[0];
			expect(bytesToHex(sig.keyId)).toBe(v.keyIdHex);
			const payloadBytes = new Uint8Array(sig.keyId.length + sig.signature.length);
			payloadBytes.set(sig.keyId, 0);
			payloadBytes.set(sig.signature, sig.keyId.length);
			// `sig.signature` from parseSignedNote already strips the
			// 4-byte keyId, so it is the timestamped_signature payload.
			expect(bytesToHex(sig.signature)).toBe(v.cosigPayloadHex);
			const parsed = parseCosigSignaturePayload(sig.signature, 64);
			expect(parsed.timestamp).toBe(v.timestamp);
			expect(bytesToHex(parsed.signature)).toBe(v.sigHex);
			const cp = parseCheckpointBody(env.body);
			expect(cp.origin).toBe(v.origin);
			expect(cp.treeSize).toBe(v.treeSize);
		});
	}
});
