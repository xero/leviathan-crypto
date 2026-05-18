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
// SignedLog<MlDsa44Suite> sign + verify roundtrip across every record
// in sign_sth_mldsa44.ts. The recorded envelopes are byte-stable via
// the deterministic primitive path (`MlDsa44.signDeterministic` on
// the cosigned_message struct); the production hedged path through
// `MlDsa44Suite.sign` produces a different (also valid) envelope on
// each call, so the production-path test only verifies (no byte
// equality). Both flows pass through the same
// `c2sp.org/tlog-cosignature §"ML-DSA-44 signed message"` wire
// layout.

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
	MlDsa44Suite,
	parseSignedNote,
	parseCheckpointBody,
	parseCosigSignaturePayload,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { signSthMldsa44Vectors } from '../../vectors/sign_sth_mldsa44.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const sha2  = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	const sha3  = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
	const mldsa = readFileSync(join(__dirname, '../../../build/mldsa.wasm'));
	await init({ sha2, sha3, mldsa });
});

function buildLog(v: typeof signSthMldsa44Vectors[number]): SignedLog<typeof MlDsa44Suite> {
	const tree = new Sha256Tree(new MemoryStorage());
	for (const leaf of v.leaves) tree.append(utf8ToBytes(leaf));
	return new SignedLog({
		tree,
		suite: MlDsa44Suite,
		origin: v.origin,
		signingKey: hexToBytes(v.skHex),
		pubkey: hexToBytes(v.pkHex),
	});
}

describe('SignedLog<MlDsa44Suite> roundtrip, c2sp.org/tlog-cosignature §"ML-DSA-44 signed message"', () => {
	for (const v of signSthMldsa44Vectors) {
		it(`verify accepts recorded deterministic envelope: ${v.id}`, () => {
			const log = buildLog(v);
			try {
				expect(log.verifyCheckpoint(hexToBytes(v.envelopeHex))).toBe(true);
			} finally {
				log.dispose();
			}
		});

		it(`production hedged sign produces an envelope that verifies: ${v.id}`, () => {
			// SignedLog.signCheckpoint routes through MlDsa44Suite.sign
			// which is hedged per FIPS 204 §3.4. The bytes differ from
			// the recorded byte-stable envelope, but the result must
			// still verify under the same SignedLog configuration.
			const log = buildLog(v);
			try {
				const env = log.signCheckpoint({ timestamp: v.timestamp });
				expect(log.verifyCheckpoint(env)).toBe(true);
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
			const env = parseSignedNote(hexToBytes(v.envelopeHex));
			expect(bytesToHex(env.body)).toBe(v.bodyHex);
			expect(env.signatures.length).toBe(1);
			const sig = env.signatures[0];
			expect(bytesToHex(sig.keyId)).toBe(v.keyIdHex);
			expect(bytesToHex(sig.signature)).toBe(v.cosigPayloadHex);
			const parsed = parseCosigSignaturePayload(sig.signature, 2420);
			expect(parsed.timestamp).toBe(v.timestamp);
			expect(bytesToHex(parsed.signature)).toBe(v.sigHex);
			const cp = parseCheckpointBody(env.body);
			expect(cp.origin).toBe(v.origin);
			expect(cp.treeSize).toBe(v.treeSize);
		});
	}
});
