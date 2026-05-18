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
// `c2sp.org/tlog-checkpoint` §Note text marks extension lines as
// OPTIONAL and NOT RECOMMENDED; the Ed25519 cosignature signed
// message includes them when present, but the ML-DSA-44
// cosigned_message struct explicitly does NOT
// (`c2sp.org/tlog-cosignature` §"ML-DSA-44 signed message":
// "checkpoint extension lines are not included in the signed message
// for ML-DSA-44 cosignatures"). Mixing the two would produce
// asymmetric verification semantics across suites, so leviathan
// avoids the surface entirely: `serializeCheckpointBody` rejects any
// Checkpoint whose origin / treeSize / rootHash would emit
// extension lines, and `parseCheckpointBody` rejects any body whose
// line count exceeds three.
//
// This test confirms the rejection at both sides so future code
// can't accidentally start emitting extension lines and silently
// produce envelopes that ML-DSA-44 verifiers reject.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	utf8ToBytes,
	parseCheckpointBody,
	parseSignedNote,
	SignedLog,
	Sha256Tree,
	MemoryStorage,
	Ed25519Suite,
	hexToBytes,
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

describe('Phase 7 extension-line policy', () => {
	it('SignedLog.signCheckpoint emits a body with exactly 3 lines (no extensions)', () => {
		const v = signSthEd25519Vectors[0];
		const tree = new Sha256Tree(new MemoryStorage());
		for (const leaf of v.leaves) tree.append(utf8ToBytes(leaf));
		const log = new SignedLog({
			tree,
			suite: Ed25519Suite,
			origin: v.origin,
			signingKey: hexToBytes(v.skHex),
			pubkey: hexToBytes(v.pkHex),
		});
		try {
			const env = log.signCheckpoint({ timestamp: v.timestamp });
			const parsed = parseSignedNote(env);
			// Count 0x0A in the body; expect exactly 3 (origin, size,
			// base64 root). Extension lines would push the count up.
			let lf = 0;
			for (const b of parsed.body) if (b === 0x0a) lf++;
			expect(lf).toBe(3);
		} finally {
			log.dispose();
		}
	});

	it('parseCheckpointBody rejects bodies with a fourth (extension) line', () => {
		// Hand-craft a body with an extension line. The serializer
		// would never produce this; the parser is the second line of
		// defense if a malicious or buggy producer sneaks one in.
		const body = utf8ToBytes(
			'leviathan.test/log1\n'
			+ '1\n'
			+ 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n'
			+ 'extension-key value\n',
		);
		expect(() => parseCheckpointBody(body)).toThrow(RangeError);
	});

	it('verifyCheckpoint rejects an envelope whose body carries extension lines', () => {
		// Same hand-crafted body, wrapped in a SignedLog envelope.
		// verifyCheckpoint should return false because
		// parseCheckpointBody throws inside the verify path.
		const v = signSthEd25519Vectors[0];
		const tree = new Sha256Tree(new MemoryStorage());
		for (const leaf of v.leaves) tree.append(utf8ToBytes(leaf));
		const log = new SignedLog({
			tree,
			suite: Ed25519Suite,
			origin: v.origin,
			signingKey: hexToBytes(v.skHex),
			pubkey: hexToBytes(v.pkHex),
		});
		try {
			// Take the recorded envelope and inject an extension line
			// before the body's terminating LF (technically after
			// the root-hash line). Replace the body slice. The
			// resulting envelope will fail parseCheckpointBody and
			// verifyCheckpoint returns false.
			const env = hexToBytes(v.envelopeHex);
			const blank = (() => {
				for (let i = 0; i < env.length - 1; i++)
					if (env[i] === 0x0a && env[i + 1] === 0x0a) return i;
				throw new Error('no blank separator');
			})();
			const tampered = new Uint8Array(env.length + 16);
			tampered.set(env.subarray(0, blank), 0);
			tampered.set(utf8ToBytes('extension foo\n'), blank);
			tampered.set(env.subarray(blank), blank + 14);
			expect(log.verifyCheckpoint(tampered.subarray(0, blank + 14 + (env.length - blank)))).toBe(false);
		} finally {
			log.dispose();
		}
	});
});
