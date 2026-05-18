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
// GATE: end-to-end SignedLog wire format per c2sp.org/tlog-cosignature
// §Format. Reproduces the V1 record from sign_sth_ed25519.ts
// byte-for-byte through `SignedLog<Ed25519Suite>.signCheckpoint`.
// The envelope locks every step of the cosignature flow: body
// serialization, cosignature signed-message construction
// (cosignature/v1 + time + body), Ed25519 detached signing,
// timestamped_signature payload assembly, keyId derivation, and
// signed-note envelope emission. Any byte drift anywhere breaks
// the gate, and no other signed-log test exercises a non-overlapping
// path; debug the implementation before touching the recorded KAT.

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

describe('SignedLog gate, c2sp.org/tlog-cosignature §Format', () => {
	it('GATE: SignedLog<Ed25519Suite>.signCheckpoint reproduces sign_sth_ed25519 V1 envelope bytes', () => {
		const v = signSthEd25519Vectors[0];
		expect(v.id).toBe('V1');

		const tree = new Sha256Tree(new MemoryStorage());
		for (const leaf of v.leaves) tree.append(utf8ToBytes(leaf));
		expect(tree.size()).toBe(v.treeSize);
		expect(bytesToHex(tree.rootHash())).toBe(v.rootHashHex);

		const log = new SignedLog({
			tree,
			suite: Ed25519Suite,
			origin: v.origin,
			signingKey: hexToBytes(v.skHex),
			pubkey: hexToBytes(v.pkHex),
		});
		try {
			const envelope = log.signCheckpoint({ timestamp: v.timestamp });
			expect(bytesToHex(envelope)).toBe(v.envelopeHex);
		} finally {
			log.dispose();
		}
	});

	it('GATE: SignedLog<Ed25519Suite>.verifyCheckpoint accepts the recorded V1 envelope', () => {
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
			expect(log.verifyCheckpoint(hexToBytes(v.envelopeHex))).toBe(true);
		} finally {
			log.dispose();
		}
	});
});
