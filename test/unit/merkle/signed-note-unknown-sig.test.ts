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
// Forward-compatibility coverage for `parseSignedNote`. Per
// c2sp.org/signed-note (Note) §Signatures, "verifiers MUST ignore
// signatures from unknown keys"; for the byte-level parser this
// generalises to "lines that the parser does not recognise are
// counted in `ignoredCount` and discarded, without rejecting the
// envelope as a whole."
//
// This guarantees a future signature-algorithm byte (e.g. a synthetic
// `0xFE` that does not appear in leviathan's algorithm registry, and
// whose corresponding signature lines use a structurally-foreign line
// format) does not break parsers that pre-date its publication. The
// scenario here is: one Ed25519 cosignature line that parses cleanly,
// alongside one "future-algorithm" line whose payload is too short to
// hold the 4-byte key ID required by every leviathan-recognised
// algorithm. The parser includes the known signature and counts the
// unknown one in `ignoredCount`.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	serializeCheckpointBody,
	emitSignedNote,
	parseSignedNote,
	deriveKeyId,
	base64ToBytes,
	hexToBytes,
	utf8ToBytes,
	concat,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	await init({ sha2: wasmBytes });
});

describe('parseSignedNote forward-compatibility on unknown signature lines', () => {
	it('one Ed25519 line + one synthetic-future-algo line: keeps the Ed25519, ignores the synthetic', () => {
		// Build a real Ed25519 cosignature line. The signature payload
		// is opaque test data, only the wire format is exercised here.
		const body = serializeCheckpointBody({
			origin: 'example.com/behind-the-sofa',
			treeSize: 20852163,
			rootHash: base64ToBytes('CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I='),
		});

		const pk = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
		const keyId = deriveKeyId('example.com/behind-the-sofa', 0x04, pk);
		const sigPayload = new Uint8Array(72).fill(0x42);

		const knownSig = { name: 'example.com/behind-the-sofa', keyId, signature: sigPayload };
		const knownEnvelope = emitSignedNote(body, [knownSig]);

		// Append a synthetic line that mimics a future-algorithm
		// signature whose line format the parser does not understand.
		// Use a base64 payload of three bytes ("AAA="), which decodes
		// to 2 bytes, well below the 4-byte key-ID minimum required by
		// every leviathan-recognised algorithm. The line is otherwise
		// structurally well-formed (em dash + name + space + base64).
		const syntheticLine = utf8ToBytes('— witness.future.example/v2 AAA=\n');
		const envelope = concat(knownEnvelope, syntheticLine);

		const parsed = parseSignedNote(envelope);
		expect(parsed.signatures.length).toBe(1);
		expect(parsed.ignoredCount).toBe(1);
		expect(parsed.signatures[0].name).toBe('example.com/behind-the-sofa');
		// The keyId returned matches the one we put in, exactly.
		expect(Array.from(parsed.signatures[0].keyId)).toEqual(Array.from(keyId));
		// Body region is unmolested.
		expect(parsed.body).toEqual(body);
	});

	it('multiple unknown lines accumulate in ignoredCount; known lines remain in order', () => {
		const body = serializeCheckpointBody({
			origin: 'example.com/log',
			treeSize: 1,
			rootHash: base64ToBytes('CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I='),
		});

		// One real Ed25519-shaped line emitted via emitSignedNote.
		const pk = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
		const keyId = deriveKeyId('example.com/log', 0x04, pk);
		const knownLine = emitSignedNote(body, [{
			name: 'example.com/log',
			keyId,
			signature: new Uint8Array(72).fill(0x55),
		}]);

		// Append three synthetic future-algorithm lines.
		const synthetic = utf8ToBytes(
			'— alt.example/a AAA=\n'
			+ '- bad-no-emdash AAAAAAAA\n'
			+ '— another.future.example/v3 ABCD!!!\n',
		);
		const envelope = concat(knownLine, synthetic);

		const parsed = parseSignedNote(envelope);
		expect(parsed.signatures.length).toBe(1);
		expect(parsed.ignoredCount).toBe(3);
		expect(parsed.signatures[0].name).toBe('example.com/log');
	});
});
