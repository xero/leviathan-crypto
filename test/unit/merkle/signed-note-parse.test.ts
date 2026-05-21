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
// Parse the published spec example envelopes verbatim and assert the
// signature lines decode to the expected (name, key ID, signature)
// tuples. Covers the c2sp.org/signed-note (Note) §Format example and
// the c2sp.org/tlog-cosignature (Transparency Log Cosignatures) §Format
// example, both of which embed a working signature line shape leviathan
// must parse without modification.

import { describe, it, expect } from 'vitest';
import {
	parseSignedNote,
	utf8ToBytes,
	bytesToUtf8,
	bytesToHex,
} from '../../../src/ts/index.js';

// c2sp.org/signed-note §Format example: a quasimodo poem signed by one
// Ed25519 key. Reproduced verbatim from the spec markdown so the
// parser is exercised on the spec's own bytes.
const SIGNED_NOTE_SPEC_EXAMPLE =
	'Ognuno sta solo sul cuor della terra\n'
	+ 'trafitto da un raggio di sole:\n'
	+ '\n'
	+ 'ed è subito sera.\n'
	+ '\n'
	+ '— quasimodo.example/salvatore '
	+ 'NnugSzTjtVAewIS+Z/iJhUPeFDkO/5QQ2i5ddnGITLlC+EhfLW9oJKONrMouFSQU0xMcXxj99ihAQwaqP3ZekRwNtIc=\n';

// c2sp.org/tlog-cosignature §Format example: the behind-the-sofa
// checkpoint with one log signature and one witness cosignature.
const COSIG_SPEC_EXAMPLE =
	'example.com/behind-the-sofa\n'
	+ '20852163\n'
	+ 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n'
	+ '\n'
	+ '— example.com/behind-the-sofa '
	+ 'Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n'
	+ '— witness.example.com/w1 '
	+ 'jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZqhf5nNo0xUe+mbIUBkBIfZ+qnA==\n';

describe('parseSignedNote on c2sp spec examples', () => {
	it('parses c2sp.org/signed-note §Format example, one Ed25519 signature', () => {
		const bytes = utf8ToBytes(SIGNED_NOTE_SPEC_EXAMPLE);
		const parsed = parseSignedNote(bytes);
		expect(parsed.ignoredCount).toBe(0);
		expect(parsed.signatures.length).toBe(1);
		expect(parsed.signatures[0].name).toBe('quasimodo.example/salvatore');
		expect(parsed.signatures[0].keyId.length).toBe(4);
		// Spec example signature payload is 4-byte keyId + 64-byte Ed25519
		// sig = 68 bytes total inside the base64 blob; subtract keyId for
		// the signature field.
		expect(parsed.signatures[0].signature.length).toBe(64);

		// Body recovery: the spec example body includes an empty line in
		// the middle of the poem; the parser must use the LAST blank
		// line in the note as the body/signatures separator per
		// c2sp.org/signed-note §Format.
		const recoveredBody = bytesToUtf8(parsed.body);
		expect(recoveredBody.startsWith('Ognuno sta solo sul cuor della terra\n')).toBe(true);
		expect(recoveredBody.endsWith('ed è subito sera.\n')).toBe(true);
	});

	it('parses c2sp.org/tlog-cosignature §Format example, two signature lines', () => {
		const bytes = utf8ToBytes(COSIG_SPEC_EXAMPLE);
		const parsed = parseSignedNote(bytes);
		expect(parsed.ignoredCount).toBe(0);
		expect(parsed.signatures.length).toBe(2);
		expect(parsed.signatures[0].name).toBe('example.com/behind-the-sofa');
		expect(parsed.signatures[1].name).toBe('witness.example.com/w1');

		// Both signature lines have 4-byte key IDs and reproducible
		// payload sizes. The log line is 68 bytes total = 4 keyId + 64
		// Ed25519 sig (this is the c2sp.org/signed-note plain Ed25519
		// 0x01 line shape, NOT timestamped 0x04). The witness line is
		// 4 keyId + 76 timestamped Ed25519 cosig payload (8-byte
		// timestamp + 64-byte sig) per c2sp.org/tlog-cosignature §Format.
		expect(parsed.signatures[0].signature.length).toBe(64);
		expect(parsed.signatures[1].signature.length).toBe(72);

		// Key IDs are opaque to the parser; just sanity-check that they
		// were extracted as 4-byte sequences.
		expect(parsed.signatures[0].keyId.length).toBe(4);
		expect(parsed.signatures[1].keyId.length).toBe(4);
		// Distinct key IDs follow trivially because the spec example
		// names two different keys, but explicit comparison hardens
		// against a future regression where one line clobbers the other.
		expect(bytesToHex(parsed.signatures[0].keyId)).not.toBe(bytesToHex(parsed.signatures[1].keyId));
	});

	it('body region preserves the body trailing newline but excludes the blank-line separator', () => {
		const bytes = utf8ToBytes(COSIG_SPEC_EXAMPLE);
		const parsed = parseSignedNote(bytes);
		// The body ends with the rootHash line's newline. The blank
		// line that follows is the body/signatures separator and is
		// NOT part of the body region per the convention.
		expect(parsed.body[parsed.body.length - 1]).toBe(0x0a);
		// Body has exactly three lines (origin, treeSize, rootHash).
		const lfCount = parsed.body.reduce((n, b) => n + (b === 0x0a ? 1 : 0), 0);
		expect(lfCount).toBe(3);
	});
});
