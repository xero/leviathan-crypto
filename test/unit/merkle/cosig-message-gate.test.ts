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
// GATE: c2sp.org/tlog-cosignature (Transparency Log Cosignatures)
// §"Ed25519 signed message" construction. Reproduces the spec worked
// example byte-for-byte via `buildCosigSignedMessage(body, ts)` for
// the c2sp.org/tlog-checkpoint §Note text body and timestamp
// `1679315147` from the spec. The signed message is what the
// cosigner runs through Ed25519 sign; any deviation here is a
// wire-format-breaking bug, so no other cosig test runs until this
// gate passes.

import { describe, it, expect } from 'vitest';
import {
	buildCosigSignedMessage,
	MerkleCodecError,
	utf8ToBytes,
} from '../../../src/ts/index.js';
import { COSIG_MESSAGE_RECORDS } from '../../vectors/cosig_message.js';

describe('Cosig signed message, c2sp.org/tlog-cosignature §"Ed25519 signed message"', () => {
	it('GATE: buildCosigSignedMessage reproduces the spec worked example bytes', () => {
		const gate = COSIG_MESSAGE_RECORDS[0];
		expect(gate.desc.startsWith('GATE:')).toBe(true);
		expect(gate.timestamp).toBe(1679315147);

		const out = buildCosigSignedMessage(utf8ToBytes(gate.body), gate.timestamp);
		expect(out).toEqual(utf8ToBytes(gate.expectedMessage));
	});

	for (const rec of COSIG_MESSAGE_RECORDS) {
		it(`KAT: ${rec.desc}`, () => {
			const out = buildCosigSignedMessage(utf8ToBytes(rec.body), rec.timestamp);
			expect(out).toEqual(utf8ToBytes(rec.expectedMessage));
		});
	}

	it('rejects a body that does not end in U+000A', () => {
		// c2sp.org/tlog-cosignature §"Ed25519 signed message" appends
		// the body including its terminating newline. A body without
		// the newline would produce a malformed signed message.
		const badBody = utf8ToBytes('example.com/log42\n0\nAAA');
		expect(() => buildCosigSignedMessage(badBody, 1)).toThrow(RangeError);
	});

	it('rejects a non-Uint8Array body', () => {
		// Defensive runtime guard against caller misuse, mirroring the
		// other merkle codec entry points.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect(() => buildCosigSignedMessage('not-bytes' as any, 1)).toThrow(TypeError);
	});

	it('rejects negative timestamps', () => {
		const body = utf8ToBytes('example.com/log42\n0\nAAA=\n');
		try {
			buildCosigSignedMessage(body, -1);
			throw new Error('expected throw');
		} catch (err) {
			expect(err).toBeInstanceOf(MerkleCodecError);
			expect((err as MerkleCodecError).discriminator).toBe('timestamp-out-of-range');
		}
	});

	it('rejects non-integer timestamps', () => {
		const body = utf8ToBytes('example.com/log42\n0\nAAA=\n');
		try {
			buildCosigSignedMessage(body, 1.5);
			throw new Error('expected throw');
		} catch (err) {
			expect(err).toBeInstanceOf(MerkleCodecError);
			expect((err as MerkleCodecError).discriminator).toBe('timestamp-out-of-range');
		}
	});

	it('rejects timestamps exceeding Number.MAX_SAFE_INTEGER', () => {
		const body = utf8ToBytes('example.com/log42\n0\nAAA=\n');
		try {
			buildCosigSignedMessage(body, Number.MAX_SAFE_INTEGER + 1);
			throw new Error('expected throw');
		} catch (err) {
			expect(err).toBeInstanceOf(MerkleCodecError);
			expect((err as MerkleCodecError).discriminator).toBe('timestamp-out-of-range');
		}
	});
});
