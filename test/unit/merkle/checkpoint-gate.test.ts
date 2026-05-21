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
// GATE: c2sp.org/tlog-checkpoint (Transparency Log Checkpoints) §Note
// text canonical body. Reproduces the spec's `example.com/behind-the-sofa`
// worked example byte-for-byte and round-trips it through
// `serializeCheckpointBody` and `parseCheckpointBody`. No other
// checkpoint test runs until this gate passes; the body bytes are
// what the STH signature is computed over, so any deviation here is
// a wire-format-breaking bug.

import { describe, it, expect } from 'vitest';
import {
	serializeCheckpointBody,
	parseCheckpointBody,
	base64ToBytes,
	utf8ToBytes,
} from '../../../src/ts/index.js';
import { CHECKPOINT_RECORDS } from '../../vectors/merkle_checkpoint.js';

describe('Checkpoint body codec, c2sp.org/tlog-checkpoint §Note text', () => {
	it('GATE: serializeCheckpointBody reproduces the spec worked example bytes', () => {
		const gate = CHECKPOINT_RECORDS[0];
		// Sanity-check that the gate record IS the spec example. The
		// invariant is that the first record's desc starts with `GATE:`.
		expect(gate.desc.startsWith('GATE:')).toBe(true);
		expect(gate.origin).toBe('example.com/behind-the-sofa');
		expect(gate.treeSize).toBe(20852163);

		const body = serializeCheckpointBody({
			origin: gate.origin,
			treeSize: gate.treeSize,
			rootHash: base64ToBytes(gate.rootHashB64),
		});
		expect(body).toEqual(utf8ToBytes(gate.expectedBody));
	});

	it('GATE: parseCheckpointBody round-trips the spec worked example', () => {
		const gate = CHECKPOINT_RECORDS[0];
		const expectedRoot = base64ToBytes(gate.rootHashB64);
		const body = utf8ToBytes(gate.expectedBody);
		const parsed = parseCheckpointBody(body, expectedRoot.length);
		expect(parsed.origin).toBe(gate.origin);
		expect(parsed.treeSize).toBe(gate.treeSize);
		expect(parsed.rootHash).toEqual(expectedRoot);

		// Re-serialize and assert byte equality with the original. The
		// body bytes are what the STH signature is computed over, so a
		// round-trip MUST be byte-stable.
		const reserialized = serializeCheckpointBody(parsed);
		expect(reserialized).toEqual(body);
	});

	for (const rec of CHECKPOINT_RECORDS) {
		it(`KAT serialize: ${rec.desc}`, () => {
			const root = base64ToBytes(rec.rootHashB64);
			const body = serializeCheckpointBody({
				origin: rec.origin,
				treeSize: rec.treeSize,
				rootHash: root,
			});
			expect(body).toEqual(utf8ToBytes(rec.expectedBody));
		});

		it(`KAT parse round-trip: ${rec.desc}`, () => {
			const root = base64ToBytes(rec.rootHashB64);
			const body = utf8ToBytes(rec.expectedBody);
			const parsed = parseCheckpointBody(body, root.length);
			expect(parsed.origin).toBe(rec.origin);
			expect(parsed.treeSize).toBe(rec.treeSize);
			expect(parsed.rootHash).toEqual(root);
		});
	}
});
