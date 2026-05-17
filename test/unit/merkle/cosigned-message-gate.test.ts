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
// §"ML-DSA-44 signed message" `cosigned_message` TLS-Presentation
// struct construction. Reproduces the log-self-cosignature wire
// bytes byte-for-byte via `buildCosignedMessage(input)` for the
// c2sp.org/tlog-cosignature worked-example body. The bytes that
// ML-DSA-44 signs are this struct (not the cosignature/v1 form), so
// any deviation here is a wire-format-breaking bug that no other
// ML-DSA-44 cosig test can usefully exercise.

import { describe, it, expect } from 'vitest';
import {
	buildCosignedMessage,
	MerkleCodecError,
	hexToBytes,
	bytesToHex,
} from '../../../src/ts/index.js';
import { COSIGNED_MESSAGE_RECORDS } from '../../vectors/cosigned_message.js';

describe('cosigned_message, c2sp.org/tlog-cosignature §"ML-DSA-44 signed message"', () => {
	it('GATE: buildCosignedMessage reproduces the spec worked-example wire bytes', () => {
		const gate = COSIGNED_MESSAGE_RECORDS[0];
		expect(gate.desc.startsWith('GATE:')).toBe(true);
		expect(gate.cosignerName).toBe('example.com/behind-the-sofa');
		expect(gate.logOrigin).toBe('example.com/behind-the-sofa');
		expect(gate.timestamp).toBe(1679315147);
		expect(gate.start).toBe(0);
		expect(gate.end).toBe(20852163);

		const out = buildCosignedMessage({
			cosignerName: gate.cosignerName,
			timestamp: gate.timestamp,
			logOrigin: gate.logOrigin,
			start: gate.start,
			end: gate.end,
			hash: hexToBytes(gate.hashHex),
		});
		expect(bytesToHex(out)).toBe(gate.expectedHex);
	});

	for (const rec of COSIGNED_MESSAGE_RECORDS) {
		it(`KAT: ${rec.desc}`, () => {
			const out = buildCosignedMessage({
				cosignerName: rec.cosignerName,
				timestamp: rec.timestamp,
				logOrigin: rec.logOrigin,
				start: rec.start,
				end: rec.end,
				hash: hexToBytes(rec.hashHex),
			});
			expect(bytesToHex(out)).toBe(rec.expectedHex);
		});
	}

	it('label is exactly the 12 bytes "subtree/v1\\n\\0" per §"ML-DSA-44 signed message"', () => {
		// Pulled out of the gate record's expectedHex: the first 12
		// bytes MUST be the spec-mandated label. Locking this here
		// catches a copy-paste error in the codec's label constant.
		const out = buildCosignedMessage({
			cosignerName: 'a',
			timestamp: 0,
			logOrigin: 'b',
			start: 0,
			end: 0,
			hash: new Uint8Array(32),
		});
		const label = out.subarray(0, 12);
		expect(bytesToHex(label)).toBe('737562747265652f76310a00');
	});

	it('struct layout for minimal inputs: total = 70 + |cosigner_name| + |log_origin|', () => {
		// |cosigner_name| = 1, |log_origin| = 1 → 72-byte total.
		const out = buildCosignedMessage({
			cosignerName: 'a',
			timestamp: 0,
			logOrigin: 'b',
			start: 0,
			end: 0,
			hash: new Uint8Array(32),
		});
		expect(out.length).toBe(12 + 1 + 1 + 8 + 1 + 1 + 8 + 8 + 32);
	});
});

describe('cosigned_message rejection paths', () => {
	function expectMerkleCodecError(fn: () => unknown, discriminator: string): void {
		try {
			fn();
			throw new Error(`expected MerkleCodecError('${discriminator}'), no throw`);
		} catch (err) {
			expect(err).toBeInstanceOf(MerkleCodecError);
			expect((err as MerkleCodecError).discriminator).toBe(discriminator);
		}
	}

	const baseInput = {
		cosignerName: 'a',
		timestamp: 0,
		logOrigin: 'b',
		start: 0,
		end: 0,
		hash: new Uint8Array(32),
	};

	it('rejects negative timestamp', () => {
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, timestamp: -1 }),
			'timestamp-out-of-range',
		);
	});

	it('rejects timestamp > Number.MAX_SAFE_INTEGER', () => {
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, timestamp: Number.MAX_SAFE_INTEGER + 1 }),
			'timestamp-out-of-range',
		);
	});

	it('rejects negative start', () => {
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, start: -1 }),
			'timestamp-out-of-range',
		);
	});

	it('rejects negative end', () => {
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, end: -1 }),
			'timestamp-out-of-range',
		);
	});

	it('rejects empty cosigner_name', () => {
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, cosignerName: '' }),
			'cosigner-name-length',
		);
	});

	it('rejects cosigner_name > 255 bytes UTF-8', () => {
		// 256 ASCII bytes.
		const longName = 'a'.repeat(256);
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, cosignerName: longName }),
			'cosigner-name-length',
		);
	});

	it('rejects empty log_origin', () => {
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, logOrigin: '' }),
			'log-origin-length',
		);
	});

	it('rejects log_origin > 255 bytes UTF-8', () => {
		const longOrigin = 'b'.repeat(256);
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, logOrigin: longOrigin }),
			'log-origin-length',
		);
	});

	it('rejects non-32-byte hash', () => {
		expect(() => buildCosignedMessage({ ...baseInput, hash: new Uint8Array(31) }))
			.toThrow(RangeError);
	});

	it('rejects non-Uint8Array hash', () => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect(() => buildCosignedMessage({ ...baseInput, hash: 'not-bytes' as any }))
			.toThrow(TypeError);
	});

	it('rejects start != 0 with timestamp != 0 (spec MUST)', () => {
		// c2sp.org/tlog-cosignature §"ML-DSA-44 signed message":
		// "If start is not zero, timestamp MUST be zero."
		expectMerkleCodecError(
			() => buildCosignedMessage({ ...baseInput, start: 1, timestamp: 1 }),
			'cosigned-message-state',
		);
	});

	it('accepts start = 0 with timestamp = 0 (no-statement case)', () => {
		// Per spec, "These two values MAY be zero if the cosigner
		// doesn't make any statement". Explicit positive test.
		expect(() => buildCosignedMessage({ ...baseInput, start: 0, timestamp: 0 }))
			.not.toThrow();
	});

	it('accepts start != 0 with timestamp = 0 (subtree case)', () => {
		expect(() => buildCosignedMessage({ ...baseInput, start: 1, timestamp: 0 }))
			.not.toThrow();
	});
});
