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
// Negative-path coverage for the c2sp.org/tlog-cosignature §Format
// `timestamped_signature` payload codec
// (`parseCosigSignaturePayload`, `emitCosigSignaturePayload`).
// Asserts that every wire-shape violation throws a typed
// `MerkleCodecError` with the documented discriminator, so consumers
// can branch reliably on the failure mode.

import { describe, it, expect } from 'vitest';
import {
	emitCosigSignaturePayload,
	parseCosigSignaturePayload,
	MerkleCodecError,
} from '../../../src/ts/index.js';

function expectMerkleCodecError(fn: () => unknown, discriminator: string): void {
	try {
		fn();
		throw new Error(`expected MerkleCodecError('${discriminator}'), no throw`);
	} catch (err) {
		expect(err).toBeInstanceOf(MerkleCodecError);
		expect((err as MerkleCodecError).discriminator).toBe(discriminator);
	}
}

describe('parseCosigSignaturePayload rejection paths', () => {
	const ED_SIZE = 64;
	const ML_SIZE = 2420;

	it('throws cosig-payload-length-mismatch on payload shorter than 8 + sigSize', () => {
		expectMerkleCodecError(
			() => parseCosigSignaturePayload(new Uint8Array(8 + ED_SIZE - 1), ED_SIZE),
			'cosig-payload-length-mismatch',
		);
	});

	it('throws cosig-payload-length-mismatch on payload longer than 8 + sigSize', () => {
		expectMerkleCodecError(
			() => parseCosigSignaturePayload(new Uint8Array(8 + ED_SIZE + 1), ED_SIZE),
			'cosig-payload-length-mismatch',
		);
	});

	it('throws cosig-payload-length-mismatch on payload too short for the timestamp prefix', () => {
		expectMerkleCodecError(
			() => parseCosigSignaturePayload(new Uint8Array(4), ED_SIZE),
			'cosig-payload-length-mismatch',
		);
	});

	it('throws cosig-payload-length-mismatch when sigSize argument disagrees with payload size', () => {
		// Payload was built for ML-DSA-44 (8 + 2420 = 2428 bytes); pass
		// it through with sigSize=64 (Ed25519). The codec catches the
		// mismatch via the expected-length check, not via any other path.
		const wireForMldsa = new Uint8Array(8 + ML_SIZE);
		expectMerkleCodecError(
			() => parseCosigSignaturePayload(wireForMldsa, ED_SIZE),
			'cosig-payload-length-mismatch',
		);
	});

	it('throws timestamp-exceeds-safe-integer for u64 timestamps > Number.MAX_SAFE_INTEGER', () => {
		// 0x20_00_00_00_00_00_00_00 = 2^61, far above 2^53 - 1. tsHi
		// 32-bit prefix is 0x20000000 = 0x200000 * 0x100, so the
		// safe-integer guard fires.
		const payload = new Uint8Array(8 + ED_SIZE);
		payload[0] = 0x20;
		expectMerkleCodecError(
			() => parseCosigSignaturePayload(payload, ED_SIZE),
			'timestamp-exceeds-safe-integer',
		);
	});

	it('throws timestamp-exceeds-safe-integer at the exact boundary 2^53', () => {
		// tsHi = 0x00200000, tsLo = 0x00000000 → ts = 2^53, one past
		// MAX_SAFE_INTEGER. The guard rejects tsHi >= 0x200000.
		const payload = new Uint8Array(8 + ED_SIZE);
		payload[0] = 0x00;
		payload[1] = 0x20;
		payload[2] = 0x00;
		payload[3] = 0x00;
		expectMerkleCodecError(
			() => parseCosigSignaturePayload(payload, ED_SIZE),
			'timestamp-exceeds-safe-integer',
		);
	});

	it('accepts the largest safe-integer timestamp 2^53 - 1', () => {
		// tsHi = 0x001FFFFF, tsLo = 0xFFFFFFFF → ts = Number.MAX_SAFE_INTEGER.
		// One byte below the rejection boundary; codec accepts.
		const payload = new Uint8Array(8 + ED_SIZE);
		payload[0] = 0x00;
		payload[1] = 0x1f;
		payload[2] = 0xff;
		payload[3] = 0xff;
		payload[4] = 0xff;
		payload[5] = 0xff;
		payload[6] = 0xff;
		payload[7] = 0xff;
		const parsed = parseCosigSignaturePayload(payload, ED_SIZE);
		expect(parsed.timestamp).toBe(Number.MAX_SAFE_INTEGER);
	});

	it('rejects a non-Uint8Array payload', () => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect(() => parseCosigSignaturePayload('not-bytes' as any, ED_SIZE))
			.toThrow(TypeError);
	});

	it('rejects a non-integer sigSize', () => {
		expect(() => parseCosigSignaturePayload(new Uint8Array(72), 64.5))
			.toThrow(RangeError);
	});

	it('rejects a negative sigSize', () => {
		expect(() => parseCosigSignaturePayload(new Uint8Array(72), -1))
			.toThrow(RangeError);
	});
});

describe('emitCosigSignaturePayload rejection paths', () => {
	it('throws timestamp-out-of-range on negative timestamp', () => {
		expectMerkleCodecError(
			() => emitCosigSignaturePayload(-1, new Uint8Array(64)),
			'timestamp-out-of-range',
		);
	});

	it('throws timestamp-out-of-range on non-integer timestamp', () => {
		expectMerkleCodecError(
			() => emitCosigSignaturePayload(1.5, new Uint8Array(64)),
			'timestamp-out-of-range',
		);
	});

	it('throws timestamp-out-of-range above Number.MAX_SAFE_INTEGER', () => {
		expectMerkleCodecError(
			() => emitCosigSignaturePayload(Number.MAX_SAFE_INTEGER + 1, new Uint8Array(64)),
			'timestamp-out-of-range',
		);
	});

	it('rejects a non-Uint8Array signature', () => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		expect(() => emitCosigSignaturePayload(0, 'not-bytes' as any))
			.toThrow(TypeError);
	});
});
