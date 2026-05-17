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
// Big-endian u64 timestamp encoding KAT for the
// `timestamped_signature` struct per c2sp.org/tlog-cosignature
// §Format and RFC 8446 §3.3, Presentation Language. Locks the
// per-byte layout produced by `emitCosigSignaturePayload` so future
// refactors of the bit-shift code cannot silently flip endianness
// or drop a high-32-bit overflow.
//
// Per c2sp.org/tlog-cosignature §Format and RFC 8446 §3.3, integers
// in the timestamped_signature struct are serialized in big-endian
// (network) byte order: the most significant byte comes first.

import { describe, it, expect } from 'vitest';
import {
	emitCosigSignaturePayload,
	bytesToHex,
} from '../../../src/ts/index.js';

interface Case {
	desc: string;
	timestamp: number;
	expectedBeHex: string;
}

const CASES: readonly Case[] = [
	{
		desc: 'epoch zero → all-zero 8 bytes',
		timestamp: 0,
		expectedBeHex: '0000000000000000',
	},
	{
		desc: 'one second past epoch → 0x00..01',
		timestamp: 1,
		expectedBeHex: '0000000000000001',
	},
	{
		desc: 'spec example 1679315147 → 0x00 00 00 00 64 18 50 cb',
		timestamp: 1679315147,
		expectedBeHex: '00000000641850cb',
	},
	{
		desc: 'low byte all-ones 0xff',
		timestamp: 0xff,
		expectedBeHex: '00000000000000ff',
	},
	{
		desc: 'low 32 bits all-ones 0xffffffff',
		timestamp: 0xffffffff,
		expectedBeHex: '00000000ffffffff',
	},
	{
		desc: 'crosses 32-bit boundary at 2^32',
		timestamp: 0x100000000,
		expectedBeHex: '0000000100000000',
	},
	{
		desc: 'Number.MAX_SAFE_INTEGER (2^53 - 1)',
		timestamp: Number.MAX_SAFE_INTEGER,
		expectedBeHex: '001fffffffffffff',
	},
];

describe('Timestamp big-endian encoding, c2sp.org/tlog-cosignature §Format', () => {
	for (const c of CASES) {
		it(`emitCosigSignaturePayload encodes ts=${c.timestamp} BE: ${c.desc}`, () => {
			// Pin the timestamp prefix only; the rest of the payload is
			// a zero-byte signature placeholder that we slice off below.
			const sig = new Uint8Array(0);
			const payload = emitCosigSignaturePayload(c.timestamp, sig);
			expect(payload.length).toBe(8);
			expect(bytesToHex(payload)).toBe(c.expectedBeHex);
		});
	}
});
