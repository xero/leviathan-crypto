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
// KAT for `deriveKeyId` per c2sp.org/signed-note (Note) §Signatures
// and c2sp.org/tlog-cosignature (Transparency Log Cosignatures) §Format:
//
//     key_id = SHA-256(name || 0x0A || algo_byte || pubkey)[:4]
//
// The first record is spec-anchored against the c2sp.org/signed-note
// §Verifier keys §Example value; the remaining two are self-generated
// for the Ed25519 cosignature (algo 0x04) and ML-DSA-44 cosignature
// (algo 0x06) cases and are cross-verified by the Rust oracle in
// scripts/verify-vectors/src/merkle_checkpoint.rs.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	deriveKeyId,
	suiteFormatEnumToAlgoByte,
	ALGO_BYTE_ED25519_NOTE,
	ALGO_BYTE_ED25519_COSIG,
	ALGO_BYTE_MLDSA44_COSIG,
	hexToBytes,
	bytesToHex,
	Ed25519Suite,
	MlDsa44Suite,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { KEY_ID_RECORDS } from '../../vectors/merkle_signed_note.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	await init({ sha2: wasmBytes });
});

describe('deriveKeyId, c2sp.org/signed-note §Signatures', () => {
	it('GATE: spec example reproduces key ID 530d903a', () => {
		const spec = KEY_ID_RECORDS[0];
		expect(spec.expectedKeyIdHex).toBe('530d903a');
		const got = deriveKeyId(spec.name, spec.algoByte, hexToBytes(spec.pubkeyHex));
		expect(bytesToHex(got)).toBe(spec.expectedKeyIdHex);
		expect(got.length).toBe(4);
	});

	for (const rec of KEY_ID_RECORDS) {
		it(`KAT: ${rec.desc}`, () => {
			const got = deriveKeyId(rec.name, rec.algoByte, hexToBytes(rec.pubkeyHex));
			expect(bytesToHex(got)).toBe(rec.expectedKeyIdHex);
		});
	}

	it('throws on empty name', () => {
		expect(() => deriveKeyId('', 0x04, new Uint8Array(32))).toThrow(/non-empty/);
	});

	it('throws on name with whitespace', () => {
		expect(() => deriveKeyId('bad name', 0x04, new Uint8Array(32))).toThrow(/whitespace|plus/);
	});

	it('throws on name with plus character', () => {
		expect(() => deriveKeyId('bad+name', 0x04, new Uint8Array(32))).toThrow(/plus/);
	});

	it('throws on out-of-range algo byte', () => {
		expect(() => deriveKeyId('example.com/log', 256, new Uint8Array(32))).toThrow(/byte in \[0, 255\]/);
		expect(() => deriveKeyId('example.com/log', -1, new Uint8Array(32))).toThrow(/byte in \[0, 255\]/);
	});
});

describe('suiteFormatEnumToAlgoByte registry, c2sp.org/tlog-cosignature §Format', () => {
	it('Ed25519Suite maps to algo byte 0x04', () => {
		expect(suiteFormatEnumToAlgoByte(Ed25519Suite.formatEnum)).toBe(ALGO_BYTE_ED25519_COSIG);
		expect(ALGO_BYTE_ED25519_COSIG).toBe(0x04);
	});

	it('MlDsa44Suite maps to algo byte 0x06', () => {
		expect(suiteFormatEnumToAlgoByte(MlDsa44Suite.formatEnum)).toBe(ALGO_BYTE_MLDSA44_COSIG);
		expect(ALGO_BYTE_MLDSA44_COSIG).toBe(0x06);
	});

	it('exports the plain Ed25519 note algo byte 0x01 for spec completeness', () => {
		expect(ALGO_BYTE_ED25519_NOTE).toBe(0x01);
	});

	it('returns undefined for unregistered format enum values', () => {
		// 0xFE and 0xFF are reserved in c2sp.org/signed-note §Signatures
		// §Signature types but have no leviathan suite mapping.
		expect(suiteFormatEnumToAlgoByte(0xfe)).toBeUndefined();
		expect(suiteFormatEnumToAlgoByte(0xff)).toBeUndefined();
	});
});
