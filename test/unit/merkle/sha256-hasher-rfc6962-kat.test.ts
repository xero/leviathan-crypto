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
// GATE: RFC 6962 / RFC 9162 §2.1.1 hash KATs for the SHA-256 merkle
// substrate. Empty-tree, empty-leaf, leaf, and internal-node values
// sourced byte-for-byte from transparency-dev/merkle's
// rfc6962/rfc6962_test.go (pinned commit fefdc92...). No other merkle
// test runs until this gate passes.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init, Sha256Hasher,
	bytesToHex, utf8ToBytes,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import {
	merkleSha256EmptyKat,
	merkleSha256EmptyLeafKat,
	merkleSha256LeafKat,
	merkleSha256NodeKat,
} from '../../vectors/merkle_sha256.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	await init({ sha2: wasmBytes });
});

describe('Sha256Hasher RFC 6962 KAT', () => {
	it('GATE: hashEmpty matches MTH({}) = SHA-256()', () => {
		const got = Sha256Hasher.hashEmpty();
		expect(bytesToHex(got)).toBe(merkleSha256EmptyKat.expectedHex);
	});

	it('GATE: hashLeaf("") matches SHA-256(0x00)', () => {
		const got = Sha256Hasher.hashLeaf(utf8ToBytes(merkleSha256EmptyLeafKat.inputUtf8!));
		expect(bytesToHex(got)).toBe(merkleSha256EmptyLeafKat.expectedHex);
	});

	it('GATE: hashLeaf("L123456") matches SHA-256(0x00 || "L123456")', () => {
		const got = Sha256Hasher.hashLeaf(utf8ToBytes(merkleSha256LeafKat.inputUtf8!));
		expect(bytesToHex(got)).toBe(merkleSha256LeafKat.expectedHex);
	});

	it('GATE: hashInternal("N123", "N456") matches SHA-256(0x01 || "N123" || "N456")', () => {
		const got = Sha256Hasher.hashInternal(
			utf8ToBytes(merkleSha256NodeKat.leftUtf8!),
			utf8ToBytes(merkleSha256NodeKat.rightUtf8!),
		);
		expect(bytesToHex(got)).toBe(merkleSha256NodeKat.expectedHex);
	});

	it('outputSize and wasmModules describe the hash function correctly', () => {
		expect(Sha256Hasher.name).toBe('sha256');
		expect(Sha256Hasher.outputSize).toBe(32);
		expect(Array.from(Sha256Hasher.wasmModules)).toEqual(['sha2']);
	});
});
