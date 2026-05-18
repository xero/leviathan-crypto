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
// GATE: BLAKE3 Merkle-tree hash KATs for the BLAKE3 substrate. The
// empty-tree root is anchored to `BLAKE3()` from the BLAKE3 spec; the
// single-leaf root is `BLAKE3(utf8("leaf-0"))`; the 1024-leaf root
// exercises the §5.3 `compress4` parallelism at the internal-node
// layer. Every recorded value in `merkle_blake3.ts` is independently
// reproduced by the RustCrypto `blake3` crate via
// `scripts/verify-vectors/src/merkle_blake3.rs`; no other BLAKE3
// merkle test runs until this gate passes.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	Blake3Hasher, Blake3Tree,
	MemoryStorage,
	bytesToHex, utf8ToBytes,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { merkleBlake3Records } from '../../vectors/merkle_blake3.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/blake3.wasm'));
	await init({ blake3: wasmBytes });
});

function recordFor(size: number) {
	const r = merkleBlake3Records.find(rec => rec.treeSize === size);
	if (!r) throw new Error(`vector record for size ${size} missing`);
	return r;
}

describe('Blake3Hasher BLAKE3 §2.4 / §2.5 KAT', () => {
	it('GATE: hashEmpty equals BLAKE3() (af1349b9... per BLAKE3 §2.5 empty-tree root)', () => {
		const got = Blake3Hasher.hashEmpty();
		const expected = recordFor(0).rootHex;
		// Spec-anchored value from BLAKE3 §2.3 Modes: BLAKE3() of empty input.
		expect(expected).toBe('af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262');
		expect(bytesToHex(got)).toBe(expected);
	});

	it('GATE: hashLeaf(utf8("leaf-0")) equals the size-1 tree root', () => {
		const got = Blake3Hasher.hashLeaf(utf8ToBytes('leaf-0'));
		expect(bytesToHex(got)).toBe(recordFor(1).rootHex);
	});

	it('GATE: Blake3Tree.rootHash() over 1024 deterministic leaves matches the recorded root', () => {
		const rec = recordFor(1024);
		const tree = new Blake3Tree(new MemoryStorage());
		for (let i = 0; i < 1024; i++) tree.append(utf8ToBytes(`leaf-${i}`));
		expect(bytesToHex(tree.rootHash())).toBe(rec.rootHex);
	}, 30_000);

	it('outputSize, name, and wasmModules describe the hash function correctly', () => {
		expect(Blake3Hasher.name).toBe('blake3');
		expect(Blake3Hasher.outputSize).toBe(32);
		expect(Array.from(Blake3Hasher.wasmModules)).toEqual(['blake3']);
	});

	it('hashInternal rejects wrong-length inputs', () => {
		const ok = new Uint8Array(32);
		expect(() => Blake3Hasher.hashInternal(new Uint8Array(31), ok)).toThrow();
		expect(() => Blake3Hasher.hashInternal(ok, new Uint8Array(33))).toThrow();
	});
});
