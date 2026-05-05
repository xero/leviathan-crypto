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
// test/unit/aes/aes_cbc_mmt.test.ts
//
// Gate 9 — AES CBC Multi-block Message Test against the three NIST CAVP
// AESVS MMT files (one per key size). Vectors are 1..10 blocks long
// (16, 32, 48, ..., 160 bytes). Same per-record format as the KAT
// files; the only structural difference is multi-block PT/CT.
//
// Reference: NIST SP 800-38A §6.2 (CBC mode), AESAVS §6.3 (MMT
// methodology).

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { getInstance } from '../../../src/ts/init.js';
import { parseCbcMmtFile, type CbcKatVector } from './vector_parser';
import { fromHex, toHex } from '../helpers';

interface AesCbcExports {
	memory:               WebAssembly.Memory
	getKeyOffset:         () => number
	getChunkPtOffset:     () => number
	getChunkCtOffset:     () => number
	getCbcIvOffset:       () => number
	loadKey:              (n: number) => number
	cbcEncryptChunk:      (n: number) => number
	cbcDecryptChunk_simd: (n: number) => number
}

function getExports(): AesCbcExports {
	return getInstance('aes').exports as unknown as AesCbcExports;
}

beforeAll(async () => {
	await init({ aes: aesWasm });
});

function rawCbcEncrypt(v: CbcKatVector): string {
	const x = getExports();
	const mem = new Uint8Array(x.memory.buffer);
	const key = fromHex(v.key);
	const iv  = fromHex(v.iv);
	const pt  = fromHex(v.pt);
	mem.set(key, x.getKeyOffset());
	x.loadKey(key.length);
	mem.set(iv, x.getCbcIvOffset());
	mem.set(pt, x.getChunkPtOffset());
	const ret = x.cbcEncryptChunk(pt.length);
	if (ret < 0) throw new Error(`cbcEncryptChunk rejected len=${pt.length}`);
	return toHex(mem.slice(x.getChunkCtOffset(), x.getChunkCtOffset() + pt.length));
}

function rawCbcDecrypt(v: CbcKatVector): string {
	const x = getExports();
	const mem = new Uint8Array(x.memory.buffer);
	const key = fromHex(v.key);
	const iv  = fromHex(v.iv);
	const ct  = fromHex(v.ct);
	mem.set(key, x.getKeyOffset());
	x.loadKey(key.length);
	mem.set(iv, x.getCbcIvOffset());
	mem.set(ct, x.getChunkCtOffset());
	const ret = x.cbcDecryptChunk_simd(ct.length);
	if (ret < 0) throw new Error(`cbcDecryptChunk_simd rejected len=${ct.length}`);
	return toHex(mem.slice(x.getChunkPtOffset(), x.getChunkPtOffset() + ct.length));
}

for (const file of ['aes_CBCMMT128.rsp', 'aes_CBCMMT192.rsp', 'aes_CBCMMT256.rsp']) {
	describe(`AES CBC MMT (Gate 9) — CAVP ${file}`, () => {
		const { encrypt, decrypt } = parseCbcMmtFile(file);

		it('parses non-zero vectors (encrypt + decrypt)', () => {
			expect(encrypt.length).toBeGreaterThan(0);
			expect(decrypt.length).toBeGreaterThan(0);
		});

		it(`all ${encrypt.length} encrypt vectors pass (multi-block)`, () => {
			for (const v of encrypt) {
				expect(
					rawCbcEncrypt(v),
					`COUNT=${v.count} key=${v.key} iv=${v.iv} pt=${v.pt}`,
				).toBe(v.ct);
			}
		});

		it(`all ${decrypt.length} decrypt vectors pass (multi-block, SIMD path)`, () => {
			for (const v of decrypt) {
				expect(
					rawCbcDecrypt(v),
					`COUNT=${v.count} key=${v.key} iv=${v.iv} ct=${v.ct}`,
				).toBe(v.pt);
			}
		});
	});
}
