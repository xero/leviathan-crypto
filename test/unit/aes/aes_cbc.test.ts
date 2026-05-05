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
// test/unit/aes/aes_cbc.test.ts
//
// Gate 8 — AES CBC KAT against the twelve NIST CAVP AESVS files
// (4 file types × 3 key sizes). Encrypt and decrypt directions, all
// three key sizes (AES-128/192/256). The KAT vectors are raw block-
// level CBC operations (no padding); we exercise the WASM module
// directly via `cbcEncryptChunk` / `cbcDecryptChunk_simd`, bypassing
// the AESCbc wrapper's PKCS7 stage.
//
// Reference: NIST SP 800-38A §6.2 (CBC mode), AESAVS §6.2 (KAT
// methodology).

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AESCbc } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { getInstance } from '../../../src/ts/init.js';
import { parseCbcKatFile, type CbcKatVector } from './vector_parser';
import { fromHex, toHex } from '../helpers';

interface AesCbcExports {
	memory:               WebAssembly.Memory
	getKeyOffset:         () => number
	getChunkPtOffset:     () => number
	getChunkCtOffset:     () => number
	getCbcIvOffset:       () => number
	loadKey:              (n: number) => number
	cbcEncryptChunk:      (n: number) => number
	cbcDecryptChunk:      (n: number) => number
	cbcDecryptChunk_simd: (n: number) => number
	wipeBuffers:          () => void
}

function getExports(): AesCbcExports {
	return getInstance('aes').exports as unknown as AesCbcExports;
}

beforeAll(async () => {
	await init({ aes: aesWasm });
});

// ── Constructor gate ────────────────────────────────────────────────────────

describe('AESCbc — dangerUnauthenticated gate', () => {
	it('new AESCbc() throws without dangerUnauthenticated flag', () => {
		expect(() => new AESCbc()).toThrow(
			'leviathan-crypto: AESCbc is unauthenticated — use Seal with SerpentCipher or XChaCha20Cipher instead.',
		);
	});

	it('new AESCbc({ dangerUnauthenticated: true }) constructs successfully', () => {
		const c = new AESCbc({ dangerUnauthenticated: true });
		expect(c).toBeDefined();
		c.dispose();
	});
});

/** Encrypt one block (or multi-block) at a time via raw WASM CBC encrypt. */
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

/** Decrypt via the SIMD path so the gate exercises both scalar (encrypt) and SIMD (decrypt). */
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

const CBC_KAT_FILES = [
	'aes_CBCGFSbox128.rsp', 'aes_CBCKeySbox128.rsp',
	'aes_CBCVarKey128.rsp', 'aes_CBCVarTxt128.rsp',
	'aes_CBCGFSbox192.rsp', 'aes_CBCKeySbox192.rsp',
	'aes_CBCVarKey192.rsp', 'aes_CBCVarTxt192.rsp',
	'aes_CBCGFSbox256.rsp', 'aes_CBCKeySbox256.rsp',
	'aes_CBCVarKey256.rsp', 'aes_CBCVarTxt256.rsp',
];

for (const file of CBC_KAT_FILES) {
	describe(`AES CBC KAT (Gate 8) — CAVP ${file}`, () => {
		const { encrypt, decrypt } = parseCbcKatFile(file);

		it('parses non-zero vectors (encrypt + decrypt)', () => {
			expect(encrypt.length).toBeGreaterThan(0);
			expect(decrypt.length).toBeGreaterThan(0);
		});

		// GATE: full-corpus encrypt KAT — single-block raw CBC against CAVP.
		it(`all ${encrypt.length} encrypt vectors pass`, () => {
			for (const v of encrypt) {
				expect(
					rawCbcEncrypt(v),
					`COUNT=${v.count} key=${v.key} iv=${v.iv} pt=${v.pt}`,
				).toBe(v.ct);
			}
		});

		it(`all ${decrypt.length} decrypt vectors pass (SIMD path)`, () => {
			for (const v of decrypt) {
				expect(
					rawCbcDecrypt(v),
					`COUNT=${v.count} key=${v.key} iv=${v.iv} ct=${v.ct}`,
				).toBe(v.pt);
			}
		});
	});
}
