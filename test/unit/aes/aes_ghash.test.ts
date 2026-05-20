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
// test/unit/aes/aes_ghash.test.ts
//
// Standalone GHASH gate, McGrew-Viega Appendix B. Tag derivation
// T = GHASH_H(...) XOR AES_ENC(K, J0); proves H derivation +
// 4-bit windowed multiply table + GHASH absorb.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { aesGcmVectors } from '../../vectors/aes_gcm';
import { fromHex as fromHexRaw, toHex } from '../helpers';

const fromHex = (s: string): Uint8Array => s.length === 0 ? new Uint8Array(0) : fromHexRaw(s);

beforeAll(async () => {
	await init({ aes: aesWasm });
});

interface AesGcmGateExports {
	memory:           WebAssembly.Memory;
	getKeyOffset:     () => number;
	getBlockPtOffset: () => number;
	getBlockCtOffset: () => number;
	getChunkPtOffset: () => number;
	getHOffset:       () => number;
	getJ0Offset:      () => number;
	getGhashAccOffset:() => number;
	getTagOffset:     () => number;
	getAadOffset:     () => number;
	loadKey:          (n: number) => number;
	encryptBlock:     () => void;
	gcmStart:         (ivLen: number, aadLen: number) => number;
	ghashStart:       () => void;
	ghashAbsorbBlock: (off: number) => void;
	ghashAbsorbWithLen:(off: number, len: number) => void;
	ghashFinalize:    (aadBits: bigint, ctBits: bigint) => void;
	wipeBuffers:      () => void;
}

function exports(): AesGcmGateExports {
	return getInstance('aes').exports as unknown as AesGcmGateExports;
}

function memBytes(): Uint8Array {
	return new Uint8Array(exports().memory.buffer);
}

function readBytes(off: number, len: number): Uint8Array {
	return memBytes().slice(off, off + len);
}

function writeBytes(bytes: Uint8Array, off: number): void {
	memBytes().set(bytes, off);
}

/** TS witness for J0 on 12-byte IV: J0 = IV || 0x00000001. */
function expectedJ0For12ByteIv(iv: Uint8Array): Uint8Array {
	if (iv.length !== 12) throw new Error('not 12-byte IV');
	const j0 = new Uint8Array(16);
	j0.set(iv, 0);
	j0[15] = 1;
	return j0;
}

describe('GHASH gate (Gate 12), McGrew-Viega Appendix B', () => {
	for (const v of aesGcmVectors) {
		// GATE: tag derivation via standalone GHASH primitive plus a single
		// AES_ENC of J0. With the AES core verified independently, any tag
		// mismatch isolates a bug to GHASH / GF(2^128) multiply.
		it(v.description, () => {
			const x = exports();
			try {
				const key = fromHex(v.key);
				const iv  = fromHex(v.iv);
				const aad = fromHex(v.aad);
				const ct  = fromHex(v.ct);

				// 1. Load key (derives H = AES_ENC(K, 0^128)).
				writeBytes(key, x.getKeyOffset());
				expect(x.loadKey(key.length)).toBe(0);

				// 2. Derive J0.
				let j0: Uint8Array;
				if (iv.length === 12) {
					j0 = expectedJ0For12ByteIv(iv);
				} else {
					writeBytes(iv, x.getChunkPtOffset());
					expect(x.gcmStart(iv.length, 0)).toBe(0);
					j0 = readBytes(x.getJ0Offset(), 16);
				}

				// 3. j0e = E(K, J0).
				writeBytes(j0, x.getBlockPtOffset());
				x.encryptBlock();
				const j0e = readBytes(x.getBlockCtOffset(), 16);

				// 4. Build GHASH input: A || pad_a || C || pad_c || [|A|]_64 BE || [|C|]_64 BE.
				const aadPadLen = (16 - (aad.length % 16)) % 16;
				const ctPadLen  = (16 - (ct.length  % 16)) % 16;
				const totalLen  = aad.length + aadPadLen + ct.length + ctPadLen + 16;
				const ghashIn   = new Uint8Array(totalLen);
				ghashIn.set(aad, 0);
				ghashIn.set(ct,  aad.length + aadPadLen);
				const lensOff = aad.length + aadPadLen + ct.length + ctPadLen;
				const aadBitsView = new DataView(ghashIn.buffer, ghashIn.byteOffset + lensOff);
				aadBitsView.setBigUint64(0, BigInt(aad.length) * 8n, false);
				aadBitsView.setBigUint64(8, BigInt(ct.length)  * 8n, false);

				writeBytes(ghashIn, x.getChunkPtOffset());

				// 5. Reset and absorb.
				x.ghashStart();
				x.ghashAbsorbWithLen(x.getChunkPtOffset(), totalLen);

				// 6. S = GHASH_H(...).
				const s = readBytes(x.getGhashAccOffset(), 16);

				// 7. T = j0e XOR S.
				const t = new Uint8Array(16);
				for (let i = 0; i < 16; i++) t[i] = j0e[i] ^ s[i];
				expect(toHex(t)).toBe(v.tag);
			} finally {
				x.wipeBuffers();
			}
		});
	}
});
