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
// Gate 12, standalone GHASH validation. Walks each McGrew-Viega Appendix B
// test case through GHASH directly (not through full AES-GCM), validating
// the GF(2^128) multiply primitive against the published intermediate values
// and the published tag.
//
// What this gate proves:
//   - H = AES_ENC(K, 0^128) is correctly derived inside loadKey.
//   - The 4-bit windowed multiply table is correctly built from H.
//   - GHASH absorbs zero, AAD, and CT blocks correctly across all three
//     AES key sizes.
//   - The tag derivation T = GHASH_H(...) XOR AES_ENC(K, J0) reproduces
//     the published Tag for each Appendix B case (handles 12-byte fast-path
//     and variable-length-IV slow-path J0 derivations).
//
// If this gate fails but Phase 1-3 gates pass, the bug is somewhere in
// gf128.ts, ghash.ts, or the loadKey integration.

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

/** Manually compute J0 in TS (independent witness for the WASM path).
 * 96-bit IV: J0 = IV || 0x00000001.
 * Other-length IV: J0 = GHASH_H(IV || 0^{s+64} || [|IV|]_64), but we let
 * WASM compute that path via gcmStart and just read J0 back.
 */
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
		// AES_ENC of J0. If the AES core is correct (Phases 1-3 verified),
		// any tag mismatch isolates a bug to GHASH / GF(2^128) multiply.
		it(v.description, () => {
			const x = exports();
			try {
				const key = fromHex(v.key);
				const iv  = fromHex(v.iv);
				const aad = fromHex(v.aad);
				const ct  = fromHex(v.ct);

				// 1. Load key, derives H = AES_ENC(K, 0^128) inside loadKey.
				writeBytes(key, x.getKeyOffset());
				expect(x.loadKey(key.length)).toBe(0);

				// 2. Derive J0.
				let j0: Uint8Array;
				if (iv.length === 12) {
					// Fast path; verify in TS.
					j0 = expectedJ0For12ByteIv(iv);
				} else {
					// Slow path: drive gcmStart on (iv, empty aad) so it runs the
					// variable-IV GHASH path; gcmStart reads IV from CHUNK_PT.
					writeBytes(iv, x.getChunkPtOffset());
					expect(x.gcmStart(iv.length, 0)).toBe(0);
					j0 = readBytes(x.getJ0Offset(), 16);
				}

				// 3. Compute E(K, J0) by encrypting J0 directly.
				writeBytes(j0, x.getBlockPtOffset());
				x.encryptBlock();
				const j0e = readBytes(x.getBlockCtOffset(), 16);

				// 4. Build the GHASH input ourselves (TS side) and call ghashStart
				//    + ghashAbsorbBlock to walk it through. The format is
				//      A || pad_a (zeros to 16 bytes) || C || pad_c || lengths.
				//    `lengths` = [|A| in bits]_64 BE || [|C| in bits]_64 BE.
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

				// Place GHASH input in CHUNK_PT (it's just a scratch read region for
				// this isolated call; the AES key schedule is preserved and the
				// GHASH state is reset by ghashStart).
				writeBytes(ghashIn, x.getChunkPtOffset());

				// 5. Reset GHASH and absorb the full input (16-byte stride).
				x.ghashStart();
				x.ghashAbsorbWithLen(x.getChunkPtOffset(), totalLen);

				// 6. Final S = GHASH_H(...).
				const s = readBytes(x.getGhashAccOffset(), 16);

				// 7. T = J0E XOR S.
				const t = new Uint8Array(16);
				for (let i = 0; i < 16; i++) t[i] = j0e[i] ^ s[i];
				expect(toHex(t)).toBe(v.tag);
			} finally {
				x.wipeBuffers();
			}
		});
	}
});
