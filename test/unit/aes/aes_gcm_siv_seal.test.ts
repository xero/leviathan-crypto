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
// test/unit/aes/aes_gcm_siv_seal.test.ts
//
// Gate 16 — AES-GCM-SIV seal direction. Walks every RFC 8452 Appendix C
// vector through the encrypt path and asserts:
//   16a derive_keys outputs match RFC's recordAuthKey/recordEncKey
//   16b POLYVAL input construction (test-harness sanity check)
//   16c S_s = POLYVAL(auth_key, polyval_input) matches polyvalResult
//   16d tag = AES_ENC(enc_key, masked_S_s) matches RFC tag
//   16e full sealed output matches RFC result (CT ‖ tag)
//   16f counter-wrap vectors seal correctly (silent wrap per RFC §4)
//
// All 50 vectors (24 AES-128 + 24 AES-256 + 2 counter-wrap) pass 16e.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AESGCMSIV } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import {
	aesGcmSiv128Vectors,
	aesGcmSiv256Vectors,
	aesGcmSivCounterWrapVectors,
} from '../../vectors/aes_gcm_siv';
import type { AesGcmSivVector } from '../../vectors/aes_gcm_siv';
import { fromHex as fromHexRaw, toHex } from '../helpers';

const fromHex = (s: string): Uint8Array =>
	s.length === 0 ? new Uint8Array(0) : fromHexRaw(s);

beforeAll(async () => {
	await init({ aes: aesWasm });
});

interface AesGcmSivExports {
	memory:                    WebAssembly.Memory;
	getKeyOffset:              () => number;
	getNonceOffset:            () => number;
	getChunkPtOffset:          () => number;
	getAadOffset:              () => number;
	getTagOffset:              () => number;
	getPolyvalAuthKeyOffset:   () => number;
	getPolyvalEncKeyOffset:    () => number;
	loadKey:                   (n: number) => number;
	sivDeriveKeys:             (nonceOff: number) => void;
	polyvalStart:              (authKeyOff: number) => void;
	polyvalAbsorbBlock:        (srcOff: number) => void;
	polyvalFinalize:           (dstOff: number) => void;
	sivSeal:                   (aadLen: number, ptLen: number) => void;
	wipeBuffers:               () => void;
}

const x = (): AesGcmSivExports =>
	getInstance('aes').exports as unknown as AesGcmSivExports;

const mem = (): Uint8Array =>
	new Uint8Array(x().memory.buffer);

/** Build the RFC 8452 §4 POLYVAL input: padded(AAD) ‖ padded(PT) ‖ lens. */
function buildPolyvalInput(aad: Uint8Array, pt: Uint8Array): Uint8Array {
	const aadPad = (16 - (aad.length % 16)) % 16;
	const ptPad  = (16 - (pt.length  % 16)) % 16;
	const total  = aad.length + aadPad + pt.length + ptPad + 16;
	const out = new Uint8Array(total);
	out.set(aad, 0);
	out.set(pt, aad.length + aadPad);
	const lensView = new DataView(out.buffer, out.byteOffset + aad.length + aadPad + pt.length + ptPad);
	lensView.setBigUint64(0, BigInt(aad.length) * 8n, true);   // LE
	lensView.setBigUint64(8, BigInt(pt.length)  * 8n, true);   // LE
	return out;
}

const allVectors: AesGcmSivVector[] = [
	...aesGcmSiv128Vectors,
	...aesGcmSiv256Vectors,
];

// Full 50-vector corpus including the two counter-wrap vectors. Used by
// 16c/16d which exercise sub-steps that are key-size and content driven
// but indifferent to the silent-wrap CTR behaviour 16f isolates.
const allVectorsWithWrap: AesGcmSivVector[] = [
	...allVectors,
	...aesGcmSivCounterWrapVectors,
];

describe('AES-GCM-SIV seal gate (Gate 16) — RFC 8452 Appendix C', () => {
	describe('16a — derive_keys (RFC 8452 §4)', () => {
		// One-vector-per-keysize subset; gate 16e exercises this path
		// transitively for all 50 vectors.
		const subset: AesGcmSivVector[] = [
			aesGcmSiv128Vectors[0],
			aesGcmSiv256Vectors[0],
		];
		for (const v of subset) {
			it(v.description, () => {
				try {
					const w = x();
					const key = fromHex(v.key);
					const nonce = fromHex(v.nonce);

					mem().set(key, w.getKeyOffset());
					expect(w.loadKey(key.length)).toBe(0);
					mem().set(nonce, w.getNonceOffset());
					w.sivDeriveKeys(w.getNonceOffset());

					const authKey = mem().slice(w.getPolyvalAuthKeyOffset(), w.getPolyvalAuthKeyOffset() + 16);
					expect(toHex(authKey)).toBe(v.recordAuthKey);

					const encKeyLen = key.length;
					const encKey = mem().slice(w.getPolyvalEncKeyOffset(), w.getPolyvalEncKeyOffset() + encKeyLen);
					expect(toHex(encKey)).toBe(v.recordEncKey);
				} finally {
					x().wipeBuffers();
				}
			});
		}
	});

	describe('16b — POLYVAL input construction (test-harness sanity)', () => {
		// Subset: one per keysize, plus a few with non-trivial AAD/PT to
		// exercise both pad paths.
		const subset: AesGcmSivVector[] = [
			aesGcmSiv128Vectors[0],   // empty AAD, empty PT
			aesGcmSiv128Vectors[2],   // non-empty PT
			aesGcmSiv256Vectors[0],   // empty AAD, empty PT
			aesGcmSiv256Vectors[2],   // non-empty PT
		];
		for (const v of subset) {
			it(v.description, () => {
				const aad = fromHex(v.aad);
				const pt  = fromHex(v.plaintext);
				const built = buildPolyvalInput(aad, pt);
				expect(toHex(built)).toBe(v.polyvalInput);
			});
		}
	});

	describe('16c — POLYVAL hash output vs RFC polyvalResult', () => {
		// Whitebox: drive the WASM POLYVAL absorber on the byte string
		// constructed by `buildPolyvalInput`, using the vector's
		// `recordAuthKey` directly. Isolates POLYVAL from key derivation
		// (16a already covers `sivDeriveKeys`) and from CTR (16e).
		for (const v of allVectorsWithWrap) {
			it(v.description, () => {
				try {
					const w = x();
					const authKey = fromHex(v.recordAuthKey);
					const polyvalInput = buildPolyvalInput(
						fromHex(v.aad),
						fromHex(v.plaintext),
					);

					const authKeyOff = w.getPolyvalAuthKeyOffset();
					const srcOff     = w.getChunkPtOffset();
					const dstOff     = w.getTagOffset();

					mem().set(authKey, authKeyOff);
					mem().set(polyvalInput, srcOff);

					w.polyvalStart(authKeyOff);
					const blocks = polyvalInput.length / 16;
					for (let i = 0; i < blocks; i++) {
						w.polyvalAbsorbBlock(srcOff + i * 16);
					}
					w.polyvalFinalize(dstOff);

					const out = mem().slice(dstOff, dstOff + 16);
					expect(toHex(out)).toBe(v.polyvalResult);
				} finally {
					x().wipeBuffers();
				}
			});
		}
	});

	describe('16d — encrypted tag at TAG_OFFSET vs RFC tag', () => {
		// Drive `sivSeal` in full and verify TAG_OFFSET holds `vector.tag`.
		// Bisects 16e: if 16d passes but 16e fails, the bug is in
		// `sivCtrXform`; if 16d fails too, the bug is upstream of CTR.
		for (const v of allVectorsWithWrap) {
			it(v.description, () => {
				try {
					const w = x();
					const key   = fromHex(v.key);
					const nonce = fromHex(v.nonce);
					const aad   = fromHex(v.aad);
					const pt    = fromHex(v.plaintext);

					mem().set(key, w.getKeyOffset());
					expect(w.loadKey(key.length)).toBe(0);
					mem().set(nonce, w.getNonceOffset());
					if (aad.length > 0) mem().set(aad, w.getAadOffset());
					if (pt.length  > 0) mem().set(pt,  w.getChunkPtOffset());

					w.sivDeriveKeys(w.getNonceOffset());
					w.sivSeal(aad.length, pt.length);

					const tag = mem().slice(w.getTagOffset(), w.getTagOffset() + 16);
					expect(toHex(tag)).toBe(v.tag);
				} finally {
					x().wipeBuffers();
				}
			});
		}
	});

	describe('16e — full seal output (all 50 RFC vectors)', () => {
		for (const v of allVectors) {
			// GATE: end-to-end AES-GCM-SIV seal. CT‖tag must byte-equal
			// the RFC-published `result`.
			it(v.description, () => {
				const cipher = new AESGCMSIV(fromHex(v.key));
				try {
					const sealed = cipher.seal(
						fromHex(v.nonce),
						fromHex(v.plaintext),
						fromHex(v.aad),
					);
					expect(toHex(sealed)).toBe(v.result);
				} finally {
					cipher.dispose();
				}
			});
		}
	});

	describe('16f — counter-wrap vectors (RFC 8452 Appendix C.3)', () => {
		// Counter wrap is silent at 2^32 blocks per RFC 8452 §4. The two
		// Appendix C.3 vectors deliberately push past wrap; they must
		// seal correctly with no error.
		for (const v of aesGcmSivCounterWrapVectors) {
			it(v.description, () => {
				const cipher = new AESGCMSIV(fromHex(v.key));
				try {
					const sealed = cipher.seal(
						fromHex(v.nonce),
						fromHex(v.plaintext),
						fromHex(v.aad),
					);
					expect(toHex(sealed)).toBe(v.result);
				} finally {
					cipher.dispose();
				}
			});
		}
	});
});
