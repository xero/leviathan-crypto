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
// test/unit/aes/aes_gcm_seal.test.ts
//
// Gate 13 — AESGCM seal direction. Two corpora:
//   (a) McGrew-Viega Appendix B — 18 worked test cases including
//       intermediate values; covers 96-bit IV fast path and variable-length
//       IV slow path across AES-128 / 192 / 256.
//   (b) NIST CAVP GCMVS encrypt files (~23k vectors total). The taglen
//       parameter varies (32, 64, 96, 104, 112, 120, 128); we only test
//       128-bit-tag vectors per phase 4a's spec-faithful API surface.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AESGCM } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { aesGcmVectors } from '../../vectors/aes_gcm';
import { parseGcmvsEncrypt } from './vector_parser';
import { fromHex as fromHexRaw, toHex } from '../helpers';

const fromHex = (s: string): Uint8Array => s.length === 0 ? new Uint8Array(0) : fromHexRaw(s);

beforeAll(async () => {
	await init({ aes: aesWasm });
});

describe('AESGCM seal (Gate 13) — McGrew-Viega Appendix B', () => {
	for (const v of aesGcmVectors) {
		// GATE: full AES-GCM encrypt for each MV worked example.
		it(v.description, () => {
			const aes = new AESGCM();
			try {
				const sealed = aes.seal(
					fromHex(v.key),
					fromHex(v.iv),
					fromHex(v.aad),
					fromHex(v.pt),
				);
				expect(toHex(sealed)).toBe(v.ct + v.tag);
			} finally {
				aes.dispose();
			}
		});
	}
});

for (const file of [
	'aes_gcmEncryptExtIV128.rsp',
	'aes_gcmEncryptExtIV192.rsp',
	'aes_gcmEncryptExtIV256.rsp',
]) {
	describe(`AESGCM seal (Gate 13) — GCMVS ${file}`, () => {
		const vectors = parseGcmvsEncrypt(file).filter(v => v.taglen === 128);

		// One outer 'it' per file so vitest reports one row; per-vector
		// failures still show a meaningful sub-message via the `expect.toBe`
		// failure message.
		it(`${vectors.length} 128-bit-tag encrypt vectors`, () => {
			const aes = new AESGCM();
			try {
				for (const v of vectors) {
					const sealed = aes.seal(
						fromHex(v.key),
						fromHex(v.iv),
						fromHex(v.aad),
						fromHex(v.pt),
					);
					expect(
						toHex(sealed),
						`${file} COUNT=${v.count} keylen=${v.keylen} ivlen=${v.ivlen} ptlen=${v.ptlen} aadlen=${v.aadlen}`,
					).toBe(v.ct + v.tag);
				}
			} finally {
				aes.dispose();
			}
		});
	});
}
