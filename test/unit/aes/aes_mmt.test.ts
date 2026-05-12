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
// test/unit/aes/aes_mmt.test.ts
//
// Gate 6, AESVS Multi-block Message Test for ECB. Three files
// (aes_ECBMMT{128,192,256}.rsp), 20 vectors per direction per file. Each
// vector is a multi-block PT/CT (1..10 blocks of 16 bytes); for ECB this
// is just a sequence of independent block-encrypts under the same key.
//
// Reference: AESAVS §6.3 (Multi-block Message Test).

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AES } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { parseEcbMmtFile } from './vector_parser';
import { fromHex, toHex } from '../helpers';

beforeAll(async () => {
	await init({ aes: aesWasm });
});

for (const file of [
	'aes_ECBMMT128.rsp',
	'aes_ECBMMT192.rsp',
	'aes_ECBMMT256.rsp',
]) {
	describe(`AES MMT (Gate 6), CAVP ${file}`, () => {
		const { encrypt, decrypt } = parseEcbMmtFile(file);

		it('parses non-zero vectors in both directions', () => {
			expect(encrypt.length).toBeGreaterThan(0);
			expect(decrypt.length).toBeGreaterThan(0);
		});

		it(`all ${encrypt.length} encrypt vectors pass`, () => {
			const aes = new AES();
			try {
				for (const v of encrypt) {
					aes.loadKey(fromHex(v.key));
					const pt = fromHex(v.pt);
					expect(pt.length % 16).toBe(0);
					const ct = new Uint8Array(pt.length);
					for (let off = 0; off < pt.length; off += 16) {
						ct.set(aes.encryptBlock(pt.subarray(off, off + 16)), off);
					}
					expect(toHex(ct), `COUNT=${v.count} key=${v.key} ptLen=${pt.length}`).toBe(v.ct);
				}
			} finally {
				aes.dispose();
			}
		});

		it(`all ${decrypt.length} decrypt vectors pass`, () => {
			const aes = new AES();
			try {
				for (const v of decrypt) {
					aes.loadKey(fromHex(v.key));
					const ct = fromHex(v.ct);
					expect(ct.length % 16).toBe(0);
					const pt = new Uint8Array(ct.length);
					for (let off = 0; off < ct.length; off += 16) {
						pt.set(aes.decryptBlock(ct.subarray(off, off + 16)), off);
					}
					expect(toHex(pt), `COUNT=${v.count} key=${v.key} ctLen=${ct.length}`).toBe(v.pt);
				}
			} finally {
				aes.dispose();
			}
		});
	});
}
