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
// test/unit/aes/aes_kat.test.ts
//
// Gate 4 — full AES encrypt KAT for all three key sizes. Combines FIPS 197
// §B (AES-128 example) with the twelve NIST CAVP AESVS ECB Known-Answer-Test
// files (4 file types × 3 key sizes).

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AES } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { aes128CipherVectors } from '../../vectors/aes';
import { parseEcbKatFile } from './vector_parser';
import { fromHex, toHex } from '../helpers';

beforeAll(async () => {
	await init({ aes: aesWasm });
});

describe('AES-128 KAT (Gate 4) — FIPS 197 §B', () => {
	// GATE: full 10-round AES-128 encrypt of the §B example.
	it('FIPS 197 §B AES-128 cipher example', () => {
		const aes = new AES();
		try {
			const v = aes128CipherVectors[0];
			aes.loadKey(fromHex(v.key));
			expect(toHex(aes.encryptBlock(fromHex(v.pt)))).toBe(v.ct);
		} finally {
			aes.dispose();
		}
	});
});

for (const file of [
	'aes_ECBGFSbox128.rsp', 'aes_ECBKeySbox128.rsp',
	'aes_ECBVarKey128.rsp', 'aes_ECBVarTxt128.rsp',
	'aes_ECBGFSbox192.rsp', 'aes_ECBKeySbox192.rsp',
	'aes_ECBVarKey192.rsp', 'aes_ECBVarTxt192.rsp',
	'aes_ECBGFSbox256.rsp', 'aes_ECBKeySbox256.rsp',
	'aes_ECBVarKey256.rsp', 'aes_ECBVarTxt256.rsp',
]) {
	describe(`AES KAT (Gate 4) — CAVP ${file}`, () => {
		const { encrypt } = parseEcbKatFile(file);

		it('parses non-zero vectors', () => {
			expect(encrypt.length).toBeGreaterThan(0);
		});

		it(`all ${encrypt.length} encrypt vectors pass`, () => {
			const aes = new AES();
			try {
				for (const v of encrypt) {
					aes.loadKey(fromHex(v.key));
					expect(
						toHex(aes.encryptBlock(fromHex(v.pt))),
						`COUNT=${v.count} key=${v.key} pt=${v.pt}`,
					).toBe(v.ct);
				}
			} finally {
				aes.dispose();
			}
		});
	});
}
