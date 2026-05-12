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
// test/unit/aes/aes_gcm_open.test.ts
//
// Gate 14, AESGCM open direction. NIST CAVP GCMVS decrypt files contain
// both passing vectors (PT field present) and FAIL vectors (no PT, marked
// FAIL, tag/CT/AAD/IV/key tampered) for each (Keylen, IVlen, PTlen,
// AADlen, Taglen) section. We exercise both:
//
//   - Passing vectors decrypt correctly to the published PT.
//   - FAIL vectors must throw `RangeError('authentication failed')` on
//     every single one. None may return plaintext.
//
// We test only 128-bit-tag vectors per phase 4a's spec-faithful API.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AESGCM } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { parseGcmvsDecrypt } from './vector_parser';
import { fromHex as fromHexRaw, toHex } from '../helpers';

const fromHex = (s: string): Uint8Array => s.length === 0 ? new Uint8Array(0) : fromHexRaw(s);

beforeAll(async () => {
	await init({ aes: aesWasm });
});

for (const file of [
	'aes_gcmDecrypt128.rsp',
	'aes_gcmDecrypt192.rsp',
	'aes_gcmDecrypt256.rsp',
]) {
	const allVectors = parseGcmvsDecrypt(file).filter(v => v.taglen === 128);
	const passing = allVectors.filter(v => !v.fail);
	const failing = allVectors.filter(v =>  v.fail);

	describe(`AESGCM open (Gate 14), GCMVS ${file}`, () => {
		// GATE: passing vectors decrypt to the published PT.
		it(`${passing.length} 128-bit-tag passing vectors decrypt correctly`, () => {
			const aes = new AESGCM();
			try {
				for (const v of passing) {
					const sealed = new Uint8Array(fromHex(v.ct).length + 16);
					sealed.set(fromHex(v.ct), 0);
					sealed.set(fromHex(v.tag), fromHex(v.ct).length);
					const pt = aes.open(
						fromHex(v.key),
						fromHex(v.iv),
						fromHex(v.aad),
						sealed,
					);
					expect(
						toHex(pt),
						`${file} COUNT=${v.count} keylen=${v.keylen} ivlen=${v.ivlen} ptlen=${v.ptlen} aadlen=${v.aadlen}`,
					).toBe(v.pt!);
				}
			} finally {
				aes.dispose();
			}
		});

		// GATE: FAIL vectors all throw, none silently produce plaintext.
		// This is the most security-critical gate in the entire phase. A
		// single FAIL vector that returns plaintext means GCM authentication
		// is broken.
		it(`${failing.length} 128-bit-tag FAIL vectors throw`, () => {
			const aes = new AESGCM();
			try {
				for (const v of failing) {
					const sealed = new Uint8Array(fromHex(v.ct).length + 16);
					sealed.set(fromHex(v.ct), 0);
					sealed.set(fromHex(v.tag), fromHex(v.ct).length);
					expect(
						() => aes.open(
							fromHex(v.key),
							fromHex(v.iv),
							fromHex(v.aad),
							sealed,
						),
						`${file} COUNT=${v.count} keylen=${v.keylen} ivlen=${v.ivlen} ptlen=${v.ptlen} aadlen=${v.aadlen} should fail`,
					).toThrow();
				}
			} finally {
				aes.dispose();
			}
		});
	});
}
