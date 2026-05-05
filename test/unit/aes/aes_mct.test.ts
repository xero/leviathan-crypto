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
//                           ▀█████▀▀▀
//
// test/unit/aes/aes_mct.test.ts
//
// Gate 7 — AESVS Monte Carlo Test for ECB. Three files
// (aes_ECBMCT{128,192,256}.rsp), 100 chains × 1000 inner iterations per
// direction. The chaining rule is key-size-dependent — see AESAVS §6.4.1
// (the encryption pseudocode and the three `If keylen = …` branches).
//
// Reference: AESAVS §6.4.1 (Monte Carlo Test - ECB), pp. 7–8 of the
// `research-docs/specs/AESAVS.pdf` document. Read before modifying.
//
// Per-iteration mechanics: the inner j-loop produces ct[0..999] (encrypt)
// or pt[0..999] (decrypt) by chaining each output back as the next input.
// The next-key derivation (`deriveNextKey`) uses the penultimate (j=998)
// and final (j=999) outputs — captured in `penult` and `final` mid-loop —
// per the AESAVS §6.4.1 byte slicing.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AES } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { parseEcbMctFile } from './vector_parser';
import { fromHex, toHex } from '../helpers';

beforeAll(async () => {
	await init({ aes: aesWasm });
});

/**
 * AESAVS §6.4.1 next-key derivation.
 *
 * Returns `Key[i+1] = Key[i] XOR mask`, where `mask` is built from the
 * penultimate and final cipher outputs of the iteration's inner 1000-step
 * loop:
 *   - 16-byte key: mask = final
 *   - 24-byte key: mask = (last 8 bytes of penult) || final  (per the
 *     AESAVS pseudocode "last 64-bits of CT[j-1] || CT[j]")
 *   - 32-byte key: mask = penult || final
 *
 * For decrypt direction, substitute pt[998]/pt[999] for ct[998]/ct[999]
 * (the rule structure is identical; the byte source flips per the AESAVS
 * §6.4 paragraph "the pseudocode for decryption can be obtained by
 * replacing all PT's with CT's and all CT's with PT's").
 */
function deriveNextKey(prev: Uint8Array, penult: Uint8Array, final: Uint8Array): Uint8Array {
	const out = new Uint8Array(prev.length);
	if (prev.length === 16) {
		for (let i = 0; i < 16; i++) out[i] = prev[i] ^ final[i];
	} else if (prev.length === 24) {
		for (let i = 0; i < 8;  i++) out[i] = prev[i] ^ penult[8 + i];
		for (let i = 0; i < 16; i++) out[8 + i] = prev[8 + i] ^ final[i];
	} else /* 32 */ {
		for (let i = 0; i < 16; i++) out[i] = prev[i] ^ penult[i];
		for (let i = 0; i < 16; i++) out[16 + i] = prev[16 + i] ^ final[i];
	}
	return out;
}

const INNER_LOOP = 1000;

for (const file of [
	'aes_ECBMCT128.rsp',
	'aes_ECBMCT192.rsp',
	'aes_ECBMCT256.rsp',
]) {
	describe(`AES MCT (Gate 7) — CAVP ${file}`, () => {
		const { encrypt, decrypt } = parseEcbMctFile(file);

		it('parses 100 chains per direction', () => {
			expect(encrypt.length).toBe(100);
			expect(decrypt.length).toBe(100);
		});

		it('100 encrypt chains × 1000 iterations — AESAVS §6.4.1 chain rule', () => {
			const aes = new AES();
			try {
				let key = fromHex(encrypt[0].key);
				let pt  = fromHex(encrypt[0].pt);
				const penult = new Uint8Array(16);

				for (let i = 0; i < 100; i++) {
					expect(toHex(key), `COUNT=${i} KEY mismatch (chain rule)`).toBe(encrypt[i].key);
					expect(toHex(pt),  `COUNT=${i} PT mismatch (chain rule)`).toBe(encrypt[i].pt);

					aes.loadKey(key);
					let cur = pt;
					for (let j = 0; j < INNER_LOOP; j++) {
						const next = aes.encryptBlock(cur);
						if (j === INNER_LOOP - 2) penult.set(next);
						cur = next;
					}
					const final = cur;  // ct[999]

					expect(toHex(final), `COUNT=${i} CT mismatch`).toBe(encrypt[i].ct);

					// AESAVS §6.4.1: Key[i+1] = Key[i] XOR mask; PT[0] = ct[999].
					key = deriveNextKey(key, penult, final);
					pt  = new Uint8Array(final);
				}
			} finally {
				aes.dispose();
			}
		});

		it('100 decrypt chains × 1000 iterations — AESAVS §6.4.1 chain rule', () => {
			const aes = new AES();
			try {
				let key = fromHex(decrypt[0].key);
				let ct  = fromHex(decrypt[0].ct);
				const penult = new Uint8Array(16);

				for (let i = 0; i < 100; i++) {
					expect(toHex(key), `COUNT=${i} KEY mismatch (chain rule)`).toBe(decrypt[i].key);
					expect(toHex(ct),  `COUNT=${i} CT mismatch (chain rule)`).toBe(decrypt[i].ct);

					aes.loadKey(key);
					let cur = ct;
					for (let j = 0; j < INNER_LOOP; j++) {
						const next = aes.decryptBlock(cur);
						if (j === INNER_LOOP - 2) penult.set(next);
						cur = next;
					}
					const final = cur;  // pt[999]

					expect(toHex(final), `COUNT=${i} PT mismatch`).toBe(decrypt[i].pt);

					// Decrypt direction: same rule, substitute pt[998]/pt[999]
					// for ct[998]/ct[999]. AESAVS §6.4 paragraph above §6.4.1.
					key = deriveNextKey(key, penult, final);
					ct  = new Uint8Array(final);
				}
			} finally {
				aes.dispose();
			}
		});
	});
}
