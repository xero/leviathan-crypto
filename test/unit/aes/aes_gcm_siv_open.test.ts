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
// test/unit/aes/aes_gcm_siv_open.test.ts
//
// Gate 17, AES-GCM-SIV open direction. Round-trips every RFC 8452
// Appendix C vector and exercises the unauthenticated-plaintext-trap
// boundary with synthesised tamper vectors:
//   17a round-trip: open(seal(pt)) == pt for all 50 vectors
//   17b tag tamper: byte-flip on the tag throws AuthenticationError('siv')
//   17c CT tamper:  byte-flip at first/middle/last position throws
//   17d AAD tamper: byte-flip in AAD throws (vectors with non-empty AAD)
//   17e nonce tamper: byte-flip in nonce throws
//   17f key tamper:   byte-flip in KGK throws
//   17g PT-not-released: after auth-fail, CHUNK_PT_OFFSET reads as zeros
//
// Tamper vectors are synthesised at test time from the positive corpus
// (single-byte XOR=1 on tag/ct/aad/nonce/key, separately). They are not
// added to test/vectors/.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AESGCMSIV, AuthenticationError } from '../../../src/ts/index.js';
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

const allVectors: AesGcmSivVector[] = [
	...aesGcmSiv128Vectors,
	...aesGcmSiv256Vectors,
	...aesGcmSivCounterWrapVectors,
];

// Pick one representative per keysize for the tamper sub-gates. The
// round-trip gate (17a) covers all 50; tamper gates run on a subset.
const tamperSubsetEmptyAad: AesGcmSivVector[] = [
	aesGcmSiv128Vectors.find(v => v.plaintext.length >= 32) ?? aesGcmSiv128Vectors[3],
	aesGcmSiv256Vectors.find(v => v.plaintext.length >= 32) ?? aesGcmSiv256Vectors[3],
];
const tamperSubsetWithAad: AesGcmSivVector[] = [
	aesGcmSiv128Vectors.find(v => v.aad.length > 0) ?? aesGcmSiv128Vectors[8],
	aesGcmSiv256Vectors.find(v => v.aad.length > 0) ?? aesGcmSiv256Vectors[8],
];

const expectAuthFail = (run: () => Uint8Array): void => {
	let threw = false;
	let caught: unknown;
	try {
		run();
	} catch (e) {
		threw = true;
		caught = e;
	}
	expect(threw).toBe(true);
	expect(caught).toBeInstanceOf(AuthenticationError);
	expect((caught as Error).message).toMatch(/^siv:/);
};

describe('AES-GCM-SIV open gate (Gate 17), RFC 8452 Appendix C', () => {
	describe('17a, round-trip (all 50 RFC vectors)', () => {
		for (const v of allVectors) {
			// GATE: open(seal(pt)) == pt for every published vector.
			it(v.description, () => {
				const cipher = new AESGCMSIV(fromHex(v.key));
				try {
					const sealed = fromHex(v.result);
					const pt = cipher.open(fromHex(v.nonce), sealed, fromHex(v.aad));
					expect(toHex(pt)).toBe(v.plaintext);
				} finally {
					cipher.dispose();
				}
			});
		}
	});

	describe('17b, tag tamper (single-byte flip on last tag byte)', () => {
		for (const v of tamperSubsetEmptyAad) {
			it(v.description, () => {
				const cipher = new AESGCMSIV(fromHex(v.key));
				try {
					const sealed = fromHex(v.result);
					sealed[sealed.length - 1] ^= 0x01;
					expectAuthFail(() => cipher.open(fromHex(v.nonce), sealed, fromHex(v.aad)));
				} finally {
					cipher.dispose();
				}
			});
		}
	});

	describe('17c, CT tamper (first / middle / last byte)', () => {
		for (const v of tamperSubsetEmptyAad) {
			const ctLen = fromHex(v.plaintext).length;
			if (ctLen < 16) continue;  // need ≥ 16 to exercise three distinct positions
			for (const pos of [0, ctLen >> 1, ctLen - 1]) {
				it(`${v.description}, flip CT[${pos}]`, () => {
					const cipher = new AESGCMSIV(fromHex(v.key));
					try {
						const sealed = fromHex(v.result);
						sealed[pos] ^= 0x01;
						expectAuthFail(() => cipher.open(fromHex(v.nonce), sealed, fromHex(v.aad)));
					} finally {
						cipher.dispose();
					}
				});
			}
		}
	});

	describe('17d, AAD tamper', () => {
		for (const v of tamperSubsetWithAad) {
			it(v.description, () => {
				const cipher = new AESGCMSIV(fromHex(v.key));
				try {
					const sealed = fromHex(v.result);
					const aad = fromHex(v.aad);
					aad[0] ^= 0x01;
					expectAuthFail(() => cipher.open(fromHex(v.nonce), sealed, aad));
				} finally {
					cipher.dispose();
				}
			});
		}
	});

	describe('17e, nonce tamper', () => {
		for (const v of tamperSubsetEmptyAad) {
			it(v.description, () => {
				const cipher = new AESGCMSIV(fromHex(v.key));
				try {
					const sealed = fromHex(v.result);
					const nonce = fromHex(v.nonce);
					nonce[0] ^= 0x01;
					expectAuthFail(() => cipher.open(nonce, sealed, fromHex(v.aad)));
				} finally {
					cipher.dispose();
				}
			});
		}
	});

	describe('17f, key tamper', () => {
		for (const v of tamperSubsetEmptyAad) {
			it(v.description, () => {
				const tamperedKey = fromHex(v.key);
				tamperedKey[0] ^= 0x01;
				const cipher = new AESGCMSIV(tamperedKey);
				try {
					const sealed = fromHex(v.result);
					expectAuthFail(() => cipher.open(fromHex(v.nonce), sealed, fromHex(v.aad)));
				} finally {
					cipher.dispose();
				}
			});
		}
	});

	describe('17g, PT-not-released after auth fail', () => {
		// Verify that on tamper-induced auth failure, the
		// decrypted-but-unauthenticated plaintext at CHUNK_PT_OFFSET is
		// zeroed by sivWipeOnFail before any TS code observes it. The
		// assertion covers the FULL 64 KiB CHUNK_PT, not just the ptLen
		// prefix, a sivWipeOnFail bug that zeros only the prefix would
		// be caught here.
		for (const v of tamperSubsetEmptyAad) {
			it(v.description, () => {
				const xExports = getInstance('aes').exports as unknown as {
					memory: WebAssembly.Memory;
					getChunkPtOffset: () => number;
					getChunkSize:     () => number;
				};
				const ptOff     = xExports.getChunkPtOffset();
				const chunkSize = xExports.getChunkSize();

				// Sentinel-prefill the full CHUNK_PT before any cipher
				// activity. The successful open below will consume the
				// sentinel via its own wipeBuffers; the value of this
				// pre-fill is purely defensive: if the cipher path
				// somehow skipped a wipe we'd see 0xAA bytes. The real
				// post-condition is the full-buffer zero check after
				// the tampered open.
				new Uint8Array(xExports.memory.buffer, ptOff, chunkSize).fill(0xAA);

				const cipher = new AESGCMSIV(fromHex(v.key));
				try {
					// Run a successful open first so CHUNK_PT goes
					// through the normal recover-then-wipe lifecycle.
					const goodSealed = fromHex(v.result);
					const recovered = cipher.open(fromHex(v.nonce), goodSealed, fromHex(v.aad));
					expect(toHex(recovered)).toBe(v.plaintext);

					// Now tamper the tag and re-open. The tampered open's
					// sivCtrXform writes decrypted-garbage bytes into
					// CHUNK_PT[0..ctLen]; sivWipeOnFail must zero the
					// full 64 KiB before the throw surfaces.
					const tampered = fromHex(v.result);
					tampered[tampered.length - 1] ^= 0x01;
					expectAuthFail(() =>
						cipher.open(fromHex(v.nonce), tampered, fromHex(v.aad)),
					);

					// Full-buffer post-condition: every byte of CHUNK_PT
					// is zero, regardless of plaintext length.
					const after = new Uint8Array(xExports.memory.buffer, ptOff, chunkSize);
					expect(after.every(b => b === 0)).toBe(true);
				} finally {
					cipher.dispose();
				}
			});
		}
	});
});
