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
// test/unit/aes/aes_ctr.test.ts
//
// Gate 11 — AES CTR mode against the SP 800-38A §F.5 worked examples
// (six vectors covering AES-128/192/256 × encrypt/decrypt). NIST CAVP
// retired the AES-CTR validation suite in 2009; the §F.5 examples are
// the authoritative source for AES-CTR test vectors.
//
// Plus a SIMD-vs-scalar consistency check across batch boundaries
// (1, 8, 9, 128, 129 blocks) and a round-trip check.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, AESCtr } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { getInstance } from '../../../src/ts/init.js';
import { aesCtrEncryptVectors, aesCtrDecryptVectors } from '../../vectors/aes_ctr';
import { fromHex, toHex } from '../helpers';

interface AesCtrExports {
	memory:            WebAssembly.Memory
	getKeyOffset:      () => number
	getNonceOffset:    () => number
	getChunkPtOffset:  () => number
	getChunkCtOffset:  () => number
	loadKey:           (n: number) => number
	resetCounter:      () => void
	encryptChunk:      (n: number) => number
	encryptChunk_simd: (n: number) => number
}

function getExports(): AesCtrExports {
	return getInstance('aes').exports as unknown as AesCtrExports;
}

beforeAll(async () => {
	await init({ aes: aesWasm });
});

// ── Constructor gate ────────────────────────────────────────────────────────

describe('AESCtr — dangerUnauthenticated gate', () => {
	it('new AESCtr() throws without dangerUnauthenticated flag', () => {
		expect(() => new AESCtr()).toThrow(
			'leviathan-crypto: AESCtr is unauthenticated — use Seal with AESGCMSIVCipher, SerpentCipher, or XChaCha20Cipher instead.',
		);
	});

	it('new AESCtr({ dangerUnauthenticated: true }) constructs successfully', () => {
		const c = new AESCtr({ dangerUnauthenticated: true });
		expect(c).toBeDefined();
		c.dispose();
	});
});

// GATE: SP 800-38A §F.5 CTR worked examples — encrypt direction.
describe('AES CTR (Gate 11) — SP 800-38A §F.5 encrypt', () => {
	for (const v of aesCtrEncryptVectors) {
		it(v.description, () => {
			const aes = new AESCtr({ dangerUnauthenticated: true });
			try {
				aes.loadKey(fromHex(v.key));
				aes.setNonce(fromHex(v.initialCounter));
				expect(toHex(aes.encrypt(fromHex(v.pt)))).toBe(v.ct);
			} finally {
				aes.dispose();
			}
		});
	}
});

describe('AES CTR (Gate 11) — SP 800-38A §F.5 decrypt', () => {
	for (const v of aesCtrDecryptVectors) {
		it(v.description, () => {
			const aes = new AESCtr({ dangerUnauthenticated: true });
			try {
				aes.loadKey(fromHex(v.key));
				aes.setNonce(fromHex(v.initialCounter));
				expect(toHex(aes.decrypt(fromHex(v.ct)))).toBe(v.pt);
			} finally {
				aes.dispose();
			}
		});
	}
});

describe('AES CTR (Gate 11) — round-trip', () => {
	it('encrypt then decrypt recovers the plaintext (AES-256, 4 blocks)', () => {
		const v = aesCtrEncryptVectors[2];   // AES-256
		const key = fromHex(v.key);
		const ic  = fromHex(v.initialCounter);
		const pt  = fromHex(v.pt);

		const enc = new AESCtr({ dangerUnauthenticated: true });
		let ct: Uint8Array;
		try {
			enc.loadKey(key); enc.setNonce(ic);
			ct = enc.encrypt(pt);
		} finally {
			enc.dispose();
		}

		const dec = new AESCtr({ dangerUnauthenticated: true });
		try {
			dec.loadKey(key); dec.setNonce(ic);
			expect(toHex(dec.decrypt(ct))).toBe(toHex(pt));
		} finally {
			dec.dispose();
		}
	});
});

// Scalar / SIMD consistency: drive the WASM directly to bypass the wrapper.
// AESCtr.encrypt always uses the SIMD path; we compare against scalar
// `encryptChunk` to verify the bitsliced 8-block kernel matches.
describe('AES CTR (Gate 11) — SIMD vs scalar consistency', () => {
	const key = fromHex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
	const ic  = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');

	for (const nblocks of [1, 7, 8, 9, 16, 17, 128, 129]) {
		it(`scalar == SIMD on ${nblocks}-block input (${nblocks * 16} bytes)`, () => {
			const x = getExports();
			const mem = new Uint8Array(x.memory.buffer);
			const len = nblocks * 16;
			const pt = new Uint8Array(len);
			for (let i = 0; i < len; i++) pt[i] = (i * 13 + 7) & 0xff;

			mem.set(key, x.getKeyOffset());
			x.loadKey(key.length);

			// scalar
			mem.set(ic, x.getNonceOffset()); x.resetCounter();
			mem.set(pt, x.getChunkPtOffset());
			x.encryptChunk(len);
			const scalarCt = mem.slice(x.getChunkCtOffset(), x.getChunkCtOffset() + len);

			// simd
			mem.set(ic, x.getNonceOffset()); x.resetCounter();
			mem.set(pt, x.getChunkPtOffset());
			x.encryptChunk_simd(len);
			const simdCt = mem.slice(x.getChunkCtOffset(), x.getChunkCtOffset() + len);

			expect(toHex(simdCt)).toBe(toHex(scalarCt));
		});
	}
});

describe('AES CTR (Gate 11) — partial-block tail', () => {
	it('non-multiple-of-16 length: the last partial block uses the keystream MSB', () => {
		// 17-byte plaintext under AES-128 §F.5.1 setup; only the first byte of
		// counter block 2's keystream is consumed.
		const v = aesCtrEncryptVectors[0];   // AES-128
		const aes = new AESCtr({ dangerUnauthenticated: true });
		try {
			aes.loadKey(fromHex(v.key));
			aes.setNonce(fromHex(v.initialCounter));
			const pt = fromHex(v.pt).subarray(0, 17);
			const expected = fromHex(v.ct).subarray(0, 17);
			expect(toHex(aes.encrypt(pt))).toBe(toHex(expected));
		} finally {
			aes.dispose();
		}
	});
});
