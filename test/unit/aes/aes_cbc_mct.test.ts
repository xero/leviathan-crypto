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
// test/unit/aes/aes_cbc_mct.test.ts
//
// Gate 10 — AES CBC Monte Carlo Test against the three NIST CAVP AESVS
// MCT files (one per key size). 100 chains × 1000 inner iterations per
// direction.
//
// Reference: AESAVS §6.4.2 (Monte Carlo Test - CBC), pp. 8–9 of
// `research-docs/specs/AESAVS.pdf`. The chain rule is non-obvious — in
// particular, the next chain's plaintext (encrypt) or ciphertext
// (decrypt) is the **penultimate** output, not the final and not zero.
// Read the spec before modifying.
//
// Encrypt inner loop (AESAVS §6.4.2):
//   for j = 0..999:
//     if j == 0:  CT[j] = E(K, IV ⊕ PT[j]);     PT[j+1] = IV
//     else:        CT[j] = E(K, CT[j-1] ⊕ PT[j]); PT[j+1] = CT[j-1]
//
// Decrypt inner loop (AESAVS §6.4.2 final paragraph: "the pseudocode for
// decryption can be obtained by replacing all PT's with CT's and all
// CT's with PT's"). The CBC chaining state still advances to the
// previous ciphertext input — that's what AES_inv uses for the implicit
// CBC chaining inside the spec text.
//
// Outer loop:
//   KEY[i+1] = KEY[i] ⊕ mask  (same byte-slicing as ECB MCT)
//   IV[i+1]  = final output (CT[999] encrypt, PT[999] decrypt)
//   chain seed for next i = penult output (CT[998] / PT[998])

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import { getInstance } from '../../../src/ts/init.js';
import { parseCbcMctFile } from './vector_parser';
import { fromHex, toHex } from '../helpers';

interface AesCbcMctExports {
	memory:           WebAssembly.Memory
	getKeyOffset:     () => number
	getBlockPtOffset: () => number
	getBlockCtOffset: () => number
	loadKey:          (n: number) => number
	encryptBlock:     () => void
	decryptBlock:     () => void
}

function getExports(): AesCbcMctExports {
	return getInstance('aes').exports as unknown as AesCbcMctExports;
}

beforeAll(async () => {
	await init({ aes: aesWasm });
});

/**
 * AESVS §6.4.1/§6.4.2 next-key derivation. Identical to ECB MCT — for CBC
 * the substituted byte source is the cipher *output* (CT for encrypt, PT
 * for decrypt) at indices j-1 (penult) and j (final).
 *
 *   16-byte key: mask = final
 *   24-byte key: mask = (low 8 bytes of penult) || final
 *   32-byte key: mask = penult || final
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

const xor16 = (a: Uint8Array, b: Uint8Array): Uint8Array => {
	const out = new Uint8Array(16);
	for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
	return out;
};

/** Raw single-block encrypt — caller has already loaded the key. */
function blockEncrypt(x: AesCbcMctExports, mem: Uint8Array, b: Uint8Array): Uint8Array {
	mem.set(b, x.getBlockPtOffset());
	x.encryptBlock();
	return mem.slice(x.getBlockCtOffset(), x.getBlockCtOffset() + 16);
}

/** Raw single-block decrypt — caller has already loaded the key.
 *  Note: aes.ts decryptBlock reads ciphertext from BLOCK_PT and writes
 *  plaintext to BLOCK_CT (the buffer-naming is encrypt-direction, see
 *  the comment in aes.ts decryptBlock). */
function blockDecrypt(x: AesCbcMctExports, mem: Uint8Array, b: Uint8Array): Uint8Array {
	mem.set(b, x.getBlockPtOffset());
	x.decryptBlock();
	return mem.slice(x.getBlockCtOffset(), x.getBlockCtOffset() + 16);
}

const INNER_LOOP = 1000;

for (const file of [
	'aes_CBCMCT128.rsp',
	'aes_CBCMCT192.rsp',
	'aes_CBCMCT256.rsp',
]) {
	describe(`AES CBC MCT (Gate 10) — CAVP ${file}`, () => {
		const { encrypt, decrypt } = parseCbcMctFile(file);

		it('parses 100 chains per direction', () => {
			expect(encrypt.length).toBe(100);
			expect(decrypt.length).toBe(100);
		});

		// Encrypt MCT — AESAVS §6.4.2 chain rule.
		it('100 encrypt chains × 1000 iterations — AESVS §6.4.2', () => {
			const x = getExports();
			const mem = new Uint8Array(x.memory.buffer);

			let key = fromHex(encrypt[0].key);
			let iv  = fromHex(encrypt[0].iv);
			let pt  = fromHex(encrypt[0].pt);
			const penult = new Uint8Array(16);

			for (let i = 0; i < 100; i++) {
				expect(toHex(key), `COUNT=${i} KEY mismatch`).toBe(encrypt[i].key);
				expect(toHex(iv),  `COUNT=${i} IV mismatch`).toBe(encrypt[i].iv);
				expect(toHex(pt),  `COUNT=${i} PT mismatch`).toBe(encrypt[i].pt);

				mem.set(key, x.getKeyOffset());
				x.loadKey(key.length);

				// Inner loop — AESAVS §6.4.2 encrypt:
				//   prev_iv = IV
				//   cur_pt  = PT
				//   prev_ct (saved across iterations to support PT[j+1] = CT[j-1])
				let prevIv: Uint8Array = iv;
				let curPt: Uint8Array = pt;
				let prevCt: Uint8Array = new Uint8Array(16);  // unused at j=0
				let lastCt: Uint8Array = new Uint8Array(16);

				for (let j = 0; j < INNER_LOOP; j++) {
					// CT[j] = E(K, PT[j] XOR prev_iv)
					const ctOut = blockEncrypt(x, mem, xor16(curPt, prevIv));

					if (j === INNER_LOOP - 2) penult.set(ctOut);
					if (j === INNER_LOOP - 1) lastCt = ctOut;

					// Set up next iteration:
					//   PT[j+1] = (j == 0) ? IV : CT[j-1]
					//   prev_iv ← CT[j] (CBC encrypt chain advance)
					const nextPt = j === 0 ? iv : prevCt;
					prevCt  = ctOut;
					prevIv  = ctOut;
					curPt   = nextPt;
				}

				expect(toHex(lastCt), `COUNT=${i} CT mismatch`).toBe(encrypt[i].ct);

				// Outer chain advance.
				key = deriveNextKey(key, penult, lastCt);
				iv  = new Uint8Array(lastCt);   // CT[999]
				pt  = new Uint8Array(penult);   // CT[998]
			}
		}, 600_000);

		// Decrypt MCT — same shape, with PT/CT swapped per AESAVS §6.4.2.
		it('100 decrypt chains × 1000 iterations — AESVS §6.4.2', () => {
			const x = getExports();
			const mem = new Uint8Array(x.memory.buffer);

			let key = fromHex(decrypt[0].key);
			let iv  = fromHex(decrypt[0].iv);
			let ct  = fromHex(decrypt[0].ct);
			const penult = new Uint8Array(16);

			for (let i = 0; i < 100; i++) {
				expect(toHex(key), `COUNT=${i} KEY mismatch`).toBe(decrypt[i].key);
				expect(toHex(iv),  `COUNT=${i} IV mismatch`).toBe(decrypt[i].iv);
				expect(toHex(ct),  `COUNT=${i} CT mismatch`).toBe(decrypt[i].ct);

				mem.set(key, x.getKeyOffset());
				x.loadKey(key.length);

				// Inner loop — AESAVS §6.4.2 decrypt (PT↔CT swap):
				//   prev_iv = IV (chain state — previous ciphertext input)
				//   cur_ct  = CT[0] (current ciphertext input; mutates per spec)
				//   prev_pt (PT[j-1] is fed back as CT[j+1] for j ≥ 1)
				let prevIv: Uint8Array = iv;
				let curCt: Uint8Array = ct;
				let prevPt: Uint8Array = new Uint8Array(16);  // unused at j=0
				let lastPt: Uint8Array = new Uint8Array(16);

				for (let j = 0; j < INNER_LOOP; j++) {
					// PT[j] = D(K, CT[j]) XOR prev_iv
					const ptOut = xor16(blockDecrypt(x, mem, curCt), prevIv);

					if (j === INNER_LOOP - 2) penult.set(ptOut);
					if (j === INNER_LOOP - 1) lastPt = ptOut;

					// Set up next iteration:
					//   CT[j+1] = (j == 0) ? IV : PT[j-1]
					//   prev_iv ← CT[j]   (CBC decrypt chain advance: previous ct input)
					const nextCt = j === 0 ? iv : prevPt;
					prevIv  = curCt;
					prevPt  = ptOut;
					curCt   = nextCt;
				}

				expect(toHex(lastPt), `COUNT=${i} PT mismatch`).toBe(decrypt[i].pt);

				// Outer chain advance (PT/CT swapped — outputs are PT here).
				key = deriveNextKey(key, penult, lastPt);
				iv  = new Uint8Array(lastPt);   // PT[999]
				ct  = new Uint8Array(penult);   // PT[998]
			}
		}, 600_000);
	});
}
