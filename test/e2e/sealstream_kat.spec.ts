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
import { test, expect } from '@playwright/test';
import { xc1, xc3, sc1, sc3, xcf1, scf1 } from '../vectors/sealstream_v2.js';
import type { SealStreamV2Vector } from '../vectors/sealstream_v2.js';

const BASE = 'http://localhost:1337';

const xchachaVectors: SealStreamV2Vector[] = [xc1, xc3, xcf1];
const serpentVectors: SealStreamV2Vector[] = [sc1, sc3, scf1];

test.beforeEach(async ({ page }) => {
	await page.goto(BASE);
});

async function runBatch(
	page: import('@playwright/test').Page,
	vectors: SealStreamV2Vector[],
	cipherName: 'xchacha20' | 'serpent',
): Promise<string[]> {
	return page.evaluate(async ({ base, vectors, cipherName }) => {
		const lib = await import(`${base}/dist/index.js`);
		const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
		const cipherImports = cipherName === 'xchacha20'
			? await import(`${base}/dist/chacha20/embedded.js`)
			: await import(`${base}/dist/serpent/embedded.js`);
		(await import(`${base}/dist/init.js`))._resetForTesting();
		await lib.init(cipherName === 'xchacha20'
			? { chacha20: cipherImports.chacha20Wasm, sha2: sha2Wasm }
			: { serpent: cipherImports.serpentWasm, sha2: sha2Wasm });

		const cipher = cipherName === 'xchacha20' ? lib.XChaCha20Cipher : lib.SerpentCipher;
		const fromHex = (h: string) => Uint8Array.from(h.match(/.{2}/g) ?? [], b => parseInt(b, 16));
		const toHex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

		const errors: string[] = [];
		for (const v of vectors) {
			const key = fromHex(v.key);
			const nonce = fromHex(v.nonce);
			const opts = { chunkSize: v.chunkSize, framed: v.framed };

			// Preamble
			const sealer1 = lib.SealStream._fromNonce(cipher, key, opts, nonce);
			if (toHex(sealer1.preamble) !== v.preamble) {
				errors.push(`${v.description}: preamble mismatch`);
			}
			sealer1.finalize(new Uint8Array(0));

			// Per-chunk seal
			const sealer2 = lib.SealStream._fromNonce(cipher, key, opts, nonce);
			for (let i = 0; i < v.chunks.length; i++) {
				const pt = fromHex(v.chunks[i].plaintext);
				const isLast = i === v.chunks.length - 1;
				const ct = isLast ? sealer2.finalize(pt) : sealer2.push(pt);
				if (toHex(ct) !== v.chunks[i].ciphertext) {
					errors.push(`${v.description}: chunk ${i} ciphertext mismatch`);
				}
			}

			// Round-trip
			const sealer3 = lib.SealStream._fromNonce(cipher, key, opts, nonce);
			const preamble = sealer3.preamble;
			const allCt: Uint8Array[] = [];
			for (let i = 0; i < v.chunks.length; i++) {
				const pt = fromHex(v.chunks[i].plaintext);
				const isLast = i === v.chunks.length - 1;
				allCt.push(isLast ? sealer3.finalize(pt) : sealer3.push(pt));
			}
			const opener = new lib.OpenStream(cipher, key, preamble);
			for (let i = 0; i < allCt.length; i++) {
				const isLast = i === allCt.length - 1;
				const pt = isLast ? opener.finalize(allCt[i]) : opener.pull(allCt[i]);
				if (toHex(pt) !== v.chunks[i].plaintext) {
					errors.push(`${v.description}: round-trip chunk ${i} plaintext mismatch`);
				}
			}
		}
		return errors;
	}, { base: BASE, vectors, cipherName });
}

test('SealStream KAT batch — XChaCha20 (XC1, XC3, XCF1)', async ({ page }) => {
	const errors = await runBatch(page, xchachaVectors, 'xchacha20');
	expect(errors, errors.join('\n')).toEqual([]);
});

test('SealStream KAT batch — Serpent (SC1, SC3, SCF1)', async ({ page }) => {
	const errors = await runBatch(page, serpentVectors, 'serpent');
	expect(errors, errors.join('\n')).toEqual([]);
});
