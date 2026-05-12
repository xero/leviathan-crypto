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
/**
 * Known-Answer Tests (KAT), Serpent AES submission
 *
 * Source: AES candidate submission, Ross Anderson / Eli Biham / Lars Knudsen
 * Files:  vectors/serpent_ecb_vt.txt (variable-text, 384 vectors)
 *         vectors/serpent_ecb_vk.txt (variable-key, 576 vectors)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { loadKeyFloppy, encryptBlockFloppy, decryptBlockFloppy } from '../helpers';
import { parseVtFile, parseVkFile } from './vector_parser';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm });
});

describe('KAT, serpent_ecb_vt.txt variable-text (384 vectors)', () => {
	const vectors = parseVtFile('serpent_ecb_vt.txt');

	it('parses 384 vectors', () => {
		expect(vectors.length).toBe(384);
	});

	it('all 384 encrypt', () => {
		for (const { key, pt, ct } of vectors) {
			loadKeyFloppy(key);
			expect(encryptBlockFloppy(pt)).toBe(ct);
		}
	});

	it('all 384 decrypt', () => {
		for (const { key, pt, ct } of vectors) {
			loadKeyFloppy(key);
			expect(decryptBlockFloppy(ct)).toBe(pt);
		}
	});
});

describe('KAT, serpent_ecb_vk.txt variable-key (576 vectors)', () => {
	const vectors = parseVkFile('serpent_ecb_vk.txt');

	it('parses 576 vectors', () => {
		expect(vectors.length).toBe(576);
	});

	it('all 576 encrypt', () => {
		for (const { key, pt, ct } of vectors) {
			loadKeyFloppy(key);
			expect(encryptBlockFloppy(pt)).toBe(ct);
		}
	});

	it('all 576 decrypt', () => {
		for (const { key, pt, ct } of vectors) {
			loadKeyFloppy(key);
			expect(decryptBlockFloppy(ct)).toBe(pt);
		}
	});
});
