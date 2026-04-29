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
 * S-box table entry tests — Serpent AES submission
 *
 * Source: AES candidate submission, Ross Anderson / Eli Biham / Lars Knudsen
 * File:   vectors/serpent_ecb_tbl.txt (1,536 vectors)
 *
 * GATE 1 — must pass before any other Serpent tests.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { loadKey, encryptBlock } from '../helpers';
import { parseTblFile } from './vector_parser';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm });
});

describe('S-box table entry tests — serpent_ecb_tbl.txt (Gate 1)', () => {
	const vectors = parseTblFile('serpent_ecb_tbl.txt');

	it('parses 1536 vectors', () => {
		expect(vectors.length).toBe(1536);
	});

	// GATE — Serpent ECB S-box: AES submission (Anderson/Biham/Knudsen)
	// Vector: serpent_ecb_tbl.txt
	it('all 1536 S-box entry vectors pass', () => {
		for (const { key, pt, ct } of vectors) {
			loadKey(key);
			expect(encryptBlock(pt)).toBe(ct);
		}
	});
});
