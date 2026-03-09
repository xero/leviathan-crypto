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
 * Intermediate value tests — Serpent AES submission
 *
 * Source: AES candidate submission, Ross Anderson / Eli Biham / Lars Knudsen
 * File:   vectors/serpent_ecb_iv.txt (3 key-size cases)
 *
 * GATE 2 — must pass before non-gate Serpent tests.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/init.js';
import { loadKey, readBytes, getWasm } from '../helpers';
import { parseIvFile } from './vector_parser';

beforeAll(async () => {
	await init('serpent');
});

function extractSubkeyHex(subkeyBuf: Uint8Array, i: number): string {
	const base = i * 4 * 4;
	const view = new DataView(subkeyBuf.buffer, subkeyBuf.byteOffset + base);
	const x0 = view.getUint32(0,  true);
	const x1 = view.getUint32(4,  true);
	const x2 = view.getUint32(8,  true);
	const x3 = view.getUint32(12, true);
	const w2h = (w: number) => (w >>> 0).toString(16).padStart(8, '0');
	return w2h(x3) + w2h(x2) + w2h(x1) + w2h(x0);
}

describe('Intermediate values — serpent_ecb_iv.txt key schedule (Gate 2)', () => {
	const cases = parseIvFile('serpent_ecb_iv.txt');

	it('parses 3 key-size cases', () => {
		expect(cases.length).toBe(3);
	});

	// GATE
	it('SK[0..32] match reference for all key sizes', () => {
		const wasm = getWasm();
		for (const { key, sk } of cases) {
			loadKey(key);
			const subkeyBuf = readBytes(wasm.getSubkeyOffset(), 33 * 4 * 4);
			for (let i = 0; i <= 32; i++) {
				const expected = sk[i];
				if (!expected) continue;
				const actual = extractSubkeyHex(subkeyBuf, i);
				expect(actual, `SK[${i}] key ${key.length / 2 * 8}-bit`).toBe(expected);
			}
		}
	});
});
