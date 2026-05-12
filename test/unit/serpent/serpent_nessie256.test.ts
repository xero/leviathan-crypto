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
 * NESSIE test vectors, serpent_nessie-256
 *
 * Source: NESSIE project evaluation, 2000-2003
 * File:   vectors/serpent_nessie-256.txt
 * Coverage: 1,284 encrypt + 1,284 decrypt vectors
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { toHex, fromHex, writeBytes, readBytes, getWasm } from '../helpers';
import { parseNessieFile } from './vector_parser';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm });
});

describe('NESSIE Serpent-256 vectors (1284 vectors)', () => {
	const vectors = parseNessieFile('serpent_nessie-256.txt');

	it('parses 1284 vectors', () => {
		expect(vectors.length).toBe(1284);
	});

	it('all 1284 encrypt', () => {
		const wasm = getWasm();
		for (const { key, plain, cipher } of vectors) {
			const k = fromHex(key);
			const pt = fromHex(plain);
			const ctExpected = fromHex(cipher);

			writeBytes(k, wasm.getKeyOffset());
			wasm.loadKey(k.length);
			writeBytes(pt, wasm.getBlockPtOffset());
			wasm.encryptBlock();
			const ctActual = readBytes(wasm.getBlockCtOffset(), 16);

			expect(toHex(ctActual)).toBe(toHex(ctExpected));
		}
	});

	it('all 1284 decrypt', () => {
		const wasm = getWasm();
		for (const { key, plain, cipher } of vectors) {
			const k = fromHex(key);
			const ct = fromHex(cipher);
			const ptExpected = fromHex(plain);

			writeBytes(k, wasm.getKeyOffset());
			wasm.loadKey(k.length);
			writeBytes(ct, wasm.getBlockCtOffset());
			wasm.decryptBlock();
			const ptActual = readBytes(wasm.getBlockPtOffset(), 16);

			expect(toHex(ptActual)).toBe(toHex(ptExpected));
		}
	});
});
