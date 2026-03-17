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
 * Monte Carlo ECB tests — Serpent AES submission
 *
 * Source: AES candidate submission, Ross Anderson / Eli Biham / Lars Knudsen
 * Files:  vectors/serpent_ecb_e_m.txt (encrypt, 1,200 outer × 10,000 inner)
 *         vectors/serpent_ecb_d_m.txt (decrypt, 1,200 outer × 10,000 inner)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { fromHex, toHex, getWasm } from '../helpers';
import { parseMcEcbEncryptFile, parseMcEcbDecryptFile } from './vector_parser';

const INNER_LOOP = 10000;

beforeAll(async () => {
	await init('serpent');
});

function wasmLoadKey(mem: Uint8Array, keyBytes: Uint8Array, wasm: ReturnType<typeof getWasm>): void {
	mem.set(keyBytes, wasm.getKeyOffset());
	if (wasm.loadKey(keyBytes.length) !== 0)
		throw new Error(`loadKey failed: len=${keyBytes.length}`);
}

function runEncryptLoop(
	mem: Uint8Array,
	initPt: Uint8Array,
	wasm: ReturnType<typeof getWasm>,
): { ct9998: Uint8Array; ct9999: Uint8Array } {
	const ptOff = wasm.getBlockPtOffset();
	const ctOff = wasm.getBlockCtOffset();
	mem.set(initPt, ptOff);
	const ct9998 = new Uint8Array(16);
	for (let j = 0; j < INNER_LOOP; j++) {
		wasm.encryptBlock();
		if (j === INNER_LOOP - 2) ct9998.set(mem.subarray(ctOff, ctOff + 16));
		mem.set(mem.subarray(ctOff, ctOff + 16), ptOff);
	}
	return { ct9998, ct9999: mem.slice(ptOff, ptOff + 16) };
}

function runDecryptLoop(
	mem: Uint8Array,
	initCt: Uint8Array,
	wasm: ReturnType<typeof getWasm>,
): { pt9999: Uint8Array } {
	const ptOff = wasm.getBlockPtOffset();
	const ctOff = wasm.getBlockCtOffset();
	mem.set(initCt, ctOff);
	for (let j = 0; j < INNER_LOOP; j++) {
		wasm.decryptBlock();
		mem.set(mem.subarray(ptOff, ptOff + 16), ctOff);
	}
	return { pt9999: mem.slice(ptOff, ptOff + 16) };
}

describe('ECB Monte Carlo — serpent_ecb_e_m.txt', () => {
	const vectors = parseMcEcbEncryptFile('serpent_ecb_e_m.txt');

	it('parses 1200 vectors (400 per key size)', () => {
		expect(vectors.length).toBe(1200);
	});

	it('all 1200 vectors pass (10000-iteration inner loop)', () => {
		const wasm = getWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		for (const v of vectors) {
			const key = fromHex(v.key);
			wasmLoadKey(mem, key, wasm);
			const { ct9999 } = runEncryptLoop(mem, fromHex(v.pt), wasm);
			expect(toHex(ct9999)).toBe(v.ct);
		}
	});
});

describe('ECB Monte Carlo — serpent_ecb_d_m.txt', () => {
	const vectors = parseMcEcbDecryptFile('serpent_ecb_d_m.txt');

	it('parses 1200 vectors (400 per key size)', () => {
		expect(vectors.length).toBe(1200);
	});

	it('all 1200 vectors pass (10000-iteration inner loop)', () => {
		const wasm = getWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		for (const v of vectors) {
			const key = fromHex(v.key);
			wasmLoadKey(mem, key, wasm);
			const { pt9999 } = runDecryptLoop(mem, fromHex(v.ct), wasm);
			expect(toHex(pt9999)).toBe(v.pt);
		}
	});
});
