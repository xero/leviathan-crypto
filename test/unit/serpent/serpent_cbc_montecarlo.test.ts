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
 * Monte Carlo CBC tests — Serpent AES submission
 *
 * Source: AES candidate submission, Ross Anderson / Eli Biham / Lars Knudsen
 * Files:  vectors/serpent_cbc_e_m.txt (encrypt, 1,200 outer × 10,000 inner)
 *         vectors/serpent_cbc_d_m.txt (decrypt, 1,200 outer × 10,000 inner)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { fromHex, toHex, getWasm } from '../helpers';
import { parseMcCbcEncryptFile, parseMcCbcDecryptFile } from './vector_parser';

const INNER_LOOP = 10000;

beforeAll(async () => {
	await init('serpent');
});

function wasmLoadKey(mem: Uint8Array, keyBytes: Uint8Array, wasm: ReturnType<typeof getWasm>): void {
	mem.set(keyBytes, wasm.getKeyOffset());
	if (wasm.loadKey(keyBytes.length) !== 0)
		throw new Error(`loadKey failed: len=${keyBytes.length}`);
}

function runCbcEncryptLoop(
	mem: Uint8Array,
	initIV: Uint8Array,
	initPt: Uint8Array,
	wasm: ReturnType<typeof getWasm>,
): Uint8Array {
	const ptOff = wasm.getBlockPtOffset();
	const ctOff = wasm.getBlockCtOffset();
	let iv = new Uint8Array(initIV);
	let pt = new Uint8Array(initPt);
	let ct9999 = new Uint8Array(16);

	for (let j = 0; j < INNER_LOOP; j++) {
		const cv = new Uint8Array(iv);
		for (let k = 0; k < 16; k++) mem[ptOff + k] = pt[k] ^ iv[k];
		wasm.encryptBlock();
		const ct = mem.slice(ctOff, ctOff + 16);
		ct9999 = new Uint8Array(ct);
		pt = cv;
		iv = ct;
	}
	return ct9999;
}

function runCbcDecryptLoop(
	mem: Uint8Array,
	initIV: Uint8Array,
	initCt: Uint8Array,
	wasm: ReturnType<typeof getWasm>,
): Uint8Array {
	const ptOff = wasm.getBlockPtOffset();
	const ctOff = wasm.getBlockCtOffset();
	let iv = new Uint8Array(initIV);
	let ct = new Uint8Array(initCt);
	let pt9999 = new Uint8Array(16);

	for (let j = 0; j < INNER_LOOP; j++) {
		mem.set(ct, ctOff);
		wasm.decryptBlock();
		const pt = new Uint8Array(16);
		for (let k = 0; k < 16; k++) pt[k] = mem[ptOff + k] ^ iv[k];
		pt9999 = new Uint8Array(pt);
		iv = new Uint8Array(ct);
		ct = new Uint8Array(pt);
	}
	return pt9999;
}

describe('CBC Monte Carlo — serpent_cbc_e_m.txt', () => {
	const vectors = parseMcCbcEncryptFile('serpent_cbc_e_m.txt');

	it('parses 1200 vectors (400 per key size)', () => {
		expect(vectors.length).toBe(1200);
	});

	it('all 1200 vectors pass (10000-iteration inner loop)', () => {
		const wasm = getWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		for (const v of vectors) {
			const key = fromHex(v.key);
			wasmLoadKey(mem, key, wasm);
			const ct9999 = runCbcEncryptLoop(mem, fromHex(v.iv), fromHex(v.pt), wasm);
			expect(toHex(ct9999)).toBe(v.ct);
		}
	});
});

describe('CBC Monte Carlo — serpent_cbc_d_m.txt', () => {
	const vectors = parseMcCbcDecryptFile('serpent_cbc_d_m.txt');

	it('parses 1200 vectors (400 per key size)', () => {
		expect(vectors.length).toBe(1200);
	});

	it('all 1200 vectors pass (10000-iteration inner loop)', () => {
		const wasm = getWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		for (const v of vectors) {
			const key = fromHex(v.key);
			wasmLoadKey(mem, key, wasm);
			const pt9999 = runCbcDecryptLoop(mem, fromHex(v.iv), fromHex(v.ct), wasm);
			expect(toHex(pt9999)).toBe(v.pt);
		}
	});
});
