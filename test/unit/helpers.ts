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
// test/unit/helpers.ts
//
// WASM test helpers for Vitest. Gets the serpent WASM instance from the
// init() cache — call `await init('serpent')` in beforeAll before using.

import { getInstance } from '../../src/ts/init.js';

interface SerpentExports {
	memory:           WebAssembly.Memory
	getKeyOffset:     () => number
	getBlockPtOffset: () => number
	getBlockCtOffset: () => number
	getNonceOffset:   () => number
	getCounterOffset: () => number
	getSubkeyOffset:  () => number
	getChunkPtOffset: () => number
	getChunkCtOffset: () => number
	getChunkSize:     () => number
	getCbcIvOffset:   () => number
	loadKey:          (n: number) => number
	encryptBlock:     () => void
	decryptBlock:     () => void
	resetCounter:     () => void
	setCounter:       (lo: bigint, hi: bigint) => void
	encryptChunk:     (n: number) => number
	decryptChunk:     (n: number) => number
	cbcEncryptChunk:  (n: number) => number
	cbcDecryptChunk:  (n: number) => number
	wipeBuffers:      () => void
}

export function getWasm(): SerpentExports {
	return getInstance('serpent').exports as unknown as SerpentExports;
}

export const mem = (): Uint8Array =>
	new Uint8Array(getWasm().memory.buffer);

export const writeBytes = (bytes: Uint8Array, offset: number): void =>
	mem().set(bytes, offset);

export const readBytes = (offset: number, length: number): Uint8Array =>
	mem().slice(offset, offset + length);

export const toHex = (bytes: Uint8Array): string =>
	Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

export const fromHex = (hex: string): Uint8Array =>
	Uint8Array.from(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));

export const loadKey = (keyHex: string): void => {
	const w = getWasm();
	const key = fromHex(keyHex);
	writeBytes(key, w.getKeyOffset());
	const result = w.loadKey(key.length);
	if (result !== 0) throw new Error(`loadKey failed for length ${key.length}`);
};

export const encryptBlock = (ptHex: string): string => {
	const w = getWasm();
	writeBytes(fromHex(ptHex), w.getBlockPtOffset());
	w.encryptBlock();
	return toHex(readBytes(w.getBlockCtOffset(), 16));
};

export const decryptBlock = (ctHex: string): string => {
	const w = getWasm();
	writeBytes(fromHex(ctHex), w.getBlockCtOffset());
	w.decryptBlock();
	return toHex(readBytes(w.getBlockPtOffset(), 16));
};

export const wipeBuffers = (): void => getWasm().wipeBuffers();
