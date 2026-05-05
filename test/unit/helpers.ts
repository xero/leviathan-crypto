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

/** Retrieves serpent WASM exports from the init() module cache; requires `await init({ serpent: ... })` in beforeAll. */
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

/** Writes key bytes to WASM memory at getKeyOffset() and calls loadKey() to expand the subkeys. */
export const loadKey = (keyHex: string): void => {
	const w = getWasm();
	const key = fromHex(keyHex);
	writeBytes(key, w.getKeyOffset());
	const result = w.loadKey(key.length);
	if (result !== 0) throw new Error(`loadKey failed for length ${key.length}`);
};

/** Writes ptHex to the plaintext buffer, calls encryptBlock(), and returns the ciphertext buffer as hex. */
export const encryptBlock = (ptHex: string): string => {
	const w = getWasm();
	writeBytes(fromHex(ptHex), w.getBlockPtOffset());
	w.encryptBlock();
	return toHex(readBytes(w.getBlockCtOffset(), 16));
};

/** Writes ctHex to the ciphertext buffer, calls decryptBlock(), and returns the plaintext buffer as hex. */
export const decryptBlock = (ctHex: string): string => {
	const w = getWasm();
	writeBytes(fromHex(ctHex), w.getBlockCtOffset());
	w.decryptBlock();
	return toHex(readBytes(w.getBlockPtOffset(), 16));
};

/** Zeros all WASM memory buffers via the exported wipeBuffers() function. */
export const wipeBuffers = (): void => getWasm().wipeBuffers();

// ── Floppy-format wrappers ──────────────────────────────────────────────────
// AES-submission floppy-format vector files use REVERSE-ALL-BYTES relative to
// the WASM's natural NIST byte order. These wrappers reverse on the way in
// and the way out so callers can keep the floppy hex strings unchanged.

/** Returns a byte-reversed copy. The floppy-format ↔ natural-order conversion. */
export const reverseBytes = (bytes: Uint8Array): Uint8Array => {
	const out = new Uint8Array(bytes.length);
	for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i];
	return out;
};

/** loadKey() with floppy-format key hex (reverses bytes before loading). */
export const loadKeyFloppy = (keyHex: string): void => {
	const w = getWasm();
	const key = reverseBytes(fromHex(keyHex));
	writeBytes(key, w.getKeyOffset());
	const result = w.loadKey(key.length);
	if (result !== 0) throw new Error(`loadKey failed for length ${key.length}`);
};

/** encryptBlock() with floppy-format pt hex; returns floppy-format ct hex. */
export const encryptBlockFloppy = (ptHex: string): string => {
	const w = getWasm();
	writeBytes(reverseBytes(fromHex(ptHex)), w.getBlockPtOffset());
	w.encryptBlock();
	return toHex(reverseBytes(readBytes(w.getBlockCtOffset(), 16)));
};

/** decryptBlock() with floppy-format ct hex; returns floppy-format pt hex. */
export const decryptBlockFloppy = (ctHex: string): string => {
	const w = getWasm();
	writeBytes(reverseBytes(fromHex(ctHex)), w.getBlockCtOffset());
	w.decryptBlock();
	return toHex(reverseBytes(readBytes(w.getBlockPtOffset(), 16)));
};
