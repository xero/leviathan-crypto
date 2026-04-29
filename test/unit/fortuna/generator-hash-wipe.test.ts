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
 * Per-call wipe discipline for the pluggable Generator / HashFn wrappers.
 *
 * Contract:
 *   - SerpentGenerator.generate() wipes the serpent WASM scratch (key,
 *     key schedule, last block plaintext/ciphertext) before returning.
 *   - ChaCha20Generator.generate() wipes the chacha20 WASM scratch (key,
 *     state, keystream chunk) before returning.
 *   - SHA256Hash.digest() wipes the sha2 WASM scratch (input/output/state).
 *   - SHA3_256Hash.digest() wipes the sha3 WASM scratch (input/output/sponge).
 *
 * Without these wipes, secret-derived bytes (Fortuna's genKey, pool-hash
 * inputs, message-key derivations) persist in shared WASM linear memory for
 * the lifetime of the module — much longer than the operation itself.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { SerpentGenerator }  from '../../../src/ts/serpent/index.js';
import { ChaCha20Generator } from '../../../src/ts/chacha20/index.js';
import { SHA256Hash }        from '../../../src/ts/sha2/index.js';
import { SHA3_256Hash }      from '../../../src/ts/sha3/index.js';
import { getInstance }       from '../../../src/ts/init.js';
import { serpentWasm }       from '../../../src/ts/serpent/embedded.js';
import { chacha20Wasm }      from '../../../src/ts/chacha20/embedded.js';
import { sha2Wasm }          from '../../../src/ts/sha2/embedded.js';
import { sha3Wasm }          from '../../../src/ts/sha3/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm });
});

function isZero(buf: Uint8Array): boolean {
	for (const b of buf) if (b !== 0) return false;
	return true;
}

describe('SerpentGenerator.generate — wipe-on-return', () => {
	it('zeroes the key + block plaintext + block ciphertext WASM scratch after return', () => {
		const x = getInstance('serpent').exports as unknown as {
			memory:           WebAssembly.Memory;
			getKeyOffset:     () => number;
			getBlockPtOffset: () => number;
			getBlockCtOffset: () => number;
		};
		const key     = new Uint8Array(32).fill(0xab);
		const counter = new Uint8Array(16).fill(0xcd);
		SerpentGenerator.generate(key, counter, 32);
		const mem = new Uint8Array(x.memory.buffer);
		const keyRegion = mem.slice(x.getKeyOffset(), x.getKeyOffset() + 32);
		const ptRegion  = mem.slice(x.getBlockPtOffset(), x.getBlockPtOffset() + 16);
		const ctRegion  = mem.slice(x.getBlockCtOffset(), x.getBlockCtOffset() + 16);
		expect(isZero(keyRegion)).toBe(true);
		expect(isZero(ptRegion)).toBe(true);
		expect(isZero(ctRegion)).toBe(true);
	});
});

describe('ChaCha20Generator.generate — wipe-on-return', () => {
	it('zeroes the key + chunk plaintext/ciphertext WASM scratch after return', () => {
		const x = getInstance('chacha20').exports as unknown as {
			memory:            WebAssembly.Memory;
			getKeyOffset:      () => number;
			getChunkPtOffset:  () => number;
			getChunkCtOffset:  () => number;
		};
		const key     = new Uint8Array(32).fill(0x55);
		const counter = new Uint8Array(4).fill(0x77);
		ChaCha20Generator.generate(key, counter, 128);
		const mem = new Uint8Array(x.memory.buffer);
		const keyRegion = mem.slice(x.getKeyOffset(), x.getKeyOffset() + 32);
		const ptRegion  = mem.slice(x.getChunkPtOffset(), x.getChunkPtOffset() + 128);
		const ctRegion  = mem.slice(x.getChunkCtOffset(), x.getChunkCtOffset() + 128);
		expect(isZero(keyRegion)).toBe(true);
		expect(isZero(ptRegion)).toBe(true);
		expect(isZero(ctRegion)).toBe(true);
	});
});

describe('SHA256Hash.digest — wipe-on-return', () => {
	it('zeroes the input + output WASM scratch after return', () => {
		const x = getInstance('sha2').exports as unknown as {
			memory:               WebAssembly.Memory;
			getSha256InputOffset: () => number;
			getSha256OutOffset:   () => number;
		};
		const msg = new Uint8Array(64).fill(0x99);
		const out = SHA256Hash.digest(msg);
		expect(out).toHaveLength(32);
		const mem = new Uint8Array(x.memory.buffer);
		const inRegion  = mem.slice(x.getSha256InputOffset(), x.getSha256InputOffset() + 64);
		const outRegion = mem.slice(x.getSha256OutOffset(),   x.getSha256OutOffset()   + 32);
		expect(isZero(inRegion)).toBe(true);
		expect(isZero(outRegion)).toBe(true);
	});
});

describe('SHA3_256Hash.digest — wipe-on-return', () => {
	it('zeroes the input + output WASM scratch after return', () => {
		const x = getInstance('sha3').exports as unknown as {
			memory:         WebAssembly.Memory;
			getInputOffset: () => number;
			getOutOffset:   () => number;
		};
		const msg = new Uint8Array(168).fill(0x33); // one full SHA3-256 rate block
		const out = SHA3_256Hash.digest(msg);
		expect(out).toHaveLength(32);
		const mem = new Uint8Array(x.memory.buffer);
		const inRegion  = mem.slice(x.getInputOffset(), x.getInputOffset() + 168);
		const outRegion = mem.slice(x.getOutOffset(),   x.getOutOffset()   + 32);
		expect(isZero(inRegion)).toBe(true);
		expect(isZero(outRegion)).toBe(true);
	});
});
