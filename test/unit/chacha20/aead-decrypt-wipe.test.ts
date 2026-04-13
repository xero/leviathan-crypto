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
 * aeadDecrypt auth-failure wipe coverage.
 *
 * On auth failure the ciphertext chunk buffer (CHUNK_CT) is wiped; that has
 * always been the case. This file also locks in wipes of the 64-byte
 * CHACHA_BLOCK_BUFFER region (which holds the last-generated keystream
 * block) and the 32-byte POLY_KEY_BUFFER copy of that block's first 32
 * bytes (the Poly1305 one-time subkey for the (key, nonce) pair). Without
 * the extra wipes, residual key material persists in linear memory until
 * the next op or until dispose().
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, ChaCha20Poly1305 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm });
});

interface ChaChaExports {
	memory: WebAssembly.Memory
	getChunkCtOffset: () => number
	getChachaBlockOffset: () => number
	getPolyKeyOffset: () => number
}

function getExports(): ChaChaExports {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

function regionIsZero(mem: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (mem[off + i] !== 0) return false;
	return true;
}

describe('ChaCha20Poly1305.decrypt — auth failure wipes WASM state', () => {
	it('CHUNK_CT region is zero after auth failure (regression)', () => {
		const enc = new ChaCha20Poly1305();
		const key = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const sealed = enc.encrypt(key, nonce, new Uint8Array(128).fill(0x42));
		enc.dispose();

		// Flip the tag so decrypt fails.
		const tampered = new Uint8Array(sealed);
		tampered[tampered.length - 1] ^= 0x01;

		const dec = new ChaCha20Poly1305();
		expect(() => dec.decrypt(key, nonce, tampered)).toThrow(/chacha20-poly1305/);

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		const ctOff = x.getChunkCtOffset();
		// The ciphertext chunk buffer must be zero in its first 128 bytes
		// (the region written by the plaintext length).
		expect(regionIsZero(mem, ctOff, 128)).toBe(true);
		dec.dispose();
	});

	it('CHACHA_BLOCK_BUFFER is zero after auth failure', () => {
		const enc = new ChaCha20Poly1305();
		const key = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const sealed = enc.encrypt(key, nonce, new Uint8Array(64).fill(0xA5));
		enc.dispose();

		const tampered = new Uint8Array(sealed);
		tampered[tampered.length - 1] ^= 0x01;

		const dec = new ChaCha20Poly1305();
		expect(() => dec.decrypt(key, nonce, tampered)).toThrow(/chacha20-poly1305/);

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		const blockOff = x.getChachaBlockOffset();
		// The 64-byte keystream block buffer holds residual poly-key material
		// after chachaGenPolyKey; must be zero-wiped on auth failure.
		expect(regionIsZero(mem, blockOff, 64)).toBe(true);
		dec.dispose();
	});

	it('POLY_KEY_BUFFER is zero after auth failure', () => {
		// chachaGenPolyKey copies keystream[0..32] from CHACHA_BLOCK_OFFSET to
		// POLY_KEY_OFFSET (=131248), far outside the 48..112 CHACHA_BLOCK
		// range. Without the explicit POLY_KEY_BUFFER wipe, the Poly1305
		// one-time subkey for this (key, nonce) pair would persist in linear
		// memory after the throw.
		const enc = new ChaCha20Poly1305();
		const key = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const sealed = enc.encrypt(key, nonce, new Uint8Array(64).fill(0x5A));
		enc.dispose();

		const tampered = new Uint8Array(sealed);
		tampered[tampered.length - 1] ^= 0x01;

		const dec = new ChaCha20Poly1305();
		expect(() => dec.decrypt(key, nonce, tampered)).toThrow(/chacha20-poly1305/);

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		const polyKeyOff = x.getPolyKeyOffset();
		expect(regionIsZero(mem, polyKeyOff, 32)).toBe(true);
		dec.dispose();
	});
});
