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
 * Buffer wipe correctness — leviathan-crypto Serpent module
 *
 * Verifies that wipeBuffers() zeroes all buffer regions in the Serpent
 * module's linear memory. No key material persists after dispose().
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/init.js';
import { loadKey, encryptBlock, readBytes, wipeBuffers, getWasm } from '../helpers';

beforeAll(async () => {
	await init('serpent');
});

describe('wipeBuffers', () => {
	it('zeros all Serpent buffer regions after use', () => {
		loadKey('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
		encryptBlock('80000000000000000000000000000000');

		wipeBuffers();

		const wasm = getWasm();
		const checkZero = (offset: number, len: number, label: string) => {
			const buf = readBytes(offset, len);
			const allZero = buf.every(b => b === 0);
			expect(allZero, `${label} should be zero`).toBe(true);
		};

		checkZero(wasm.getKeyOffset(),       32,    'KEY_BUFFER');
		checkZero(wasm.getBlockPtOffset(),   16,    'BLOCK_PT_BUFFER');
		checkZero(wasm.getBlockCtOffset(),   16,    'BLOCK_CT_BUFFER');
		checkZero(wasm.getNonceOffset(),     16,    'NONCE_BUFFER');
		checkZero(wasm.getCounterOffset(),   16,    'COUNTER_BUFFER');
		checkZero(wasm.getSubkeyOffset(),    528,   'SUBKEY_BUFFER');
		checkZero(wasm.getChunkPtOffset(),   65536, 'CHUNK_PT_BUFFER');
		checkZero(wasm.getChunkCtOffset(),   65536, 'CHUNK_CT_BUFFER');
		checkZero(wasm.getCbcIvOffset(),     16,    'CBC_IV_BUFFER');
	});
});
