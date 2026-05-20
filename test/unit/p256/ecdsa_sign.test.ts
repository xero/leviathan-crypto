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
 * Validate `ecdsaSign` against RFC 6979 §A.2.5 + ACVP keyGen.
 * rnd=0^32 selects RFC 6979 §3.2 deterministic K → byte-exact (r, s).
 * AGENTS.md §3: vectors immutable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import {
	RFC6979_P256_KEY, ecdsa_p256_rfc6979,
} from '../../vectors/ecdsa_p256.js';
import {
	loadP256, hexToBytes, bytesToHex, readBytes, writeBytes,
	testSlot, N_HEX,
	type P256Exports,
} from './util.js';

// Library emits low-S per RFC 6979 §3.5; compare RFC's high-S sigs against (n - s).
function lowS(sHex: string): string {
	const n = BigInt('0x' + N_HEX);
	const s = BigInt('0x' + sHex);
	const half = n >> 1n;
	const out = s > half ? n - s : s;
	return out.toString(16).padStart(64, '0');
}

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

describe('p256 ecdsaSign (deterministic shortcut)', () => {
	for (const vec of ecdsa_p256_rfc6979) {
		it(`§A.2.5 record "${vec.id}" reproduces (r, s) byte-for-byte`, () => {
			wasm.wipeBuffers();

			// Materialise compressed pk first via ecdsaKeygen so the
			// fault-check has a comparable target.
			const seedOff = testSlot(0);    // 32 bytes (= d)
			const pkOff   = testSlot(32);   // 33 bytes compressed pk
			const msgHashOff = testSlot(96);// 32 bytes
			const rndOff  = testSlot(128);  // 32 bytes (all zero)
			const sigOff  = testSlot(160);  // 64 bytes

			const d = hexToBytes(RFC6979_P256_KEY.xHex);
			writeBytes(wasm.memory, seedOff, d);

			wasm.ecdsaKeygen(seedOff, pkOff);

			const msgBytes = new TextEncoder().encode(vec.msgUtf8);
			const msgHash = createHash('sha256').update(msgBytes).digest();
			writeBytes(wasm.memory, msgHashOff, new Uint8Array(msgHash));
			writeBytes(wasm.memory, rndOff, new Uint8Array(32));  // all zero

			wasm.ecdsaSign(seedOff, pkOff, msgHashOff, rndOff, sigOff);

			const r = readBytes(wasm.memory, sigOff, 32);
			const s = readBytes(wasm.memory, sigOff + 32, 32);

			// Library low-S per RFC 6979 §3.5; compare against lowS(§A.2.5 s).
			expect(bytesToHex(r).toLowerCase()).toBe(vec.rHex.toLowerCase());
			expect(bytesToHex(s).toLowerCase()).toBe(lowS(vec.sHex).toLowerCase());
		});
	}
});
