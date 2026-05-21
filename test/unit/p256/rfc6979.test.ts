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
 * Validate `deriveKDeterministic` against RFC 6979 §A.2.5 expected k
 * values for P-256 + SHA-256. This is the substrate gate for the
 * deterministic nonce path; ACVP SigGen supplies k explicitly and
 * therefore cannot exercise RFC 6979's k-from-(d, H(m)) derivation,
 * so this test is the only direct check against the RFC.
 *
 * Per AGENTS.md §3, RFC 6979 §A.2.5 expected values are sourced from
 * the RFC verbatim (via test/vectors/ecdsa_p256.ts) and never modified.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import {
	RFC6979_P256_KEY, ecdsa_p256_rfc6979,
} from '../../vectors/ecdsa_p256.js';
import {
	loadP256, hexToBytes, bytesToHex, readBytes, writeBytes,
	testSlot,
	type P256Exports,
} from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

describe('p256 RFC 6979 deterministic K derivation', () => {
	for (const vec of ecdsa_p256_rfc6979) {
		it(`§A.2.5 record "${vec.id}" reproduces RFC's k`, () => {
			wasm.wipeBuffers();
			const dOff       = testSlot(0);     // 32 bytes BE
			const msgHashOff = testSlot(32);    // 32 bytes BE
			const kOut       = testSlot(64);    // 32 bytes BE

			const d = hexToBytes(RFC6979_P256_KEY.xHex);
			const msgBytes = new TextEncoder().encode(vec.msgUtf8);
			const msgHash = createHash('sha256').update(msgBytes).digest();

			writeBytes(wasm.memory, dOff, d);
			writeBytes(wasm.memory, msgHashOff, new Uint8Array(msgHash));

			wasm.deriveKDeterministic(dOff, msgHashOff, kOut);

			const k = readBytes(wasm.memory, kOut, 32);
			expect(bytesToHex(k).toUpperCase()).toBe(vec.kHex.toUpperCase());
		});
	}
});
