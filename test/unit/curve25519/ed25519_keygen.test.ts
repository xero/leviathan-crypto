//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▒█▀▄ ▒█▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓ ▓ ▓ ▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ █ ▒ █
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
 * Ed25519 deterministic key generation (RFC 8032 §5.1.5).
 *
 * Order matters: the RFC 8032 §7 records run first as the GATE; if any
 * RFC record fails the ACVP block is skipped (vitest's per-it independence
 * keeps the ACVP failures from drowning the diagnosable RFC failure).
 *
 * The pure-mode RFC §7.1 vectors each contain a (skHex, pkHex) pair which
 * exercises keygen as a side effect: ed25519Keygen(skHex) must equal
 * pkHex byte-for-byte. The §7.3 prehash record has a matching seed/pk
 * pair too; keygen is mode-independent so it counts as a keygen vector
 * regardless of whether the surrounding signature is pure or prehash.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { ed25519Vectors } from '../../vectors/ed25519.js';
import { ed25519_keygen } from '../../vectors/ed25519_keygen.js';
import {
	loadCurve25519, hexToBytes, bytesToHex, readBytes, writeBytes, testSlot,
	type Curve25519Exports,
} from './util.js';

let wasm: Curve25519Exports;

beforeAll(async () => {
	wasm = await loadCurve25519();
});

const SEED_OFF = testSlot(0);
const PK_OFF   = testSlot(64);

describe('ed25519 keygen', () => {
	// GATE: RFC 8032 §7 (4 pure + 1 prehash records, each with a sk/pk pair).
	describe('RFC 8032 §7 keygen pairs', () => {
		for (let i = 0; i < ed25519Vectors.length; i++) {
			const v = ed25519Vectors[i];
			it(`record ${i} (${v.mode}): keygen(sk) == pk`, () => {
				wasm.wipeBuffers();
				writeBytes(wasm.memory, SEED_OFF, hexToBytes(v.skHex));
				wasm.ed25519Keygen(SEED_OFF, PK_OFF);
				expect(bytesToHex(readBytes(wasm.memory, PK_OFF, 32))).toBe(v.pkHex);
			});
		}
	});

	// ACVP EDDSA-KeyGen-1.0, 3 records. Runs after the RFC gate.
	describe('ACVP EDDSA keyGen', () => {
		for (const rec of ed25519_keygen) {
			it(`tcId ${rec.tcId}: keygen(seed) == q`, () => {
				wasm.wipeBuffers();
				writeBytes(wasm.memory, SEED_OFF, hexToBytes(rec.seed));
				wasm.ed25519Keygen(SEED_OFF, PK_OFF);
				expect(bytesToHex(readBytes(wasm.memory, PK_OFF, 32)).toUpperCase()).toBe(rec.q.toUpperCase());
			});
		}
	});
});
