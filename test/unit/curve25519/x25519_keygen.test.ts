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
 * X25519 deterministic key generation (RFC 7748 §6, basepoint variant).
 *
 * Both tests below are marked // GATE. Per AGENTS.md §3 (gate discipline),
 * the substrate gate in `gate.test.ts` already established that the
 * ladder produces the correct Alice/Bob shared secret given pre-clamped
 * inputs; this file verifies that the high-level `x25519Keygen` wrapper
 * adds the spec-mandated clamp (RFC 7748 §5) and uses the basepoint
 * u-coord (RFC 7748 §4.1, u = 9) on both halves of the §6.1 exchange.
 *
 * Vectors are sourced from `test/vectors/x25519.ts` (the §6.1 exchange
 * record); never re-transcribed in this file.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { x25519Vectors } from '../../vectors/x25519.js';
import {
	loadCurve25519, hexToBytes, bytesToHex, readBytes, writeBytes, testSlot,
	type Curve25519Exports,
} from './util.js';

let wasm: Curve25519Exports;

beforeAll(async () => {
	wasm = await loadCurve25519();
});

const SK_OFF = testSlot(0);
const PK_OFF = testSlot(64);

describe('x25519 keygen', () => {
	// GATE: RFC 7748 §6.1 Alice basepoint scalar mult.
	it('keygen(aliceSk) == alicePk per RFC 7748 §6.1', () => {
		const vec = x25519Vectors.find(v => v.kind === 'exchange');
		expect(vec).toBeDefined();
		if (vec === undefined || vec.kind !== 'exchange') return;

		wasm.wipeBuffers();
		writeBytes(wasm.memory, SK_OFF, hexToBytes(vec.aliceSkHex));
		wasm.x25519Keygen(SK_OFF, PK_OFF);
		expect(bytesToHex(readBytes(wasm.memory, PK_OFF, 32))).toBe(vec.alicePkHex);
	});

	// GATE: RFC 7748 §6.1 Bob basepoint scalar mult.
	it('keygen(bobSk) == bobPk per RFC 7748 §6.1', () => {
		const vec = x25519Vectors.find(v => v.kind === 'exchange');
		expect(vec).toBeDefined();
		if (vec === undefined || vec.kind !== 'exchange') return;

		wasm.wipeBuffers();
		writeBytes(wasm.memory, SK_OFF, hexToBytes(vec.bobSkHex));
		wasm.x25519Keygen(SK_OFF, PK_OFF);
		expect(bytesToHex(readBytes(wasm.memory, PK_OFF, 32))).toBe(vec.bobPkHex);
	});
});
