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
 * X25519 Diffie-Hellman shared-secret agreement (RFC 7748 §6, peer-pk
 * variant).
 *
 * Tests 1-2 are marked // GATE. They exercise both halves of the §6.1
 * Alice/Bob exchange: DH(aliceSk, bobPk) and DH(bobSk, alicePk) must
 * both yield the published sharedHex byte-for-byte (symmetry). Test 3
 * is an internal-consistency check: x25519DH agrees with the substrate
 * `x25519Ladder` when fed the same clamped scalar and peer u-coord.
 *
 * The all-zero shared-secret rejection (small-order peer-pk) is
 * enforced at the TS layer and exercised against the wrapped class
 * elsewhere; this file does not exercise it.
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

const SK_OFF      = testSlot(0);
const PEER_OFF    = testSlot(64);
const SHARED_OFF  = testSlot(128);
const CLAMP_OFF   = testSlot(192);
const LADDER_OFF  = testSlot(256);

describe('x25519 dh', () => {
	// GATE: RFC 7748 §6.1 DH from Alice's perspective.
	it('DH(aliceSk, bobPk) == sharedSecret per RFC 7748 §6.1', () => {
		const vec = x25519Vectors.find(v => v.kind === 'exchange');
		expect(vec).toBeDefined();
		if (vec === undefined || vec.kind !== 'exchange') return;

		wasm.wipeBuffers();
		writeBytes(wasm.memory, SK_OFF,   hexToBytes(vec.aliceSkHex));
		writeBytes(wasm.memory, PEER_OFF, hexToBytes(vec.bobPkHex));
		wasm.x25519DH(SK_OFF, PEER_OFF, SHARED_OFF);
		expect(bytesToHex(readBytes(wasm.memory, SHARED_OFF, 32))).toBe(vec.sharedHex);
	});

	// GATE: RFC 7748 §6.1 DH from Bob's perspective.
	// Symmetry: Bob and Alice must derive the same shared secret.
	it('DH(bobSk, alicePk) == sharedSecret per RFC 7748 §6.1', () => {
		const vec = x25519Vectors.find(v => v.kind === 'exchange');
		expect(vec).toBeDefined();
		if (vec === undefined || vec.kind !== 'exchange') return;

		wasm.wipeBuffers();
		writeBytes(wasm.memory, SK_OFF,   hexToBytes(vec.bobSkHex));
		writeBytes(wasm.memory, PEER_OFF, hexToBytes(vec.alicePkHex));
		wasm.x25519DH(SK_OFF, PEER_OFF, SHARED_OFF);
		expect(bytesToHex(readBytes(wasm.memory, SHARED_OFF, 32))).toBe(vec.sharedHex);
	});

	// Internal-consistency: the high-level wrapper agrees with the
	// substrate when handed the same clamped scalar and peer u-coord.
	// Confirms x25519DH applies clamping correctly and routes through
	// x25519Ladder without altering its arguments.
	it('DH agrees with x25519Ladder on clamped scalar + peer pk', () => {
		const vec = x25519Vectors.find(v => v.kind === 'exchange');
		expect(vec).toBeDefined();
		if (vec === undefined || vec.kind !== 'exchange') return;

		const sk   = hexToBytes(vec.aliceSkHex);
		const peer = hexToBytes(vec.bobPkHex);

		wasm.wipeBuffers();
		writeBytes(wasm.memory, SK_OFF,   sk);
		writeBytes(wasm.memory, PEER_OFF, peer);
		wasm.x25519DH(SK_OFF, PEER_OFF, SHARED_OFF);
		const fromHigh = readBytes(wasm.memory, SHARED_OFF, 32);

		// Substrate path: clamp manually then call the ladder.
		wasm.wipeBuffers();
		writeBytes(wasm.memory, SK_OFF,   sk);
		writeBytes(wasm.memory, PEER_OFF, peer);
		wasm.scalarClamp(CLAMP_OFF, SK_OFF);
		wasm.x25519Ladder(LADDER_OFF, CLAMP_OFF, PEER_OFF);
		const fromSub = readBytes(wasm.memory, LADDER_OFF, 32);

		expect(bytesToHex(fromHigh)).toBe(bytesToHex(fromSub));
	});
});
