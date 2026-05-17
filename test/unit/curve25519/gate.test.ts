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
 * curve25519 substrate gate, RFC 7748 §6.1 (X25519 Alice/Bob) and
 * RFC 8032 §5.1 (edwards25519 basepoint identity).
 *
 * Both checks below are marked // GATE. Per AGENTS.md §3 (gate
 * discipline), the gate MUST pass before any other curve25519 test is
 * written. If a gate fails, debug the implementation; do NOT modify the
 * test or the source vector.
 *
 * Vectors are sourced from `test/vectors/x25519.ts` and from the RFC
 * 8032 §5.1 spec table for the basepoint encoding; never re-transcribed
 * in this file beyond the spec citation.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { x25519Vectors } from '../../vectors/x25519.js';
import {
	loadCurve25519, hexToBytes, bytesToHex, readBytes, writeBytes,
	testSlot,
	type Curve25519Exports,
} from './util.js';

let wasm: Curve25519Exports;

beforeAll(async () => {
	wasm = await loadCurve25519();
});

describe('curve25519 substrate gate', () => {
	// GATE: RFC 7748 §6.1 X25519 Alice/Bob.
	// Vector: test/vectors/x25519.ts (kind: 'exchange').
	it('X25519(alice_sk, bob_pk) == shared_secret per RFC 7748 §6.1', () => {
		const vec = x25519Vectors.find(v => v.kind === 'exchange');
		expect(vec).toBeDefined();
		if (vec === undefined || vec.kind !== 'exchange') return;

		const aliceSk = hexToBytes(vec.aliceSkHex);
		const bobPk   = hexToBytes(vec.bobPkHex);
		wasm.wipeBuffers();

		const base = wasm.getFieldTmpOffset();
		const offClamped = base +  0;
		const offU       = base + 32;
		const offRawSk   = base + 64;
		const offOut     = base + 96;

		writeBytes(wasm.memory, offRawSk, aliceSk);
		writeBytes(wasm.memory, offU,     bobPk);

		wasm.scalarClamp(offClamped, offRawSk);
		wasm.x25519Ladder(offOut, offClamped, offU);

		const shared = readBytes(wasm.memory, offOut, 32);
		expect(bytesToHex(shared)).toBe(vec.sharedHex);
	});

	// GATE: RFC 8032 §5.1 basepoint identity.
	// edPointMulBase(scalar=1) must produce the basepoint B; the compressed
	// encoding of B is fixed by §5.1 (y = By = 4/5 mod p, sign bit = LSB(Bx)
	// = 0) and equals "5866666666666666666666666666666666666666666666666666666666666666".
	// This encoding is derived from the spec-stated Bx, By decimal values
	// in §5.1 Table 1; the derivation is reproducible from those decimal
	// values via standard 32-byte LE encoding and the sign-bit rule.
	it('[1]B = B per RFC 8032 §5.1', () => {
		wasm.wipeBuffers();

		const P     = testSlot(0);        // [1]B result
		const Bref  = testSlot(160);      // reference basepoint
		const enc1  = testSlot(320);      // 32 bytes encoded P
		const encB  = testSlot(352);      // 32 bytes encoded B
		const scal  = testSlot(384);      // 32-byte scalar

		// scalar = 1: byte 0 = 1, rest zero
		const one = new Uint8Array(32);
		one[0] = 1;
		writeBytes(wasm.memory, scal, one);

		wasm.edPointMulBase(P, scal);
		wasm.edPointBasepoint(Bref);

		expect(wasm.edPointEqual(P, Bref)).toBe(1);

		wasm.edPointCompress(enc1, P);
		wasm.edPointCompress(encB, Bref);

		// Cross-check: compressed encoding matches the spec-derived
		// canonical 32-byte form of B.
		const SPEC_B = '5866666666666666666666666666666666666666666666666666666666666666';
		expect(bytesToHex(readBytes(wasm.memory, encB, 32))).toBe(SPEC_B);
		expect(bytesToHex(readBytes(wasm.memory, enc1, 32))).toBe(SPEC_B);
	});

	// GATE: scalar mult by the curve order L must yield the identity.
	// L is given in RFC 8032 §5.1 (Table 1, "L = 2^252 + δ"); the LE byte
	// encoding is derived directly from that decimal value. The identity
	// point (0, 1) compresses to "0100000000...00".
	it('[L]B = identity per RFC 8032 §5.1 (group order)', () => {
		wasm.wipeBuffers();

		const P    = testSlot(0);
		const enc  = testSlot(160);
		const Ls   = testSlot(192);

		// L per RFC 8032 §5.1 (2^252 + 27742317777372353535851937790883648493).
		// 32-byte LE encoding derived from the decimal value.
		const L_LE = hexToBytes('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
		writeBytes(wasm.memory, Ls, L_LE);

		wasm.edPointMulBase(P, Ls);
		wasm.edPointCompress(enc, P);

		const SPEC_IDENTITY = '0100000000000000000000000000000000000000000000000000000000000000';
		expect(bytesToHex(readBytes(wasm.memory, enc, 32))).toBe(SPEC_IDENTITY);
	});
});
