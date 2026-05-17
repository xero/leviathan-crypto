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
 * p256 substrate gate, SP 800-186 §3.2.1.3 (P-256 parameters) and
 * SEC1 §2.3.3 (compressed-point encoding).
 *
 * Three checks below are marked // GATE. Per AGENTS.md §3 (gate
 * discipline), the gate MUST pass before any other p256 test is
 * written. If a gate fails, debug the implementation; do NOT modify
 * the test or the source vector.
 *
 * Vectors are sourced from the SP 800-186 spec table for the
 * basepoint and curve order, never re-transcribed from a planning
 * document.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadP256, hexToBytes, bytesToHex, readBytes, writeBytes,
	testSlot, N_HEX,
	type P256Exports,
} from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

describe('p256 substrate gate', () => {
	// GATE: [1]G == G, basepoint identity from SP 800-186 §3.2.1.3.
	// pointBasepoint writes G; pointMulBase(1) computes [1]G via the
	// scalar-mult ladder. Both must produce the same point.
	it('[1]G == G per SP 800-186 §3.2.1.3', () => {
		wasm.wipeBuffers();
		const P    = testSlot(0);     // [1]G result (96 bytes projective)
		const G    = testSlot(96);    // reference basepoint
		const scal = testSlot(192);   // 32-byte BE scalar

		const one = new Uint8Array(32);
		one[31] = 1;  // BE: byte 31 is LSB
		writeBytes(wasm.memory, scal, one);

		wasm.pointMulBase(scal, P);
		wasm.pointBasepoint(G);

		expect(wasm.pointEqual(P, G)).toBe(1);
	});

	// GATE: compressed-G encoding matches SP 800-186 §3.2.1.3 + SEC1 §2.3.3.
	// Gy LSB = 0xF5 & 1 = 1 (odd), so prefix = 0x03; payload is Gx in BE.
	//
	//   Compressed G = 03 || 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81
	//                       2DEB33A0 F4A13945 D898C296
	//
	// SP 800-186 §3.2.1.3 publishes Gx in this form; the prefix byte is
	// fixed by SEC1 §2.3.3 once Gy's parity is known. No value here is
	// from a planning document; every byte is the spec.
	it('compress(G) matches SEC1 §2.3.3 + SP 800-186 §3.2.1.3', () => {
		wasm.wipeBuffers();
		const G   = testSlot(0);
		const enc = testSlot(96);     // 33 bytes compressed

		wasm.pointBasepoint(G);
		wasm.pointCompress(enc, G);

		const SPEC_G_COMPRESSED =
			'03' +
			'6b17d1f2e12c4247f8bce6e563a440f2' +
			'77037d812deb33a0f4a13945d898c296';

		expect(bytesToHex(readBytes(wasm.memory, enc, 33)))
			.toBe(SPEC_G_COMPRESSED);
	});

	// GATE: decompress(compress(G)) == G round-trip.
	it('decompress(compress(G)) == G per SEC1 §2.3.4', () => {
		wasm.wipeBuffers();
		const G    = testSlot(0);
		const enc  = testSlot(96);
		const Gout = testSlot(192);

		wasm.pointBasepoint(G);
		wasm.pointCompress(enc, G);
		const ok = wasm.pointDecompress(Gout, enc);

		expect(ok).toBe(1);
		expect(wasm.pointEqual(G, Gout)).toBe(1);
	});

	// GATE: [n]G == identity per SP 800-186 §3.2.1.3 (curve order).
	// n is the order of the basepoint, so [n]G is the identity element
	// (point at infinity, Z = 0 in projective). pointZero produces the
	// canonical (0:1:0) identity; we compare with pointEqual which uses
	// the projective equivalence relation.
	it('[n]G == identity per SP 800-186 §3.2.1.3', () => {
		wasm.wipeBuffers();
		const P     = testSlot(0);
		const Ident = testSlot(96);
		const ns    = testSlot(192);

		writeBytes(wasm.memory, ns, hexToBytes(N_HEX));

		wasm.pointMulBase(ns, P);
		wasm.pointZero(Ident);

		expect(wasm.pointEqual(P, Ident)).toBe(1);
	}, 30000);
});
