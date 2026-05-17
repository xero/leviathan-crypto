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
 * scalarReduce64 BigInt-oracle cross-check. Regression coverage for the
 * L_LE byte-14 transcription error surfaced by ed25519 sign gating:
 * the original substrate hardcoded L14 = 0x4D (wrong) instead of
 * 0xDE (correct, per RFC 8032 §5.1 L = 2^252 + 27742317777372353535851937790883648493).
 * The previous substrate test only covered reduce64(0) = 0, which did
 * not exercise the byte-14 path. These tests touch every non-trivial
 * reduction shape the Ed25519 r / k derivations rely on.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadCurve25519, hexToBytes, bytesToHex, readBytes, writeBytes, testSlot,
	type Curve25519Exports,
} from './util.js';

let wasm: Curve25519Exports;
beforeAll(async () => {
	wasm = await loadCurve25519();
});

const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

function bytesToLeBig(b: Uint8Array): bigint {
	let v = 0n;
	for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
	return v;
}
function leBigToBytes(v: bigint, n: number): Uint8Array {
	const o = new Uint8Array(n);
	for (let i = 0; i < n; i++) {
		o[i] = Number(v & 0xffn);
		v >>= 8n;
	}
	return o;
}

describe('scalarReduce64 BigInt-oracle cross-check', () => {
	it('reduce64 of [zero 32 LE bytes || byte 32 = 1] = 2^256 mod L', () => {
		const src = new Uint8Array(64);
		src[32] = 1;
		wasm.wipeBuffers();
		const SRC_OFF = testSlot(0);
		const OUT_OFF = testSlot(64);
		writeBytes(wasm.memory, SRC_OFF, src);
		wasm.scalarReduce64(OUT_OFF, SRC_OFF);
		const got = readBytes(wasm.memory, OUT_OFF, 32);
		const expected = leBigToBytes((1n << 256n) % L, 32);
		expect(bytesToHex(got)).toBe(bytesToHex(expected));
	});

	it('reduce64 of HI=1, LO=0 (high byte at byte 32)', () => {
		const src = new Uint8Array(64);
		src[32] = 1;
		// HI = 1 (since bytes 32..64 = [1,0,...,0])
		// LO = 0
		// n = HI * 2^256 + LO = 2^256
		const got = computeWasm(src);
		const expected = leBigToBytes((1n << 256n) % L, 32);
		expect(bytesToHex(got)).toBe(bytesToHex(expected));
	});

	it('reduce64 of 2^248 (no reduction needed, < L)', () => {
		const src = new Uint8Array(64);
		src[31] = 1;  // 2^248 in low 32 bytes LE
		const got = computeWasm(src);
		const expected = new Uint8Array(32);
		expected[31] = 1;
		expect(bytesToHex(got)).toBe(bytesToHex(expected));
	});

	it('reduce64 of 2^252 (just below L)', () => {
		const src = new Uint8Array(64);
		src[31] = 0x10;  // 2^252 in low 32 bytes LE (still < L)
		const got = computeWasm(src);
		const expected = new Uint8Array(32);
		expected[31] = 0x10;
		expect(bytesToHex(got)).toBe(bytesToHex(expected));
	});

	it('reduce64 of L itself = 0', () => {
		const src = new Uint8Array(64);
		// L_LE
		const L_hex = 'edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010';
		src.set(hexToBytes(L_hex), 0);
		const got = computeWasm(src);
		const expected = new Uint8Array(32);
		expect(bytesToHex(got)).toBe(bytesToHex(expected));
	});

	it('reduce64 of a known SHA-512(prefix) output', () => {
		const src = hexToBytes('b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d');
		const got = computeWasm(src);
		const expected = leBigToBytes(bytesToLeBig(src) % L, 32);
		expect(bytesToHex(got)).toBe(bytesToHex(expected));
	});

	function computeWasm(src: Uint8Array): Uint8Array {
		wasm.wipeBuffers();
		const SRC_OFF = testSlot(0);
		const OUT_OFF = testSlot(64);
		writeBytes(wasm.memory, SRC_OFF, src);
		wasm.scalarReduce64(OUT_OFF, SRC_OFF);
		return readBytes(wasm.memory, OUT_OFF, 32);
	}
});
