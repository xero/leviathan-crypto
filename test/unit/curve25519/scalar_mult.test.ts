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
 * edwards25519 scalar-multiplication invariants. Validates the
 * straight-line double-and-add loop in edPointMul / edPointMulBase
 * against group-theoretic identities.
 *
 * All scalars are deterministic (xorshift32) and small (32-bit values
 * written into byte 0..3 of a 32-byte LE scalar) so the JS-side
 * arithmetic for cross-checks stays in safe-integer / BigInt range.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadCurve25519, RNG, writeBytes, testSlot,
	type Curve25519Exports,
} from './util.js';

let wasm: Curve25519Exports;

beforeAll(async () => {
	wasm = await loadCurve25519();
});

// Encode a small 32-bit nonnegative integer s as a 32-byte LE scalar.
function smallScalar(dst: number, s: number): void {
	const b = new Uint8Array(32);
	b[0] = s        & 0xFF;
	b[1] = (s >>>  8) & 0xFF;
	b[2] = (s >>> 16) & 0xFF;
	b[3] = (s >>> 24) & 0xFF;
	writeBytes(wasm.memory, dst, b);
}

// Encode a BigInt scalar (assumed reducible mod L; we keep these small
// so reduction is unnecessary) as a 32-byte LE scalar.
function bigScalar(dst: number, s: bigint): void {
	const b = new Uint8Array(32);
	for (let i = 0; i < 32; i++) {
		b[i] = Number((s >> BigInt(i * 8)) & 0xFFn);
	}
	writeBytes(wasm.memory, dst, b);
}

describe('curve25519 Edwards scalar-mult invariants', () => {
	it('[0]G = O', () => {
		wasm.wipeBuffers();
		const P  = testSlot(0);
		const O  = testSlot(160);
		const sc = testSlot(320);
		smallScalar(sc, 0);
		wasm.edPointMulBase(P, sc);
		wasm.edPointZero(O);
		expect(wasm.edPointEqual(P, O)).toBe(1);
	});

	it('[1]G = G', () => {
		wasm.wipeBuffers();
		const P  = testSlot(0);
		const G  = testSlot(160);
		const sc = testSlot(320);
		smallScalar(sc, 1);
		wasm.edPointMulBase(P, sc);
		wasm.edPointBasepoint(G);
		expect(wasm.edPointEqual(P, G)).toBe(1);
	});

	it('[2]G = double(G)', () => {
		wasm.wipeBuffers();
		const P  = testSlot(0);
		const G  = testSlot(160);
		const G2 = testSlot(320);
		const sc = testSlot(480);
		smallScalar(sc, 2);
		wasm.edPointMulBase(P, sc);
		wasm.edPointBasepoint(G);
		wasm.edPointDouble(G2, G);
		expect(wasm.edPointEqual(P, G2)).toBe(1);
	});

	it('[s+t]G = [s]G + [t]G (group homomorphism)', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0x5A5A_0001);
		const sP   = testSlot(0);
		const tP   = testSlot(160);
		const sumP = testSlot(320);
		const lhs  = testSlot(480);
		const scS  = testSlot(640);
		const scT  = testSlot(672);
		const scSum = testSlot(704);

		for (let trial = 0; trial < 4; trial++) {
			const s = rng.next() % 100000;
			const t = rng.next() % 100000;
			smallScalar(scS, s);
			smallScalar(scT, t);
			smallScalar(scSum, s + t);

			wasm.edPointMulBase(sP, scS);
			wasm.edPointMulBase(tP, scT);
			wasm.edPointMulBase(sumP, scSum);
			wasm.edPointAdd(lhs, sP, tP);
			expect(wasm.edPointEqual(sumP, lhs)).toBe(1);
		}
	});

	it('[s]([t]G) = [s*t]G (scalar composition)', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0x5A5A_0002);
		const tP    = testSlot(0);
		const stP   = testSlot(160);
		const lhs   = testSlot(320);
		const scS   = testSlot(480);
		const scT   = testSlot(512);
		const scST  = testSlot(544);

		for (let trial = 0; trial < 4; trial++) {
			// Keep s, t < 2^16 so s*t < 2^32 fits an i32 (well within L).
			const s = rng.next() & 0xFFFF;
			const t = rng.next() & 0xFFFF;
			smallScalar(scS, s);
			smallScalar(scT, t);
			bigScalar(scST, BigInt(s) * BigInt(t));

			wasm.edPointMulBase(tP, scT);
			wasm.edPointMul(lhs, scS, tP);
			wasm.edPointMulBase(stP, scST);
			expect(wasm.edPointEqual(lhs, stP)).toBe(1);
		}
	});

	it('edPointMulBase(s) = edPointMul(s, B) (fixed-base / variable-base agreement)', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0x5A5A_0003);
		const fixedR = testSlot(0);
		const varR   = testSlot(160);
		const G      = testSlot(320);
		const sc     = testSlot(480);

		wasm.edPointBasepoint(G);
		for (let trial = 0; trial < 4; trial++) {
			const scalarBytes = rng.scalar32();
			writeBytes(wasm.memory, sc, scalarBytes);
			wasm.edPointMulBase(fixedR, sc);
			wasm.edPointMul(varR, sc, G);
			expect(wasm.edPointEqual(fixedR, varR)).toBe(1);
		}
	});
});
