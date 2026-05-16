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
 * edwards25519 point operation invariants on extended (X:Y:Z:T)
 * coordinates. Tests structural correctness of edPointAdd, edPointSub,
 * edPointDouble, edPointEqual, edPointOnCurve, edPointCompress,
 * edPointDecompress.
 *
 * Uses deterministic random scalars (xorshift32) to derive multiple
 * Edwards points for invariant testing; never crypto.getRandomValues.
 * The basepoint B and points derived from it via scalar mult are the
 * primary input source.
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

// Generate the i-th deterministic test point P_i = [scalar_i]B.
function makePoint(out: number, rng: RNG): void {
	const scal = testSlot(900);
	const s = rng.scalar32();
	writeBytes(wasm.memory, scal, s);
	wasm.edPointMulBase(out, scal);
}

describe('curve25519 Edwards point invariants', () => {
	it('identity P + O = P', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0xA5A5_0001);
		const P  = testSlot(0);
		const O  = testSlot(160);
		const R  = testSlot(320);
		makePoint(P, rng);
		wasm.edPointZero(O);
		wasm.edPointAdd(R, P, O);
		expect(wasm.edPointEqual(R, P)).toBe(1);
	});

	it('inverse P - P = O', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0xA5A5_0002);
		const P = testSlot(0);
		const O = testSlot(160);
		const R = testSlot(320);
		makePoint(P, rng);
		wasm.edPointSub(R, P, P);
		wasm.edPointZero(O);
		expect(wasm.edPointEqual(R, O)).toBe(1);
	});

	it('abelian P + Q = Q + P', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0xA5A5_0003);
		const P  = testSlot(0);
		const Q  = testSlot(160);
		const PQ = testSlot(320);
		const QP = testSlot(480);
		makePoint(P, rng);
		makePoint(Q, rng);
		wasm.edPointAdd(PQ, P, Q);
		wasm.edPointAdd(QP, Q, P);
		expect(wasm.edPointEqual(PQ, QP)).toBe(1);
	});

	it('double matches add: 2P = P + P', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0xA5A5_0004);
		const P    = testSlot(0);
		const Pdbl = testSlot(160);
		const PpP  = testSlot(320);
		makePoint(P, rng);
		wasm.edPointDouble(Pdbl, P);
		wasm.edPointAdd(PpP, P, P);
		expect(wasm.edPointEqual(Pdbl, PpP)).toBe(1);
	});

	it('curve membership: every derived point passes edPointOnCurve', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0xA5A5_0005);
		const P = testSlot(0);
		// Test the basepoint, identity, and 8 derived points.
		wasm.edPointBasepoint(P);
		expect(wasm.edPointOnCurve(P)).toBe(1);
		wasm.edPointZero(P);
		expect(wasm.edPointOnCurve(P)).toBe(1);
		for (let i = 0; i < 8; i++) {
			makePoint(P, rng);
			expect(wasm.edPointOnCurve(P)).toBe(1);
		}
	});

	it('compression round-trip: decompress(compress(P)) = P', () => {
		wasm.wipeBuffers();
		const rng = new RNG(0xA5A5_0006);
		const P      = testSlot(0);
		const enc    = testSlot(160);   // 32 bytes
		const Pback  = testSlot(192);   // 160-byte decompressed point

		// Test basepoint and 8 random derived points.
		wasm.edPointBasepoint(P);
		wasm.edPointCompress(enc, P);
		expect(wasm.edPointDecompress(Pback, enc)).toBe(1);
		expect(wasm.edPointEqual(Pback, P)).toBe(1);

		for (let i = 0; i < 8; i++) {
			makePoint(P, rng);
			wasm.edPointCompress(enc, P);
			const ok = wasm.edPointDecompress(Pback, enc);
			expect(ok).toBe(1);
			expect(wasm.edPointEqual(Pback, P)).toBe(1);
		}
	});

	it('decompression rejects non-curve points', () => {
		wasm.wipeBuffers();
		const enc   = testSlot(0);
		const Pback = testSlot(32);

		// Construct an encoded point whose y satisfies (y^2 - 1)/(d*y^2 + 1)
		// is a quadratic non-residue. The simplest such case: y = 0 gives
		// x^2 = (0-1)/(0+1) = -1, and -1 is a square mod p (sqrt(-1) exists),
		// so y=0 actually decodes successfully. y = 2 gives x^2 = 3/(4d+1);
		// most random encodings hit the non-residue case.
		//
		// Approach: try several deterministic byte strings, expect at least
		// some to be rejected. We assert that at least one is rejected.
		const rng = new RNG(0xA5A5_0007);
		let rejectCount = 0;
		for (let trial = 0; trial < 32; trial++) {
			const bytes = rng.bytes(32);
			// Clear bit 7 of byte 31 to avoid trivial canonicality fails on
			// large y; we want the non-residue path to fire.
			bytes[31] &= 0x7F;
			writeBytes(wasm.memory, enc, bytes);
			const ok = wasm.edPointDecompress(Pback, enc);
			if (ok === 0) rejectCount++;
		}
		// Roughly half of random y values yield non-residue. With 32 trials
		// we expect at least 8 rejections in any reasonable seed; assert > 0.
		expect(rejectCount).toBeGreaterThan(0);
	});
});
