//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//
/**
 * RCB-complete-addition invariants over P-256 projective coords.
 *   - P + O == P, O + P == P
 *   - P + (-P) == O
 *   - P + Q == Q + P
 *   - 2P == P + P
 *   - pointOnCurve(G) holds, and pointOnCurve(P + Q) holds for any
 *     two on-curve P, Q.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { loadP256, testSlot, type P256Exports } from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

describe('p256 point ops invariants', () => {
	it('P + O == P', () => {
		wasm.wipeBuffers();
		const P = testSlot(0);    // basepoint G
		const O = testSlot(96);
		const out = testSlot(192);
		wasm.pointBasepoint(P);
		wasm.pointZero(O);
		wasm.pointAdd(out, P, O);
		expect(wasm.pointEqual(out, P)).toBe(1);
	});

	it('O + P == P', () => {
		wasm.wipeBuffers();
		const P = testSlot(0);
		const O = testSlot(96);
		const out = testSlot(192);
		wasm.pointBasepoint(P);
		wasm.pointZero(O);
		wasm.pointAdd(out, O, P);
		expect(wasm.pointEqual(out, P)).toBe(1);
	});

	it('P + (-P) == O', () => {
		wasm.wipeBuffers();
		const P = testSlot(0);
		const negP = testSlot(96);
		const out = testSlot(192);
		const O = testSlot(288);
		wasm.pointBasepoint(P);
		wasm.pointNegate(negP, P);
		wasm.pointAdd(out, P, negP);
		wasm.pointZero(O);
		expect(wasm.pointEqual(out, O)).toBe(1);
	});

	it('2P == P + P (pointDouble matches pointAdd self-application)', () => {
		wasm.wipeBuffers();
		const P = testSlot(0);
		const dbl = testSlot(96);
		const sum = testSlot(192);
		wasm.pointBasepoint(P);
		wasm.pointDouble(dbl, P);
		wasm.pointAdd(sum, P, P);
		expect(wasm.pointEqual(dbl, sum)).toBe(1);
	});

	it('P + Q == Q + P (abelian)', () => {
		wasm.wipeBuffers();
		const P = testSlot(0);
		const Q = testSlot(96);
		const pq = testSlot(192);
		const qp = testSlot(288);

		wasm.pointBasepoint(P);
		wasm.pointDouble(Q, P);   // Q = 2G (any other point would work)

		wasm.pointAdd(pq, P, Q);
		wasm.pointAdd(qp, Q, P);

		expect(wasm.pointEqual(pq, qp)).toBe(1);
	});

	it('pointOnCurve holds for G and for 2G + G', () => {
		wasm.wipeBuffers();
		const G = testSlot(0);
		const twoG = testSlot(96);
		const sum = testSlot(192);
		wasm.pointBasepoint(G);
		wasm.pointDouble(twoG, G);
		wasm.pointAdd(sum, twoG, G);

		expect(wasm.pointOnCurve(G)).toBe(1);
		expect(wasm.pointOnCurve(twoG)).toBe(1);
		expect(wasm.pointOnCurve(sum)).toBe(1);
	});

	it('compress/decompress round-trips on 3G', () => {
		wasm.wipeBuffers();
		const G = testSlot(0);
		const threeG = testSlot(96);
		const tmp = testSlot(192);
		const enc = testSlot(288);
		const dec = testSlot(384);

		wasm.pointBasepoint(G);
		wasm.pointDouble(tmp, G);
		wasm.pointAdd(threeG, tmp, G);
		wasm.pointCompress(enc, threeG);
		expect(wasm.pointDecompress(dec, enc)).toBe(1);
		expect(wasm.pointEqual(dec, threeG)).toBe(1);
	});
});
