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
 * pointDecompress strict x < p canonicality, SEC 1 §2.3.4 + SP 800-186
 * §3.2.1.3 (P-256). feFromBytes is a literal byte loader; without the
 * explicit feIsCanonical gate inserted in pointDecompress, an
 * adversarial wire encoding with x ∈ [p, 2^256) would silently reduce
 * mod p inside the curve-equation feMul / feSqr calls and (for the
 * reducing-to-on-curve case) produce a malleable second encoding for
 * the same logical pk.
 *
 * Surfacing test for the audit item docs/ecdsa-p256_audit.md "Public-
 * key canonicality". The four adversarial shapes below are:
 *
 *   1. trivial overflow (x = 2^256 - 1)
 *   2. boundary             (x = p)
 *   3. reducing to on-curve (x = x_small_valid + p)       ← GATE
 *   4. reducing to off-curve (x = x_off_curve + p)
 *
 * Case 3 is the malleability gap: under the substrate's mod-p
 * arithmetic, pointOnCurve cannot distinguish x_small_valid from
 * x_small_valid + p, so the rejection MUST come from the explicit
 * canonicality gate. The test cross-checks this by calling
 * feIsCanonical directly on the parsed non-canonical x.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadP256, hexToBytes, writeBytes, testSlot,
	type P256Exports,
} from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

// P-256 field prime and curve `b` constant per SP 800-186 §3.2.1.3.
const P256_P = BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF');
const P256_B = BigInt('0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B');

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
	let r = 1n, b = base % mod;
	while (exp > 0n) {
		if (exp & 1n) r = (r * b) % mod;
		b = (b * b) % mod;
		exp >>= 1n;
	}
	return r;
}

// Euler's criterion: a ∈ QR(p) iff a^((p-1)/2) ≡ 1 (mod p) for odd
// prime p. y² is a QR iff a candidate y exists, i.e. x is on the curve.
function isQR(a: bigint): boolean {
	if (a === 0n) return true;
	return modPow(a, (P256_P - 1n) / 2n, P256_P) === 1n;
}

function curveRhs(x: bigint): bigint {
	return (((x * x * x) - 3n * x + P256_B) % P256_P + P256_P) % P256_P;
}

function bigIntToBE32(x: bigint): Uint8Array {
	const hex = x.toString(16).padStart(64, '0');
	if (hex.length !== 64) throw new Error(`bigIntToBE32 overflow: ${hex.length}`);
	return hexToBytes(hex);
}

// Search for the smallest positive on-curve x in [1, gap) where
// gap = 2^256 - p = 2^224 - 2^192 - 2^96 + 1. For any such x, x + p
// fits in 32 bytes (< 2^256) and represents a non-canonical wire
// encoding that reduces to the canonical on-curve x mod p. The
// substrate's mod-p feMul / feSqr therefore yield the SAME y² as the
// canonical encoding; only the explicit feIsCanonical gate can
// distinguish the two.
const GAP = (1n << 256n) - P256_P;

function findSmallOnCurveX(): bigint {
	for (let i = 1n; i < 1000n; i++) {
		if (isQR(curveRhs(i))) return i;
	}
	throw new Error('on-curve x search exhausted');
}

function findSmallOffCurveX(): bigint {
	for (let i = 1n; i < 1000n; i++) {
		if (!isQR(curveRhs(i))) return i;
	}
	throw new Error('off-curve x search exhausted');
}

describe('p256 pointDecompress strict x < p canonicality', () => {
	it('positive control: canonical RFC 6979 §A.2.5 compressed pk decompresses', () => {
		wasm.wipeBuffers();
		// RFC 6979 §A.2.5 pk x; y is odd so the compressed prefix is 0x03.
		const RFC_X_HEX = '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6';
		const pk = hexToBytes('03' + RFC_X_HEX);
		const enc = testSlot(0);
		const out = testSlot(64);
		writeBytes(wasm.memory, enc, pk);
		expect(wasm.pointDecompress(out, enc)).toBe(1);
	});

	it('rejects x = 2^256 - 1 (trivial overflow, all-0xFF bytes)', () => {
		wasm.wipeBuffers();
		const pk = new Uint8Array(33);
		pk[0] = 0x02;
		for (let i = 1; i < 33; i++) pk[i] = 0xff;
		const enc = testSlot(0);
		const out = testSlot(64);
		writeBytes(wasm.memory, enc, pk);
		expect(wasm.pointDecompress(out, enc)).toBe(0);
	});

	it('rejects x = p exactly (boundary)', () => {
		wasm.wipeBuffers();
		const pk = new Uint8Array(33);
		pk[0] = 0x02;
		pk.set(bigIntToBE32(P256_P), 1);
		const enc = testSlot(0);
		const out = testSlot(64);
		writeBytes(wasm.memory, enc, pk);
		expect(wasm.pointDecompress(out, enc)).toBe(0);
	});

	// GATE: the malleability case. Without the explicit feIsCanonical
	// gate inserted in pointDecompress, the substrate's mod-p arithmetic
	// would accept x_valid + p as a second encoding of the canonical
	// pk at x_valid.
	it('rejects x = x_valid + p (reducing to on-curve, malleability gap)', () => {
		wasm.wipeBuffers();
		const xValid = findSmallOnCurveX();
		expect(xValid).toBeGreaterThan(0n);
		expect(xValid).toBeLessThan(GAP);  // x_valid + p must fit in 32 bytes

		const xAttack = xValid + P256_P;
		expect(xAttack).toBeLessThan(1n << 256n);

		const pk = new Uint8Array(33);
		pk.set(bigIntToBE32(xAttack), 1);
		const enc = testSlot(0);
		const out = testSlot(64);

		// Both prefixes must reject; rejection fires at feIsCanonical,
		// upstream of the prefix-consuming curve equation.
		for (const prefix of [0x02, 0x03]) {
			pk[0] = prefix;
			writeBytes(wasm.memory, enc, pk);
			expect(wasm.pointDecompress(out, enc)).toBe(0);
		}

		// Cross-check: the substrate's feIsCanonical, called directly on
		// the parsed non-canonical x, must return 0. This proves the
		// rejection in pointDecompress fired at the explicit gate, not
		// downstream at pointOnCurve. The pointOnCurve indirect catch
		// CANNOT distinguish x_valid from x_valid + p because every
		// feMul / feSqr in the curve-equation evaluation reduces mod p.
		const xFE      = testSlot(128);
		const xRawBuf  = testSlot(192);
		writeBytes(wasm.memory, xRawBuf, bigIntToBE32(xAttack));
		wasm.feFromBytes(xFE, xRawBuf);
		expect(wasm.feIsCanonical(xFE)).toBe(0);

		// And feIsCanonical on the canonical encoding is 1 — sanity.
		const xValidFE  = testSlot(256);
		const xValidBuf = testSlot(320);
		writeBytes(wasm.memory, xValidBuf, bigIntToBE32(xValid));
		wasm.feFromBytes(xValidFE, xValidBuf);
		expect(wasm.feIsCanonical(xValidFE)).toBe(1);
	});

	it('rejects x = x_off_curve + p (reducing to off-curve)', () => {
		wasm.wipeBuffers();
		const xOff = findSmallOffCurveX();
		expect(xOff).toBeGreaterThan(0n);
		expect(xOff).toBeLessThan(GAP);

		const xAttack = xOff + P256_P;
		expect(xAttack).toBeLessThan(1n << 256n);

		const pk = new Uint8Array(33);
		pk[0] = 0x02;
		pk.set(bigIntToBE32(xAttack), 1);

		const enc = testSlot(0);
		const out = testSlot(64);
		writeBytes(wasm.memory, enc, pk);
		expect(wasm.pointDecompress(out, enc)).toBe(0);
	});
});
