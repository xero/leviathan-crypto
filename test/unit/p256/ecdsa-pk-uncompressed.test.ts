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
 * ECDSA-P256 uncompressed-pk surface tests.
 *
 * Exercises the SEC 1 §2.3.4 uncompressed encoding path: the
 * `pointDecompress` free function in `src/ts/ecdsa/index.ts` and the
 * `EcdsaP256.keygenUncompressed` keygen variant. The substrate's
 * `pointDecompress` WASM export is itself gated upstream by
 * `test/unit/p256/gate.test.ts` (compress / decompress round-trip on G);
 * this file gates the TS-layer wrapper plus the SEC 1 §2.3.3 ↔ §2.3.4
 * round-trip and contract-violation throws.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init, EcdsaP256, SigningError,
	hexToBytes, bytesToHex,
} from '../../../src/ts/index.js';
import { pointDecompress } from '../../../src/ts/ecdsa/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { RFC6979_P256_KEY } from '../../vectors/ecdsa_p256.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

// RFC 6979 §A.2.5 keypair, used as a known-answer vector for the
// SEC 1 §2.3.3 ↔ §2.3.4 conversion. The published (Ux, Uy) is the
// authority for the uncompressed encoding; the compressed form's
// prefix follows from the parity of Uy.
const RFC_X_HEX  = RFC6979_P256_KEY.uxHex.toLowerCase();
const RFC_Y_HEX  = RFC6979_P256_KEY.uyHex.toLowerCase();
const RFC_PK_COMPRESSED_HEX   = '03' + RFC_X_HEX;            // y ends in 0x99 (odd)
const RFC_PK_UNCOMPRESSED_HEX = '04' + RFC_X_HEX + RFC_Y_HEX;

// P-256 field prime and curve `b` constant per SP 800-186 §3.2.1.3
// (P-256). Used in the test setup to deterministically locate an
// x value with no on-curve y, exercising the substrate's
// non-quadratic-residue rejection path.
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

// Euler's criterion: a is a QR mod p iff a^((p-1)/2) ≡ 1 (mod p) for
// odd prime p. Used to find an x where y² = x³ - 3x + b is a
// non-residue, i.e. an off-curve x for the SEC 1 §2.3.4 decoder
// rejection test.
function isQuadraticResidue(a: bigint): boolean {
	if (a === 0n) return true;
	return modPow(a, (P256_P - 1n) / 2n, P256_P) === 1n;
}

function bigIntToBE32(x: bigint): Uint8Array {
	const hex = x.toString(16).padStart(64, '0');
	if (hex.length !== 64) throw new Error(`bigIntToBE32 overflow: ${hex.length}`);
	return hexToBytes(hex);
}

function findOffCurveX(): Uint8Array {
	// Brute force from x = 1; with ~50% on-curve density, the search
	// terminates well within the first few candidates.
	for (let i = 1n; i < 1000n; i++) {
		const ySq = (((i * i * i) - 3n * i + P256_B) % P256_P + P256_P) % P256_P;
		if (!isQuadraticResidue(ySq)) return bigIntToBE32(i);
	}
	throw new Error('off-curve x search exhausted (unexpected)');
}

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/p256.wasm'));
	await init({ p256: wasmBytes });
});

describe('pointDecompress: free function', () => {
	it('decompresses RFC 6979 §A.2.5 compressed pk to the published uncompressed (Ux, Uy)', () => {
		const compressed = hexToBytes(RFC_PK_COMPRESSED_HEX);
		const out = pointDecompress(compressed);
		expect(out.length).toBe(65);
		expect(out[0]).toBe(0x04);
		expect(bytesToHex(out)).toBe(RFC_PK_UNCOMPRESSED_HEX);
		// X half of the uncompressed output matches the compressed
		// input's bytes [1..33).
		expect(bytesToHex(out.subarray(1, 33))).toBe(bytesToHex(compressed.subarray(1, 33)));
	});

	it('round-trips compressed → uncompressed → re-compressed for the RFC vector', () => {
		const compressed = hexToBytes(RFC_PK_COMPRESSED_HEX);
		const uncompressed = pointDecompress(compressed);
		// Re-compress by reading the parity of y[63] and prepending
		// the 0x02/0x03 prefix to the X bytes. This is SEC 1 §2.3.3
		// in reverse.
		const yParity = uncompressed[64] & 0x01;
		const recompressed = new Uint8Array(33);
		recompressed[0] = 0x02 | yParity;
		recompressed.set(uncompressed.subarray(1, 33), 1);
		expect(bytesToHex(recompressed)).toBe(bytesToHex(compressed));
	});

	it('round-trips for both prefix parities (0x02 and 0x03)', () => {
		// Start from the RFC vector (prefix 0x03 because y is odd).
		const origCompressed = hexToBytes(RFC_PK_COMPRESSED_HEX);
		const origUncompressed = pointDecompress(origCompressed);

		// Flip the parity by negating y. y' = p - y is the other
		// root of y² = x³ - 3x + b; the resulting (x, y') is on the
		// curve too and its compressed prefix is the opposite parity.
		const y = BigInt('0x' + bytesToHex(origUncompressed.subarray(33, 65)));
		const yNeg = (P256_P - y) % P256_P;
		const yNegBytes = bigIntToBE32(yNeg);
		const flippedPrefix = origCompressed[0] === 0x02 ? 0x03 : 0x02;
		const flippedCompressed = new Uint8Array(33);
		flippedCompressed[0] = flippedPrefix;
		flippedCompressed.set(origCompressed.subarray(1, 33), 1);

		const flippedUncompressed = pointDecompress(flippedCompressed);
		expect(flippedUncompressed[0]).toBe(0x04);
		// X half unchanged.
		expect(bytesToHex(flippedUncompressed.subarray(1, 33)))
			.toBe(bytesToHex(origUncompressed.subarray(1, 33)));
		// Y half is the negated y.
		expect(bytesToHex(flippedUncompressed.subarray(33, 65))).toBe(bytesToHex(yNegBytes));
	});

	it('rejects 33-byte input with prefix byte not in {0x02, 0x03}', () => {
		const bad = hexToBytes(RFC_PK_COMPRESSED_HEX);
		bad[0] = 0x04;  // uncompressed-prefix value on a 33-byte input
		expect(() => pointDecompress(bad)).toThrow(SigningError);
		bad[0] = 0x00;
		expect(() => pointDecompress(bad)).toThrow(SigningError);
		bad[0] = 0xFF;
		expect(() => pointDecompress(bad)).toThrow(SigningError);
	});

	it('rejects an off-curve x with SigningError', () => {
		const xOff = findOffCurveX();
		const compressed = new Uint8Array(33);
		compressed[0] = 0x02;
		compressed.set(xOff, 1);
		expect(() => pointDecompress(compressed)).toThrow(SigningError);
		// The other parity prefix also rejects (same x, same
		// non-residue y²).
		compressed[0] = 0x03;
		expect(() => pointDecompress(compressed)).toThrow(SigningError);
	});

	it('rejects wrong-length input with RangeError', () => {
		expect(() => pointDecompress(new Uint8Array(32))).toThrow(RangeError);
		expect(() => pointDecompress(new Uint8Array(34))).toThrow(RangeError);
		expect(() => pointDecompress(new Uint8Array(65))).toThrow(RangeError);
	});

	it('rejects non-Uint8Array input with TypeError', () => {
		// Cast through unknown so the TypeError fires inside the
		// runtime check rather than at the TS-compile boundary.
		expect(() => pointDecompress('not bytes' as unknown as Uint8Array)).toThrow(TypeError);
		expect(() => pointDecompress(null as unknown as Uint8Array)).toThrow(TypeError);
	});
});

describe('EcdsaP256.keygenUncompressed', () => {
	it('returns 65-byte pk with 0x04 prefix and 32-byte sk', () => {
		const ec = new EcdsaP256();
		try {
			const { publicKey, secretKey } = ec.keygenUncompressed();
			expect(publicKey).toBeInstanceOf(Uint8Array);
			expect(secretKey).toBeInstanceOf(Uint8Array);
			expect(publicKey.length).toBe(65);
			expect(secretKey.length).toBe(32);
			expect(publicKey[0]).toBe(0x04);
		} finally {
			ec.dispose();
		}
	});

	it('uncompressed pk X coordinate equals the compressed pk X coordinate from keygen', () => {
		// Drive both keygen variants with the same seed and assert
		// X-byte equality between the two pk encodings.
		const ec = new EcdsaP256();
		try {
			const seed = hexToBytes(RFC6979_P256_KEY.xHex);
			const compressed = ec.keygenDerand(seed);
			const uncompressed = ec.keygenUncompressed(seed);
			expect(bytesToHex(compressed.publicKey.subarray(1, 33)))
				.toBe(bytesToHex(uncompressed.publicKey.subarray(1, 33)));
			// secretKeys are byte-equal too (both derived from the
			// same seed).
			expect(bytesToHex(compressed.secretKey)).toBe(bytesToHex(uncompressed.secretKey));
		} finally {
			ec.dispose();
		}
	});

	it('reproduces the RFC 6979 §A.2.5 (Ux, Uy) when seeded with the §A.2.5 x', () => {
		const ec = new EcdsaP256();
		try {
			const seed = hexToBytes(RFC6979_P256_KEY.xHex);
			const { publicKey, secretKey } = ec.keygenUncompressed(seed);
			expect(bytesToHex(publicKey)).toBe(RFC_PK_UNCOMPRESSED_HEX);
			expect(bytesToHex(secretKey)).toBe(RFC6979_P256_KEY.xHex.toLowerCase());
		} finally {
			ec.dispose();
		}
	});

	it('seedless keygenUncompressed returns a fresh pk on every call', () => {
		const ec = new EcdsaP256();
		try {
			const a = ec.keygenUncompressed();
			const b = ec.keygenUncompressed();
			expect(a.publicKey.length).toBe(65);
			expect(b.publicKey.length).toBe(65);
			// Two random keygens must differ (catches a constant-seed
			// bug in the uncompressed path).
			expect(bytesToHex(a.secretKey)).not.toBe(bytesToHex(b.secretKey));
			expect(bytesToHex(a.publicKey)).not.toBe(bytesToHex(b.publicKey));
		} finally {
			ec.dispose();
		}
	});

	it('keygenUncompressed pk verifies under EcdsaP256.verify (accepts 65-byte form)', async () => {
		// Pull sha2 in for the digest leg.
		const sha2Bytes = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
		await init({ sha2: sha2Bytes });
		const ec = new EcdsaP256();
		try {
			const { publicKey, secretKey } = ec.keygenUncompressed();
			// Sign with the 65-byte pk: validatePublicKey accepts
			// both lengths, the wrapper normalises internally.
			const msgHash = new Uint8Array(32);
			msgHash.fill(0xaa);
			const sig = ec.sign(secretKey, publicKey, msgHash, new Uint8Array(32));
			expect(ec.verify(publicKey, msgHash, sig)).toBe(true);
		} finally {
			ec.dispose();
		}
	});
});
