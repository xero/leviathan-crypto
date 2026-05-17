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
 * ECDSA-P256 DER ↔ raw signature codec tests.
 *
 * Round-trip + strict-DER rejection cases for `ecdsaSignatureToDer` and
 * `ecdsaSignatureFromDer` per RFC 3279 §2.2.3, ECDSA Signature
 * Algorithm. Each malformed-input case asserts `SigningError` with
 * discriminator `'sig-malformed-input'`. Implementation is hand-rolled
 * against X.690 §8.3 (INTEGER) and §8.9 (SEQUENCE); the rejection
 * surface here doubles as a spec-fence on the strict-DER posture.
 */
import { describe, it, expect } from 'vitest';
import {
	ecdsaSignatureToDer, ecdsaSignatureFromDer,
	SigningError,
	hexToBytes, bytesToHex,
} from '../../../src/ts/index.js';

function rawSig(rHex: string, sHex: string): Uint8Array {
	const out = new Uint8Array(64);
	out.set(hexToBytes(rHex.padStart(64, '0')), 0);
	out.set(hexToBytes(sHex.padStart(64, '0')), 32);
	return out;
}

// xorshift32: deterministic, repeatable test inputs. Not crypto-safe.
function rng(seed: number): () => number {
	let s = seed | 1;
	return () => {
		s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
		return s >>> 0;
	};
}

function randomScalarHex(seed: number): string {
	const next = rng(seed);
	let hex = '';
	for (let i = 0; i < 32; i++) hex += (next() & 0xff).toString(16).padStart(2, '0');
	return hex;
}

describe('ecdsaSignatureToDer / ecdsaSignatureFromDer round-trip', () => {
	it('round-trips 4 deterministic random r||s inputs', () => {
		for (let s = 1; s <= 4; s++) {
			const r = randomScalarHex(s * 0x1337);
			const ss = randomScalarHex(s * 0xc0de);
			const raw = rawSig(r, ss);
			const der = ecdsaSignatureToDer(raw);
			const back = ecdsaSignatureFromDer(der);
			expect(bytesToHex(back)).toBe(bytesToHex(raw));
		}
	});

	it('pads back to 32 bytes when r has leading zeros (e.g. r = 0x...0001)', () => {
		const raw = rawSig('1', '01' + 'ff'.repeat(31));
		const der = ecdsaSignatureToDer(raw);
		// r = 1 encodes as 0x02 0x01 0x01 (3 bytes), no leading-zero pad.
		expect(der[2]).toBe(0x02);
		expect(der[3]).toBe(0x01);
		expect(der[4]).toBe(0x01);
		const back = ecdsaSignatureFromDer(der);
		expect(bytesToHex(back)).toBe(bytesToHex(raw));
	});

	it('prepends a 0x00 sign-pad when r or s has its leading-byte high bit set', () => {
		// r = 0x80....00 (high bit set), s = 0xff...ff (high bit set)
		const raw = rawSig('80' + '00'.repeat(31), 'ff'.repeat(32));
		const der = ecdsaSignatureToDer(raw);
		// SEQUENCE header
		expect(der[0]).toBe(0x30);
		// r INTEGER: tag 0x02, length 0x21 (33), content starts 0x00 0x80...
		expect(der[2]).toBe(0x02);
		expect(der[3]).toBe(0x21);
		expect(der[4]).toBe(0x00);
		expect(der[5]).toBe(0x80);
		// s INTEGER: also 33-byte content; starts after r (2 + 35 = 37).
		expect(der[37]).toBe(0x02);
		expect(der[38]).toBe(0x21);
		expect(der[39]).toBe(0x00);
		expect(der[40]).toBe(0xff);
		const back = ecdsaSignatureFromDer(der);
		expect(bytesToHex(back)).toBe(bytesToHex(raw));
	});

	it('produces a 72-byte DER for both components 0x80... (longest practical)', () => {
		const raw = rawSig('80' + 'aa'.repeat(31), '80' + 'bb'.repeat(31));
		const der = ecdsaSignatureToDer(raw);
		// 2 (SEQUENCE header) + 2 * (2 + 33) = 72 bytes.
		expect(der.length).toBe(72);
	});

	it('produces an 8-byte DER for r = s = 1 (shortest practical)', () => {
		const raw = rawSig('1', '1');
		const der = ecdsaSignatureToDer(raw);
		// 2 (SEQUENCE) + 2 * (2 + 1) = 8 bytes.
		expect(der.length).toBe(8);
		expect(bytesToHex(der)).toBe('3006020101020101');
		const back = ecdsaSignatureFromDer(der);
		expect(bytesToHex(back)).toBe(bytesToHex(raw));
	});
});

describe('ecdsaSignatureToDer input validation', () => {
	it('rejects non-Uint8Array input with TypeError', () => {
		expect(() => ecdsaSignatureToDer('not bytes' as unknown as Uint8Array)).toThrow(TypeError);
	});

	it('rejects wrong-length input with RangeError (63 and 65)', () => {
		expect(() => ecdsaSignatureToDer(new Uint8Array(63))).toThrow(RangeError);
		expect(() => ecdsaSignatureToDer(new Uint8Array(65))).toThrow(RangeError);
	});
});

// Strict-DER rejection helpers. Each constructs a single malformed
// payload and asserts the SigningError discriminator.
function expectMalformed(der: Uint8Array): void {
	try {
		ecdsaSignatureFromDer(der);
		throw new Error('expected ecdsaSignatureFromDer to throw');
	} catch (e) {
		expect(e).toBeInstanceOf(SigningError);
		expect((e as SigningError).discriminator).toBe('sig-malformed-input');
	}
}

describe('ecdsaSignatureFromDer strict-DER rejection', () => {
	it('rejects non-Uint8Array input with TypeError (not SigningError)', () => {
		expect(() => ecdsaSignatureFromDer('not bytes' as unknown as Uint8Array)).toThrow(TypeError);
	});

	it('rejects truncated input (under 8 bytes)', () => {
		for (const n of [0, 1, 4, 7]) expectMalformed(new Uint8Array(n));
	});

	it('rejects wrong outer tag (not 0x30)', () => {
		// 0x31 0x06 0x02 0x01 0x01 0x02 0x01 0x01: shape valid, tag wrong.
		expectMalformed(hexToBytes('3106020101020101'));
		expectMalformed(hexToBytes('0006020101020101'));
	});

	it('rejects long-form length on the outer SEQUENCE (X.690 §10.1 strict-DER violation)', () => {
		// 0x30 0x81 0x06 ... — long-form when short-form (0x06) would suffice.
		expectMalformed(hexToBytes('3081060201010201010000'));
	});

	it('rejects outer SEQUENCE length not matching input size (trailing bytes)', () => {
		// Valid 8-byte SEQUENCE + 1 trailing byte.
		expectMalformed(hexToBytes('300602010102010100'));
	});

	it('rejects outer SEQUENCE length shorter than input (truncated)', () => {
		// SEQUENCE claims 4 bytes content but input has 6.
		expectMalformed(hexToBytes('3004020101020101'));
	});

	it('rejects mismatched inner tag (not 0x02)', () => {
		// 0x30 0x06 0x03 0x01 0x01 0x02 0x01 0x01: first INTEGER tag is 0x03.
		expectMalformed(hexToBytes('3006030101020101'));
	});

	it('rejects long-form INTEGER length', () => {
		// 0x30 0x07 0x02 0x81 0x01 0x01 0x02 0x01 0x01: r uses long-form 0x81.
		expectMalformed(hexToBytes('3007028101010201 01'.replace(/\s+/g, '')));
	});

	it('rejects zero-length INTEGER content', () => {
		// 0x30 0x05 0x02 0x00 0x02 0x01 0x01: r has zero content.
		expectMalformed(hexToBytes('3005020002 0101'.replace(/\s+/g, '')));
	});

	it('rejects excess leading-zero bytes inside an INTEGER (non-minimal DER)', () => {
		// r encoded as 0x02 0x02 0x00 0x01: the 0x00 is excess (next byte
		// is 0x01, high bit clear) per X.690 §8.3.2.
		expectMalformed(hexToBytes('3007020200010201 01'.replace(/\s+/g, '')));
	});

	it('rejects negative INTEGER (high bit set on first content byte without sign-pad)', () => {
		// r = 0x02 0x01 0x80: a one-byte INTEGER 0x80 is the two's-complement
		// value -128. ECDSA r is positive, reject.
		expectMalformed(hexToBytes('3006020180020101'));
	});

	it('rejects INTEGER content longer than 32 bytes (after sign-pad strip)', () => {
		// r encoded as 34-byte INTEGER (32 + 0x00 sign-pad + one extra byte
		// of garbage). Even after stripping the sign-pad the value is 33
		// bytes long, which exceeds the P-256 scalar size.
		// SEQUENCE length = 2 + 36 + 2 + 1 = 41 (0x29)
		// r: 0x02 0x22 (34) followed by 34 content bytes (0x00 plus 33
		//    bytes starting with 0x80...)
		// s: 0x02 0x01 0x01
		const der = new Uint8Array(2 + 36 + 3);
		der[0] = 0x30;
		der[1] = der.length - 2;
		der[2] = 0x02; der[3] = 0x22;
		der[4] = 0x00; der[5] = 0x80;
		// fill remaining r content
		for (let i = 6; i < 38; i++) der[i] = 0xaa;
		der[38] = 0x02; der[39] = 0x01; der[40] = 0x01;
		expectMalformed(der);
	});

	it('rejects truncated INTEGER (content extends past SEQUENCE)', () => {
		// SEQUENCE length 0x05 but r claims 5 bytes of content followed by
		// only 3 actual bytes, so s INTEGER is missing.
		expectMalformed(hexToBytes('3005020501020304'));
	});

	it('rejects all-zero seven-byte input (not enough for a valid SEQUENCE)', () => {
		expectMalformed(new Uint8Array(7));
	});
});
