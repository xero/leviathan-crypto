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
 * ECDSA-P256 ECPrivateKey DER codec tests.
 *
 * Round-trip + strict-DER rejection cases for `encodeEcPrivateKey` and
 * `decodeEcPrivateKey` per RFC 5915 §3, ECPrivateKey, and X.690 §10,
 * DER restrictions. The encoder produces a byte-stable 51-byte form;
 * the decoder accepts any conforming RFC 5915 ECPrivateKey for P-256
 * (with optional publicKey [1] tolerated and ignored) and rejects
 * every documented DER syntax violation.
 *
 * Expected encoded bytes are derived from the RFC 5915 §3 structure
 * shape and the secp256r1 named-curve OID (1.2.840.10045.3.1.7,
 * SP 800-186 §3.2.1.3); each test case spells the expected hex
 * verbatim so a reader can compare byte-for-byte against the spec
 * without running the implementation.
 */
import { describe, it, expect } from 'vitest';
import { hexToBytes, bytesToHex } from '../../../src/ts/index.js';
import { encodeEcPrivateKey, decodeEcPrivateKey } from '../../../src/ts/ecdsa/index.js';
import { RFC6979_P256_KEY } from '../../vectors/ecdsa_p256.js';

// xorshift32: deterministic, repeatable test inputs. Not crypto-safe.
function rng(seed: number): () => number {
	let s = seed | 1;
	return () => {
		s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
		return s >>> 0;
	};
}

function randomScalar(seed: number): Uint8Array {
	const next = rng(seed);
	const out = new Uint8Array(32);
	for (let i = 0; i < 32; i++) out[i] = next() & 0xff;
	return out;
}

// Expected DER bytes for the RFC 6979 §A.2.5 scalar:
//
//   30 31                             SEQUENCE, 49 content bytes
//   02 01 01                          INTEGER, version = 1
//   04 20 <32 bytes scalar>           OCTET STRING, 32 bytes
//   A0 0A                             [0] EXPLICIT, 10 content bytes
//   06 08 2A 86 48 CE 3D 03 01 07     OBJECT IDENTIFIER, secp256r1
//
// Total 51 bytes.
const RFC_SCALAR_HEX = RFC6979_P256_KEY.xHex.toLowerCase();
const RFC_DER_HEX =
	'3031020101'
	+ '0420' + RFC_SCALAR_HEX
	+ 'a00a06082a8648ce3d030107';

describe('encodeEcPrivateKey', () => {
	it('encodes the RFC 6979 §A.2.5 scalar to the 51-byte DER form', () => {
		const scalar = hexToBytes(RFC_SCALAR_HEX);
		const der = encodeEcPrivateKey(scalar);
		expect(der.length).toBe(51);
		expect(bytesToHex(der)).toBe(RFC_DER_HEX);
	});

	it('always emits the exact 51-byte shape regardless of scalar content', () => {
		// Scalars whose bytes are all 0x00 or all 0xff still emit the
		// same length (no leading-zero stripping or sign-pad logic;
		// OCTET STRING content is the raw scalar verbatim).
		const allZero = new Uint8Array(32);  // not valid as a P-256 sk but a valid OCTET STRING
		const allOnes = new Uint8Array(32); allOnes.fill(0xff);
		expect(encodeEcPrivateKey(allZero).length).toBe(51);
		expect(encodeEcPrivateKey(allOnes).length).toBe(51);
		// Byte-stable: same scalar → same DER bytes.
		const a = encodeEcPrivateKey(allZero);
		const b = encodeEcPrivateKey(allZero);
		expect(bytesToHex(a)).toBe(bytesToHex(b));
	});

	it('embeds the secp256r1 OID at offsets 41..51', () => {
		const der = encodeEcPrivateKey(new Uint8Array(32));
		// X.690 §8.19 collapses 1.2 → 0x2A; 840=0x8648, 10045=0xCE3D,
		// then 3, 1, 7. The full TLV is 06 08 2A 86 48 CE 3D 03 01 07.
		expect(bytesToHex(der.subarray(41, 51))).toBe('06082a8648ce3d030107');
	});

	it('rejects non-Uint8Array input with TypeError', () => {
		expect(() => encodeEcPrivateKey('not bytes' as unknown as Uint8Array)).toThrow(TypeError);
		expect(() => encodeEcPrivateKey(null as unknown as Uint8Array)).toThrow(TypeError);
	});

	it('rejects wrong-length input with RangeError', () => {
		expect(() => encodeEcPrivateKey(new Uint8Array(31))).toThrow(RangeError);
		expect(() => encodeEcPrivateKey(new Uint8Array(33))).toThrow(RangeError);
		expect(() => encodeEcPrivateKey(new Uint8Array(0))).toThrow(RangeError);
	});
});

describe('decodeEcPrivateKey: round-trip', () => {
	it('decodes the encoder output back to the input scalar', () => {
		const scalar = hexToBytes(RFC_SCALAR_HEX);
		const der = encodeEcPrivateKey(scalar);
		const back = decodeEcPrivateKey(der);
		expect(bytesToHex(back)).toBe(RFC_SCALAR_HEX);
	});

	it('round-trips on 100 deterministic random scalars', () => {
		for (let s = 1; s <= 100; s++) {
			const scalar = randomScalar(s * 0xdeadbeef);
			const der = encodeEcPrivateKey(scalar);
			const back = decodeEcPrivateKey(der);
			expect(bytesToHex(back)).toBe(bytesToHex(scalar));
		}
	});

	it('decodes the spec-shape DER directly (without going through the encoder)', () => {
		const der = hexToBytes(RFC_DER_HEX);
		const back = decodeEcPrivateKey(der);
		expect(bytesToHex(back)).toBe(RFC_SCALAR_HEX);
	});
});

describe('decodeEcPrivateKey: optional publicKey [1] tolerance', () => {
	it('accepts a DER blob with the optional publicKey [1] field present', () => {
		// Construct a DER blob with parameters [0] AND publicKey [1]:
		//
		//   30 <seqLen>
		//   02 01 01
		//   04 20 <32 bytes scalar>
		//   A0 0A 06 08 2A 86 48 CE 3D 03 01 07
		//   A1 44 03 42 00 04 <32 bytes Ux> <32 bytes Uy>
		//
		// publicKey [1] EXPLICIT wraps a BIT STRING; the BIT STRING
		// contains the leading 0x00 "unused bits" octet followed by
		// the SEC 1 §2.3.4 uncompressed 65-byte point.
		const scalarHex = RFC_SCALAR_HEX;
		const xHex = RFC6979_P256_KEY.uxHex.toLowerCase();
		const yHex = RFC6979_P256_KEY.uyHex.toLowerCase();
		const inner =
			'020101'                          // version
			+ '0420' + scalarHex              // privateKey
			+ 'a00a06082a8648ce3d030107'      // parameters [0]
			+ 'a14403420004' + xHex + yHex;   // publicKey [1] EXPLICIT
		// inner.length / 2 = 3 + 34 + 12 + 70 = 119 content bytes
		const seqLen = inner.length / 2;
		expect(seqLen).toBe(119);
		// SEQUENCE content is 119 bytes (< 128) so short-form length
		// remains valid; encoded length byte = 0x77.
		const derHex = '30' + seqLen.toString(16).padStart(2, '0') + inner;
		const back = decodeEcPrivateKey(hexToBytes(derHex));
		expect(bytesToHex(back)).toBe(scalarHex);
	});

	it('accepts a DER blob without the optional parameters [0] field', () => {
		// Per RFC 5915 §3, parameters is OPTIONAL. A minimal valid
		// ECPrivateKey is: SEQUENCE(version, privateKey) = 39 bytes
		// total.
		const scalarHex = RFC_SCALAR_HEX;
		const inner = '020101' + '0420' + scalarHex;   // 3 + 34 = 37 content bytes
		const seqLen = inner.length / 2;
		expect(seqLen).toBe(37);
		const derHex = '30' + seqLen.toString(16).padStart(2, '0') + inner;
		const back = decodeEcPrivateKey(hexToBytes(derHex));
		expect(bytesToHex(back)).toBe(scalarHex);
	});
});

describe('decodeEcPrivateKey: strict-DER rejections', () => {
	it('rejects non-Uint8Array input with TypeError', () => {
		expect(() => decodeEcPrivateKey('not bytes' as unknown as Uint8Array)).toThrow(TypeError);
		expect(() => decodeEcPrivateKey(null as unknown as Uint8Array)).toThrow(TypeError);
	});

	it('rejects an input shorter than the 7-byte minimum', () => {
		expect(() => decodeEcPrivateKey(new Uint8Array(6))).toThrow(/shorter than the 7-byte minimum/);
		expect(() => decodeEcPrivateKey(new Uint8Array(0))).toThrow(/shorter than the 7-byte minimum/);
	});

	it('rejects wrong outer tag (not 0x30 SEQUENCE)', () => {
		const der = hexToBytes(RFC_DER_HEX);
		der[0] = 0x31;  // SET, not SEQUENCE
		expect(() => decodeEcPrivateKey(der)).toThrow(/outer tag.*expected 0x30/);
	});

	it('rejects long-form length encoding on the outer SEQUENCE', () => {
		// Replace the short-form `30 31 ...` (49 content bytes) with
		// a long-form `30 81 31 ...` (one length octet 0x31 = 49,
		// announced via the 0x81 = "one length-byte follows").
		// Long-form is forbidden for content < 128 bytes per X.690
		// §10.1.
		const longForm = new Uint8Array(52);
		longForm[0] = 0x30;
		longForm[1] = 0x81;
		longForm[2] = 0x31;
		longForm.set(hexToBytes(RFC_DER_HEX).subarray(2), 3);
		expect(() => decodeEcPrivateKey(longForm)).toThrow(/long-form length encoding/);
	});

	it('rejects SEQUENCE length that does not match input size', () => {
		const der = hexToBytes(RFC_DER_HEX);
		der[1] = 0x30;  // declared content 48, actual 49 (trailing byte)
		expect(() => decodeEcPrivateKey(der)).toThrow(/does not match input size/);
	});

	it('rejects wrong version tag (not 0x02 INTEGER)', () => {
		const der = hexToBytes(RFC_DER_HEX);
		der[2] = 0x04;  // OCTET STRING tag
		expect(() => decodeEcPrivateKey(der)).toThrow(/version tag.*expected 0x02/);
	});

	it('rejects version length other than 1', () => {
		const der = hexToBytes(RFC_DER_HEX);
		der[3] = 0x02;  // INTEGER length 2 (non-minimal encoding of value 1)
		expect(() => decodeEcPrivateKey(der)).toThrow(/version length/);
	});

	it('rejects version value other than 1', () => {
		const der = hexToBytes(RFC_DER_HEX);
		der[4] = 0x00;  // version = 0 (FIPS 186-5 ECDSA does not define v0)
		expect(() => decodeEcPrivateKey(der)).toThrow(/version value.*expected 1/);
	});

	it('rejects wrong privateKey tag (not 0x04 OCTET STRING)', () => {
		const der = hexToBytes(RFC_DER_HEX);
		der[5] = 0x02;  // INTEGER tag
		expect(() => decodeEcPrivateKey(der)).toThrow(/privateKey tag.*expected 0x04/);
	});

	it('rejects privateKey OCTET STRING length other than 32 (P-256 scalar size)', () => {
		// Reconstruct DER with privateKey length 0x10 (16 bytes) instead
		// of 0x20 (32 bytes). The SEQUENCE length still has to add up
		// to a self-consistent structure, so build it from scratch.
		const inner =
			'020101'
			+ '0410' + '00'.repeat(16)        // wrong-length OCTET STRING
			+ 'a00a06082a8648ce3d030107';
		const seqLen = inner.length / 2;
		const derHex = '30' + seqLen.toString(16).padStart(2, '0') + inner;
		expect(() => decodeEcPrivateKey(hexToBytes(derHex)))
			.toThrow(/privateKey OCTET STRING length.*expected 32/);
	});

	it('rejects long-form length encoding on the privateKey OCTET STRING', () => {
		// Build a DER where the privateKey OCTET STRING length octet
		// uses long-form `81 20` instead of short-form `20`.
		const inner =
			'020101'
			+ '048120' + RFC_SCALAR_HEX
			+ 'a00a06082a8648ce3d030107';
		const seqLen = inner.length / 2;
		const derHex = '30' + seqLen.toString(16).padStart(2, '0') + inner;
		expect(() => decodeEcPrivateKey(hexToBytes(derHex)))
			.toThrow(/privateKey OCTET STRING.*long-form length encoding/);
	});

	it('rejects parameters [0] containing an OID other than secp256r1', () => {
		// Build a DER with the secp384r1 OID (1.3.132.0.34) inside
		// parameters [0]. DER for that OID is 06 05 2B 81 04 00 22.
		const inner =
			'020101'
			+ '0420' + RFC_SCALAR_HEX
			+ 'a007' + '06052b81040022';  // secp384r1, 7-byte content
		const seqLen = inner.length / 2;
		const derHex = '30' + seqLen.toString(16).padStart(2, '0') + inner;
		expect(() => decodeEcPrivateKey(hexToBytes(derHex)))
			.toThrow(/parameters \[0\] content is 7 bytes, expected 10/);
	});

	it('rejects parameters [0] containing a same-length non-secp256r1 OID', () => {
		// secp256k1 OID is 1.3.132.0.10 (DER: 06 05 2B 81 04 00 0A,
		// 7 bytes). Pad it to 10 bytes via a fake OID to hit the
		// content-match check rather than the length check.
		const inner =
			'020101'
			+ '0420' + RFC_SCALAR_HEX
			+ 'a00a06082a8648ce3d03010f';  // last byte 0F instead of 07
		const seqLen = inner.length / 2;
		const derHex = '30' + seqLen.toString(16).padStart(2, '0') + inner;
		expect(() => decodeEcPrivateKey(hexToBytes(derHex)))
			.toThrow(/parameters \[0\] OID does not match secp256r1/);
	});

	it('rejects long-form length encoding on parameters [0]', () => {
		const inner =
			'020101'
			+ '0420' + RFC_SCALAR_HEX
			+ 'a0810a06082a8648ce3d030107';
		const seqLen = inner.length / 2;
		const derHex = '30' + seqLen.toString(16).padStart(2, '0') + inner;
		expect(() => decodeEcPrivateKey(hexToBytes(derHex)))
			.toThrow(/parameters \[0\].*long-form length encoding/);
	});

	it('rejects trailing bytes after the optional fields', () => {
		// Append a stray byte after the well-formed DER and bump
		// the SEQUENCE length so the parser accepts the outer
		// length but then fails on the trailing-bytes check after
		// consuming the known fields.
		const inner =
			'020101'
			+ '0420' + RFC_SCALAR_HEX
			+ 'a00a06082a8648ce3d030107'
			+ '99';   // garbage trailing byte after parameters [0]
		const seqLen = inner.length / 2;
		const derHex = '30' + seqLen.toString(16).padStart(2, '0') + inner;
		expect(() => decodeEcPrivateKey(hexToBytes(derHex)))
			.toThrow(/trailing byte/);
	});

	it('rejects truncated privateKey content that extends past SEQUENCE end', () => {
		// SEQUENCE length advertises 7 content bytes (version 3 +
		// OCTET STRING TLV header 2 + privateKey content claimed 32
		// = doesn't fit). Construct a SEQUENCE that says "40 bytes"
		// but the OCTET STRING claims to be 32 bytes when only 5 of
		// those bytes are actually present before the SEQUENCE ends.
		const derHex =
			'30' + '0a'           // SEQUENCE, 10 bytes content
			+ '020101'             // version
			+ '0420' + '0001020304';  // OCTET STRING claims 32 bytes, but only 5 follow
		// Total length 12 bytes; SEQUENCE says 10 bytes content;
		// privateKey claims 32 bytes but only 5 fit. Expect rejection.
		expect(() => decodeEcPrivateKey(hexToBytes(derHex)))
			.toThrow(/privateKey OCTET STRING.*past the outer SEQUENCE end/);
	});
});
