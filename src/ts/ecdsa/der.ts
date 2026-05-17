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
// src/ts/ecdsa/der.ts
//
// ECDSA signature DER ↔ raw r||s conversion utility, RFC 3279 §2.2.3,
// ECDSA Signature Algorithm.
//
//   Ecdsa-Sig-Value ::= SEQUENCE {
//       r  INTEGER,
//       s  INTEGER
//   }
//
// The library's WASM ABI consumes and produces raw 64-byte r || s
// signatures. DER is a side utility for callers who need X.509 / JWS /
// TLS interop. The encoder / decoder is hand-rolled against X.690 §8.3
// (INTEGER) and §8.9 (SEQUENCE); leviathan-crypto is zero-dependency
// so no external ASN.1 parser is used.
//
// Strict DER (not BER). The decoder rejects:
//   - non-minimal length encodings (long-form length when short-form
//     would suffice; X.690 §10.1, definite-length encoding)
//   - excess leading-zero bytes inside INTEGER content (X.690 §8.3.2)
//   - negative INTEGERs (sign bit set on the leading content octet
//     without a 0x00 sign-pad; ECDSA r, s ∈ [1, n-1] are positive)
//   - INTEGER content longer than 33 bytes (32-byte BE scalar plus an
//     optional 0x00 sign-pad)
//   - trailing bytes after the outer SEQUENCE
//   - wrong tags (outer 0x30 SEQUENCE, inner 0x02 INTEGER)
//
// The from-DER path never throws on a semantic value problem
// (r = 0, s = 0, high-s, off-range); those are verify-time rejections
// in the WASM. Only DER syntax violations throw.

import { SigningError } from '../errors.js';

const SEQUENCE_TAG = 0x30;
const INTEGER_TAG  = 0x02;

function reject(detail: string): never {
	throw new SigningError(
		'sig-malformed-input',
		`leviathan-crypto: ecdsa-p256 DER signature ${detail}`,
	);
}

/**
 * Encode a positive 32-byte BE scalar (r or s component) as a DER
 * INTEGER TLV. Strips leading zero bytes to the minimal encoding per
 * X.690 §8.3.2, then prepends a single 0x00 if the high bit of the
 * resulting first content byte is set, so the INTEGER remains positive.
 *
 * The component length is at most 33 bytes (32-byte scalar + optional
 * sign-pad), so the DER length octet always fits in short-form.
 */
function encodeInteger(scalarBE: Uint8Array): Uint8Array {
	let start = 0;
	while (start < scalarBE.length - 1 && scalarBE[start] === 0) start++;
	const stripped   = scalarBE.subarray(start);
	const needsPad   = (stripped[0] & 0x80) !== 0;
	const contentLen = stripped.length + (needsPad ? 1 : 0);
	const out = new Uint8Array(2 + contentLen);
	out[0] = INTEGER_TAG;
	out[1] = contentLen;
	if (needsPad) {
		out[2] = 0;
		out.set(stripped, 3);
	} else {
		out.set(stripped, 2);
	}
	return out;
}

/**
 * Decode one DER INTEGER TLV starting at `start`. Returns the strict-DER
 * minimal content bytes (with any leading 0x00 sign-pad stripped) and
 * the offset immediately past the INTEGER. Throws SigningError on any
 * DER syntax violation.
 */
function decodeInteger(der: Uint8Array, start: number): { value: Uint8Array; next: number } {
	if (start + 2 > der.length)
		reject(`has a truncated INTEGER header at offset ${start}`);
	if (der[start] !== INTEGER_TAG)
		reject(`INTEGER tag at offset ${start} is 0x${der[start].toString(16).padStart(2, '0')}, expected 0x02`);
	const lenByte = der[start + 1];
	// Strict DER: ECDSA-P256 INTEGER content is at most 33 bytes, so the
	// length octet is always short-form (high bit clear, value 1..127).
	if (lenByte & 0x80)
		reject(`INTEGER at offset ${start} uses long-form length encoding (forbidden for content < 128 bytes)`);
	// Zero-length INTEGER content has no representable value; ASN.1
	// requires at least one content octet (X.690 §8.3.1).
	if (lenByte === 0)
		reject(`INTEGER at offset ${start} has zero-length content`);
	const contentStart = start + 2;
	const contentEnd   = contentStart + lenByte;
	if (contentEnd > der.length)
		reject(`INTEGER at offset ${start} extends past the outer SEQUENCE end`);
	const content = der.subarray(contentStart, contentEnd);
	// Minimal encoding: a leading 0x00 octet is permitted only when the
	// next byte's high bit is set (sign-pad). Otherwise the 0x00 is
	// excess per X.690 §8.3.2.
	if (content[0] === 0x00 && content.length > 1 && (content[1] & 0x80) === 0)
		reject(`INTEGER at offset ${start} has excess leading zero byte (non-minimal DER)`);
	// ECDSA r, s ∈ [1, n-1] are positive integers. A first content
	// octet with the high bit set means the ASN.1 INTEGER decodes as a
	// negative two's-complement value; reject.
	if ((content[0] & 0x80) !== 0)
		reject(`INTEGER at offset ${start} is negative (high bit set on first content byte); ECDSA r, s are positive`);
	const value = (content[0] === 0x00) ? content.subarray(1) : content;
	return { value, next: contentEnd };
}

/**
 * Convert a 64-byte raw r || s signature to DER per RFC 3279 §2.2.3.
 * Output length is variable: 8 bytes minimum (r = s = 1 byte each, no
 * sign-pad), 72 bytes maximum (both components 32 bytes with high bit
 * set, each picking up a 0x00 sign-pad).
 *
 * @throws TypeError if `sig` is not a Uint8Array
 * @throws RangeError if `sig.length !== 64`
 */
export function ecdsaSignatureToDer(sig: Uint8Array): Uint8Array {
	if (!(sig instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 raw signature must be a Uint8Array');
	if (sig.length !== 64)
		throw new RangeError(
			`leviathan-crypto: ecdsa-p256 raw signature must be 64 bytes r||s (got ${sig.length})`,
		);
	const r = encodeInteger(sig.subarray(0, 32));
	const s = encodeInteger(sig.subarray(32, 64));
	const contentLen = r.length + s.length;
	// SEQUENCE content is at most 2 * 35 = 70 bytes, so the SEQUENCE
	// length octet is always short-form.
	const out = new Uint8Array(2 + contentLen);
	out[0] = SEQUENCE_TAG;
	out[1] = contentLen;
	out.set(r, 2);
	out.set(s, 2 + r.length);
	return out;
}

/**
 * Convert a DER ECDSA-P256 signature to 64-byte raw r || s. Rejects
 * any DER syntax violation via SigningError('sig-malformed-input'):
 * see the file-level header for the rejection rules.
 *
 * Semantic value rejections (r = 0, s = 0, high-s, off-range) are
 * deferred to the WASM verify path; this function only enforces DER
 * structure.
 *
 * @throws TypeError if `der` is not a Uint8Array
 * @throws SigningError('sig-malformed-input') on any DER syntax error
 */
export function ecdsaSignatureFromDer(der: Uint8Array): Uint8Array {
	if (!(der instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 DER signature must be a Uint8Array');
	// 8 bytes is the absolute minimum: SEQUENCE(2) + INTEGER(0x01 0x01)
	// + INTEGER(0x01 0x01) = 8. Anything shorter cannot represent two
	// non-empty INTEGER components.
	if (der.length < 8)
		reject(`is shorter than the 8-byte minimum (got ${der.length} bytes)`);
	if (der[0] !== SEQUENCE_TAG)
		reject(`outer tag is 0x${der[0].toString(16).padStart(2, '0')}, expected 0x30 (SEQUENCE)`);
	const seqLen = der[1];
	// ECDSA-P256 SEQUENCE content is at most 70 bytes; strict DER
	// requires short-form length encoding when < 128.
	if (seqLen & 0x80)
		reject('uses long-form length encoding for the outer SEQUENCE (forbidden for content < 128 bytes)');
	if (2 + seqLen !== der.length)
		reject(`outer SEQUENCE length ${seqLen} does not match input size (${der.length} bytes total)`);
	const { value: r, next: afterR } = decodeInteger(der, 2);
	const { value: s, next: end }    = decodeInteger(der, afterR);
	if (end !== der.length)
		reject('has trailing bytes after the second INTEGER');
	// Each component must fit in 32 bytes BE (P-256 scalar size).
	if (r.length > 32)
		reject(`r component is ${r.length} bytes, exceeds the 32-byte scalar size`);
	if (s.length > 32)
		reject(`s component is ${s.length} bytes, exceeds the 32-byte scalar size`);
	const out = new Uint8Array(64);
	out.set(r, 32 - r.length);
	out.set(s, 64 - s.length);
	return out;
}
