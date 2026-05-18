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
// src/ts/ecdsa/ecprivatekey-der.ts
//
// DER `ECPrivateKey` (RFC 5915 §3, Elliptic Curve Private Key Structure)
// codec for P-256. The library's WASM ABI stores secrets as 32-byte raw
// scalars; DER `ECPrivateKey` is the X.509 / PKCS#8-adjacent wire form
// some interop contexts require (PKCS#8 wraps an ECPrivateKey OCTET
// STRING inside its `privateKey` field; X.509 self-signed certs reference
// it through their algorithm OID).
//
//   ECPrivateKey ::= SEQUENCE {
//       version        INTEGER (1),
//       privateKey     OCTET STRING,
//       parameters [0] EXPLICIT ECParameters OPTIONAL,
//       publicKey  [1] EXPLICIT BIT STRING OPTIONAL
//   }
//
// Encoder side: emits the exact 51-byte DER form with version 1, the
// 32-byte raw scalar in `privateKey`, and the named-curve OID
// `1.2.840.10045.3.1.7` (secp256r1, SP 800-186 §3.2.1.3) wrapped in
// `parameters [0]`. `publicKey` is omitted; consumers that need the
// public key alongside should re-derive via `EcdsaP256.keygenDerand` and
// the SEC 1 §2.3.4 uncompressed encoding (see `pointDecompress` in
// `./index.ts`). Byte-stable: same scalar in, same DER out.
//
// Decoder side: accepts any conforming RFC 5915 `ECPrivateKey` (not just
// leviathan's exact byte layout). Strict-DER posture per X.690 §10
// (Restrictions on the BER) rejects:
//   - non-minimal length encodings (long-form when short-form suffices)
//   - non-minimal INTEGER encodings on the `version` field
//   - SEQUENCE / OCTET STRING / parameters [0] / publicKey [1] length
//     prefixes that disagree with the on-the-wire content size
//   - any curve OID inside `parameters [0]` other than secp256r1
//   - trailing bytes after the outer SEQUENCE
//   - wrong tags or missing required fields
//
// Lenient on `publicKey [1]`: some encoders include the derived pk
// alongside the scalar; the decoder skips past the field after a
// minimal-length check. The scalar is the only return value; callers
// who need the embedded pk should parse the DER themselves.
//
// No third-party ASN.1 library. Hand-rolled against X.690 §8.1 (TLV
// structure), §8.3 (INTEGER), §8.7 (OCTET STRING), §8.14 (tagged types),
// §10 (DER restrictions), mirroring the strict-parser hygiene of
// `./der.ts` (Ecdsa-Sig-Value codec).

const SEQUENCE_TAG      = 0x30;
const INTEGER_TAG       = 0x02;
const OCTET_STRING_TAG  = 0x04;
const OID_TAG           = 0x06;
const TAG_PARAMETERS_0  = 0xA0;  // [0] EXPLICIT, constructed
const TAG_PUBLIC_KEY_1  = 0xA1;  // [1] EXPLICIT, constructed

// DER OID for secp256r1: 1.2.840.10045.3.1.7. X.690 §8.19 collapses the
// first two arcs (1.2) into a single byte 0x2A (= 1 * 40 + 2); the
// remaining arcs (840, 10045, 3, 1, 7) base-128 encode as 86 48, CE 3D,
// 03, 01, 07. Wrapped in the OBJECT IDENTIFIER TLV (tag 0x06, len 0x08).
const SECP256R1_OID_DER = new Uint8Array([
	OID_TAG, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
]);

// Exact 51-byte DER shape for a P-256 ECPrivateKey with no embedded
// public key:
//   30 31                          SEQUENCE, 49 bytes content
//   02 01 01                       INTEGER, version = 1
//   04 20 <32 bytes scalar>        OCTET STRING, 32 bytes
//   A0 0A                          [0] EXPLICIT, 10 bytes content
//   06 08 2A 86 48 CE 3D 03 01 07  OBJECT IDENTIFIER, secp256r1
const ENCODED_LEN          = 51;
const SEQUENCE_CONTENT_LEN = 49;
const SCALAR_LEN           = 32;

// Absolute minimum input size that exposes every required field's TLV
// header without index-out-of-bounds on the parser side. SEQUENCE
// header (2) + version INTEGER TLV (3) + OCTET STRING tag + len byte
// (2) = 7. The decoder's field-level checks surface more specific
// rejections beyond this floor (wrong scalar length, missing required
// fields, etc).
const MIN_INPUT_LEN        = 7;

function reject(detail: string): never {
	throw new Error(
		`leviathan-crypto: ecdsa-p256 ECPrivateKey DER ${detail}`,
	);
}

/**
 * Encode a 32-byte P-256 secret scalar as DER `ECPrivateKey` per
 * RFC 5915 §3. Output length is exactly 51 bytes; version is 1, the
 * named-curve OID for secp256r1 (`1.2.840.10045.3.1.7`,
 * SP 800-186 §3.2.1.3) is included in `parameters [0]`, and the
 * `publicKey [1]` field is omitted.
 *
 * Byte-stable: same input scalar produces byte-identical output. No
 * canonicalisation pass needed because every field has a single legal
 * DER encoding under the strict-DER rules of X.690 §10.
 *
 * @throws TypeError if `scalar` is not a Uint8Array
 * @throws RangeError if `scalar.length !== 32`
 */
export function encodeEcPrivateKey(scalar: Uint8Array): Uint8Array {
	if (!(scalar instanceof Uint8Array))
		throw new TypeError(
			'leviathan-crypto: ecdsa-p256 ECPrivateKey scalar must be a Uint8Array',
		);
	if (scalar.length !== SCALAR_LEN)
		throw new RangeError(
			`leviathan-crypto: ecdsa-p256 ECPrivateKey scalar must be ${SCALAR_LEN} bytes (got ${scalar.length})`,
		);

	const out = new Uint8Array(ENCODED_LEN);
	let p = 0;

	// SEQUENCE header
	out[p++] = SEQUENCE_TAG;
	out[p++] = SEQUENCE_CONTENT_LEN;

	// version INTEGER (1)
	out[p++] = INTEGER_TAG;
	out[p++] = 0x01;
	out[p++] = 0x01;

	// privateKey OCTET STRING (32 bytes)
	out[p++] = OCTET_STRING_TAG;
	out[p++] = SCALAR_LEN;
	out.set(scalar, p);
	p += SCALAR_LEN;

	// parameters [0] EXPLICIT { secp256r1 OID }
	out[p++] = TAG_PARAMETERS_0;
	out[p++] = SECP256R1_OID_DER.length;
	out.set(SECP256R1_OID_DER, p);

	// p + SECP256R1_OID_DER.length now equals ENCODED_LEN by construction.
	return out;
}

/**
 * Decode a DER `ECPrivateKey` (RFC 5915 §3) and return the 32-byte
 * raw P-256 secret scalar.
 *
 * Strict-DER per X.690 §10 (Restrictions on the BER). Rejects the
 * cases enumerated in the file-level header. Accepts (and ignores)
 * an optional `publicKey [1]` field per RFC 5915 §3 lenient input;
 * the scalar is the only return value.
 *
 * Any curve OID inside `parameters [0]` other than secp256r1
 * (`1.2.840.10045.3.1.7`) is rejected. Decoders that need other
 * curves must use a different parser; this library is P-256 only.
 *
 * @throws TypeError if `der` is not a Uint8Array
 * @throws Error on any DER syntax violation or unsupported parameter
 */
export function decodeEcPrivateKey(der: Uint8Array): Uint8Array {
	if (!(der instanceof Uint8Array))
		throw new TypeError(
			'leviathan-crypto: ecdsa-p256 ECPrivateKey DER must be a Uint8Array',
		);
	// Floor at the bytes needed for the SEQUENCE header + version
	// INTEGER TLV + privateKey OCTET STRING TLV header (no content
	// required at the floor). Specific field-level checks below
	// surface more accurate rejections beyond this.
	if (der.length < MIN_INPUT_LEN)
		reject(`is shorter than the ${MIN_INPUT_LEN}-byte minimum (got ${der.length} bytes)`);

	if (der[0] !== SEQUENCE_TAG)
		reject(`outer tag is 0x${der[0].toString(16).padStart(2, '0')}, expected 0x30 (SEQUENCE)`);

	const seqLen = der[1];
	// Strict DER short-form: outer SEQUENCE content for a P-256
	// ECPrivateKey is at most 51 - 2 = 49 bytes with no public key, or
	// roughly 51 + 67 - 2 = 116 with a publicKey [1] field; both fit
	// in short-form. Long-form here would be a non-minimal encoding
	// for content < 128 bytes.
	if (seqLen & 0x80)
		reject('uses long-form length encoding for the outer SEQUENCE (forbidden for content < 128 bytes)');
	if (2 + seqLen !== der.length)
		reject(`outer SEQUENCE length ${seqLen} does not match input size (${der.length} bytes total)`);

	let off = 2;

	// version INTEGER (1). Strict: exactly `02 01 01`. Any other
	// length, leading-zero pad, or value rejects.
	if (der[off] !== INTEGER_TAG)
		reject(`version tag at offset ${off} is 0x${der[off].toString(16).padStart(2, '0')}, expected 0x02 (INTEGER)`);
	if (der[off + 1] !== 0x01)
		reject(`version length at offset ${off + 1} is ${der[off + 1]}, expected 1 (single-byte INTEGER)`);
	if (der[off + 2] !== 0x01)
		reject(`version value at offset ${off + 2} is ${der[off + 2]}, expected 1`);
	off += 3;

	// privateKey OCTET STRING (32 bytes for P-256).
	if (der[off] !== OCTET_STRING_TAG)
		reject(`privateKey tag at offset ${off} is 0x${der[off].toString(16).padStart(2, '0')}, expected 0x04 (OCTET STRING)`);
	const skLen = der[off + 1];
	if (skLen & 0x80)
		reject(`privateKey OCTET STRING at offset ${off + 1} uses long-form length encoding (forbidden for content < 128 bytes)`);
	if (skLen !== SCALAR_LEN)
		reject(`privateKey OCTET STRING length at offset ${off + 1} is ${skLen}, expected ${SCALAR_LEN} (P-256 scalar)`);
	if (off + 2 + skLen > der.length)
		reject('privateKey OCTET STRING content extends past the outer SEQUENCE end');
	const scalar = der.slice(off + 2, off + 2 + skLen);
	off += 2 + skLen;

	// Optional parameters [0] EXPLICIT. Per RFC 5915 §3 this field is
	// OPTIONAL; when present it carries the curve OID. We require
	// secp256r1 specifically; any other OID rejects.
	if (off < der.length && der[off] === TAG_PARAMETERS_0) {
		const paramLen = der[off + 1];
		if (paramLen & 0x80)
			reject(`parameters [0] at offset ${off + 1} uses long-form length encoding (forbidden for content < 128 bytes)`);
		if (off + 2 + paramLen > der.length)
			reject('parameters [0] content extends past the outer SEQUENCE end');
		if (paramLen !== SECP256R1_OID_DER.length)
			reject(
				`parameters [0] content is ${paramLen} bytes, expected ${SECP256R1_OID_DER.length} `
				+ '(secp256r1 OID TLV); other curves are not supported',
			);
		for (let i = 0; i < paramLen; i++) {
			if (der[off + 2 + i] !== SECP256R1_OID_DER[i])
				reject(
					'parameters [0] OID does not match secp256r1 (1.2.840.10045.3.1.7); '
					+ 'other curves are not supported',
				);
		}
		off += 2 + paramLen;
	}

	// Optional publicKey [1] EXPLICIT. RFC 5915 §3 leaves this
	// OPTIONAL; some encoders include it. We skip past after a
	// minimal-length sanity check; the scalar is the canonical
	// secret material and the embedded pk is informational at the
	// codec layer (a caller who needs it should re-derive from the
	// scalar via keygenDerand for a constant-time-checked match).
	if (off < der.length && der[off] === TAG_PUBLIC_KEY_1) {
		const pkLen = der[off + 1];
		if (pkLen & 0x80)
			reject(`publicKey [1] at offset ${off + 1} uses long-form length encoding (forbidden for content < 128 bytes)`);
		if (off + 2 + pkLen > der.length)
			reject('publicKey [1] content extends past the outer SEQUENCE end');
		off += 2 + pkLen;
	}

	// No trailing bytes after the (optional) tail fields.
	if (off !== der.length)
		reject(`has ${der.length - off} trailing byte(s) after the optional fields`);

	return scalar;
}
