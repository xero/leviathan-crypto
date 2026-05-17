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
// test/vectors/cosig_payload.ts
//
// KAT corpus for the c2sp.org/tlog-cosignature (Transparency Log
// Cosignatures) §Format `timestamped_signature` payload codec.
// Locks the bytes `emitCosigSignaturePayload(ts, sig)` produces and
// `parseCosigSignaturePayload(payload, sigSize)` must accept.
//
// Layout per RFC 8446 §3.3, Presentation Language (big-endian):
//
//     u64_be(timestamp) || signature[sigSize]
//
// The codec is signature-content-agnostic, so signature bytes here
// are deterministic ramp patterns rather than real Ed25519 / ML-DSA-44
// signatures. The Rust verifier oracle regenerates the same bytes
// from the recorded `salt` field via the same ramp formula and
// asserts byte equality with the literal hex captured below.
//
// Pattern formula (matches `pattern_hex(n, salt)` in
// `scripts/verify-vectors/src/merkle_cosig.rs`):
//
//     byte[i] = (i * 31 + salt) & 0xff      for i in [0, n)
//
// Named-fixture style is consistent with `test/vectors/merkle_signed_note.ts`;
// the Rust verifier resolves identifiers (e.g. `COSIG_ED_SIG_V1`) into
// the same computed bytes.
//
// C2SP commit pinned for this vector corpus:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).

function patternHex(n: number, salt: number): string {
	let s = '';
	for (let i = 0; i < n; i++) {
		const b = (i * 31 + salt) & 0xff;
		s += b.toString(16).padStart(2, '0');
	}
	return s;
}

function timestampBeHex(ts: number): string {
	const hi = Math.floor(ts / 0x100000000);
	const lo = ts >>> 0;
	const h = (n: number) => n.toString(16).padStart(8, '0');
	return h(hi) + h(lo);
}

// Named fixtures, one per record's sigHex / payloadHex. The Rust
// verifier in `scripts/verify-vectors/src/merkle_cosig.rs` has the
// same name table and resolves each identifier to the same bytes
// independently.

const COSIG_ED_SIG_V1 = patternHex(64,   7);
const COSIG_ED_SIG_V2 = patternHex(64,  23);
const COSIG_ED_SIG_V3 = patternHex(64,  91);
const COSIG_ED_SIG_V4 = patternHex(64, 149);
const COSIG_ML_SIG_V1 = patternHex(2420,  3);
const COSIG_ML_SIG_V2 = patternHex(2420, 47);

const COSIG_ED_PAYLOAD_V1 = timestampBeHex(0) + COSIG_ED_SIG_V1;
const COSIG_ED_PAYLOAD_V2 = timestampBeHex(1) + COSIG_ED_SIG_V2;
const COSIG_ED_PAYLOAD_V3 = timestampBeHex(1679315147) + COSIG_ED_SIG_V3;
const COSIG_ED_PAYLOAD_V4 = timestampBeHex(Number.MAX_SAFE_INTEGER) + COSIG_ED_SIG_V4;
const COSIG_ML_PAYLOAD_V1 = timestampBeHex(0) + COSIG_ML_SIG_V1;
const COSIG_ML_PAYLOAD_V2 = timestampBeHex(1679315147) + COSIG_ML_SIG_V2;

export interface CosigPayloadRecord {
	/** Human-readable description of the case. */
	desc: string;
	/**
	 * Suite identifier: 'ed25519' (sigSize=64, C2SP algo byte 0x04)
	 * or 'mldsa44' (sigSize=2420, C2SP algo byte 0x06). Both sizes
	 * pass through the codec identically; the discriminator pins
	 * the `sigSize` argument to `parseCosigSignaturePayload`.
	 */
	suite: 'ed25519' | 'mldsa44';
	/**
	 * POSIX-seconds timestamp on the cosignature. Non-negative safe
	 * integer; see c2sp.org/tlog-cosignature §Format on the u64
	 * upper bound and the leviathan-specific safe-integer guard.
	 */
	timestamp: number;
	/**
	 * Salt parameter for the ramp pattern that generates the
	 * signature bytes. Stored explicitly so the Rust verifier can
	 * regenerate the bytes from the same `(n, salt)` inputs and
	 * cross-check the named-fixture identifier resolution.
	 */
	salt: number;
	/**
	 * Signature bytes as a deterministic pattern. Length is
	 * `sigSize` (64 for Ed25519, 2420 for ML-DSA-44).
	 */
	sigHex: string;
	/**
	 * Expected payload bytes. Length is `8 + sigSize` (72 for
	 * Ed25519, 2428 for ML-DSA-44).
	 */
	payloadHex: string;
}

export const COSIG_PAYLOAD_RECORDS: readonly CosigPayloadRecord[] = [
	{
		desc: 'Ed25519, timestamp 0',
		suite: 'ed25519',
		timestamp: 0,
		salt: 7,
		sigHex: COSIG_ED_SIG_V1,
		payloadHex: COSIG_ED_PAYLOAD_V1,
	},
	{
		desc: 'Ed25519, timestamp 1',
		suite: 'ed25519',
		timestamp: 1,
		salt: 23,
		sigHex: COSIG_ED_SIG_V2,
		payloadHex: COSIG_ED_PAYLOAD_V2,
	},
	{
		desc: 'Ed25519, spec example timestamp 1679315147',
		suite: 'ed25519',
		timestamp: 1679315147,
		salt: 91,
		sigHex: COSIG_ED_SIG_V3,
		payloadHex: COSIG_ED_PAYLOAD_V3,
	},
	{
		desc: 'Ed25519, timestamp Number.MAX_SAFE_INTEGER (2^53 - 1)',
		suite: 'ed25519',
		timestamp: Number.MAX_SAFE_INTEGER,
		salt: 149,
		sigHex: COSIG_ED_SIG_V4,
		payloadHex: COSIG_ED_PAYLOAD_V4,
	},
	{
		desc: 'ML-DSA-44, timestamp 0',
		suite: 'mldsa44',
		timestamp: 0,
		salt: 3,
		sigHex: COSIG_ML_SIG_V1,
		payloadHex: COSIG_ML_PAYLOAD_V1,
	},
	{
		desc: 'ML-DSA-44, spec example timestamp 1679315147',
		suite: 'mldsa44',
		timestamp: 1679315147,
		salt: 47,
		sigHex: COSIG_ML_SIG_V2,
		payloadHex: COSIG_ML_PAYLOAD_V2,
	},
];
