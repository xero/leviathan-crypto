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
// test/vectors/merkle_signed_note.ts
//
// KAT corpus for the c2sp.org/signed-note (Note) §Format envelope codec
// and the c2sp.org/tlog-cosignature §Format key-ID derivation.
//
// The first key-ID record is spec-anchored against the worked example
// in c2sp.org/signed-note §Verifier keys §Example: the verifier key
// "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
// publishes its key ID as the hex "530d903a", which any spec-compliant
// implementation MUST reproduce from the (name, algo=0x01, public key)
// triple. The remaining key-ID records are self-generated against the
// algo bytes 0x04 (timestamped Ed25519 cosignature) and 0x06
// (timestamped ML-DSA-44 cosignature) per c2sp.org/tlog-cosignature
// §Format and are cross-checked by an independent RustCrypto sha2
// computation in scripts/verify-vectors/src/merkle_checkpoint.rs.
//
// Round-trip records exercise emit / parse byte-equality for
// single-sig, multi-sig, and mixed-algorithm envelopes. The signature
// payload bytes inside each record are deterministic test fixtures
// (not real signatures); both stacks reproduce the same envelope
// bytes from the same inputs.
//
// C2SP commit pinned: 3752ba5b3590dc3754e04fcc8369bd3612897c02
// (github.com/C2SP/C2SP).

// ── key-ID derivation KATs ─────────────────────────────────────────────────

export interface KeyIdRecord {
	desc: string;
	name: string;
	algoByte: number;
	pubkeyHex: string;
	expectedKeyIdHex: string;
}

// Helper-only: not exported; reused inside this file's record literals.
// 32-byte deterministic Ed25519 public key fixture: bytes 0x00..0x1F.
const ED25519_PK_HEX_FIXTURE =
	'000102030405060708090a0b0c0d0e0f'
	+ '101112131415161718191a1b1c1d1e1f';

// 1312-byte deterministic ML-DSA-44 public key fixture: byte i = (7i + 3) mod 256.
// Stored as a hex string literal so the vector file is plain data and the
// Rust verifier can extract it via the same `extract_hex` helpers used for
// the existing mlkem / mldsa / slhdsa vectors.
const MLDSA44_PK_HEX_FIXTURE = (() => {
	let s = '';
	const lut = '0123456789abcdef';
	for (let i = 0; i < 1312; i++) {
		const b = (i * 7 + 3) & 0xff;
		s += lut[(b >>> 4) & 0xf] + lut[b & 0xf];
	}
	return s;
})();

export const KEY_ID_RECORDS: readonly KeyIdRecord[] = [
	{
		desc: 'spec example: signed-note §Verifier keys, Ed25519 algo 0x01',
		name: 'example.com/foo',
		algoByte: 0x01,
		pubkeyHex: 'e932791ae6e7a840a46164c904786426d5e7821dd8b29a00d61cae72afdd4da4',
		expectedKeyIdHex: '530d903a',
	},
	{
		desc: 'self-gen: timestamped Ed25519 cosignature, algo 0x04',
		name: 'example.com/behind-the-sofa',
		algoByte: 0x04,
		pubkeyHex: ED25519_PK_HEX_FIXTURE,
		expectedKeyIdHex: 'b3793d48',
	},
	{
		desc: 'self-gen: timestamped ML-DSA-44 cosignature, algo 0x06',
		name: 'example.com/behind-the-sofa',
		algoByte: 0x06,
		pubkeyHex: MLDSA44_PK_HEX_FIXTURE,
		expectedKeyIdHex: 'ba396de3',
	},
];

// ── round-trip envelope vectors ────────────────────────────────────────────

export interface SignedNoteSig {
	/** Key name written into the signature line. */
	name: string;
	/** c2sp.org/signed-note §Signatures algorithm byte for key-ID derivation. */
	algoByte: number;
	/** Hex-encoded public key bytes; length is algorithm-specific. */
	pubkeyHex: string;
	/**
	 * Hex-encoded signature payload bytes that follow the 4-byte key ID
	 * inside the base64-encoded signature blob. For timestamped Ed25519
	 * cosignatures this is `u64_be(timestamp) || ed25519_signature(64)`
	 * for 72 bytes; for timestamped ML-DSA-44 cosignatures it is
	 * `u64_be(timestamp) || ml_dsa_44_signature(2420)` for 2428 bytes.
	 */
	sigPayloadHex: string;
}

export interface SignedNoteRoundtripRecord {
	desc: string;
	/** Checkpoint body inputs (the body is `serializeCheckpointBody`d). */
	origin: string;
	treeSize: number;
	rootHashB64: string;
	signatures: SignedNoteSig[];
	/**
	 * Total length, in bytes, of the emitted envelope. Both TS and the
	 * Rust verifier cross-check produce a buffer of exactly this length.
	 */
	expectedEnvelopeLen: number;
	/**
	 * SHA-256 of the emitted envelope bytes, hex-encoded. Frozen at
	 * vector creation time; both TS and the Rust verifier reproduce
	 * the envelope from the (origin, treeSize, rootHash, signatures)
	 * inputs and hash the result; matching this digest confirms the
	 * two stacks agreed on every byte without storing the full
	 * envelope literal in the vector file.
	 */
	expectedEnvelopeSha256Hex: string;
}

// Deterministic 72-byte Ed25519-cosignature payload fixture. The first 8
// bytes are a u64-BE timestamp (`0x65 65 a7 00 00 00 00 00` = the POSIX
// time at which we pretend to have signed); the remaining 64 bytes
// follow a `(5i + 1) mod 256` ramp. The bytes are not a valid signature,
// just stable test data.
const ED25519_COSIG_72_HEX = (() => {
	let s = '6565a70000000000';
	const lut = '0123456789abcdef';
	for (let i = 0; i < 64; i++) {
		const b = (i * 5 + 1) & 0xff;
		s += lut[(b >>> 4) & 0xf] + lut[b & 0xf];
	}
	return s;
})();

// Deterministic 2428-byte ML-DSA-44-cosignature payload fixture. First 8
// bytes u64-BE timestamp; remaining 2420 bytes via a `(3i + 7) mod 256`
// ramp.
const MLDSA44_COSIG_2428_HEX = (() => {
	let s = '6565a70100000000';
	const lut = '0123456789abcdef';
	for (let i = 0; i < 2420; i++) {
		const b = (i * 3 + 7) & 0xff;
		s += lut[(b >>> 4) & 0xf] + lut[b & 0xf];
	}
	return s;
})();

export const ROUNDTRIP_RECORDS: readonly SignedNoteRoundtripRecord[] = [
	{
		desc: 'single Ed25519 cosignature (algo 0x04)',
		origin: 'example.com/behind-the-sofa',
		treeSize: 20852163,
		rootHashB64: 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=',
		signatures: [{
			name: 'example.com/behind-the-sofa',
			algoByte: 0x04,
			pubkeyHex: ED25519_PK_HEX_FIXTURE,
			sigPayloadHex: ED25519_COSIG_72_HEX,
		}],
		expectedEnvelopeLen: 220,
		expectedEnvelopeSha256Hex: '3bc04ce178072e009672e9cc34c3df5549e7ea18708f98c31784f5e63eff2348',
	},
	{
		desc: 'single ML-DSA-44 cosignature (algo 0x06)',
		origin: 'example.com/behind-the-sofa',
		treeSize: 20852163,
		rootHashB64: 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=',
		signatures: [{
			name: 'example.com/behind-the-sofa',
			algoByte: 0x06,
			pubkeyHex: MLDSA44_PK_HEX_FIXTURE,
			sigPayloadHex: MLDSA44_COSIG_2428_HEX,
		}],
		expectedEnvelopeLen: 3360,
		expectedEnvelopeSha256Hex: 'db5779d4de1f00f4127aa11ab7de01e1ba40bd5fa18e79a222fa05b188af5c3e',
	},
	{
		desc: 'two cosignatures, Ed25519 first then ML-DSA-44',
		origin: 'example.com/behind-the-sofa',
		treeSize: 20852163,
		rootHashB64: 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=',
		signatures: [
			{
				name: 'example.com/behind-the-sofa',
				algoByte: 0x04,
				pubkeyHex: ED25519_PK_HEX_FIXTURE,
				sigPayloadHex: ED25519_COSIG_72_HEX,
			},
			{
				name: 'witness.example.com/w1',
				algoByte: 0x06,
				pubkeyHex: MLDSA44_PK_HEX_FIXTURE,
				sigPayloadHex: MLDSA44_COSIG_2428_HEX,
			},
		],
		expectedEnvelopeLen: 3492,
		expectedEnvelopeSha256Hex: '7088e241cf1db6cf5c01b7a72000c0e7468a39956f419c5ba09995a1411a1c0e',
	},
];
