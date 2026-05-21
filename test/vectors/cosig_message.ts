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
// test/vectors/cosig_message.ts
//
// KAT corpus for the c2sp.org/tlog-cosignature (Transparency Log
// Cosignatures) §"Ed25519 signed message" construction. The first
// record (`gate`) is the spec worked example reproduced byte-for-byte
// from `c2sp.org/tlog-cosignature` §"Ed25519 signed message". The
// remaining records are self-generated and cross-verified by
// `scripts/verify-vectors/src/merkle_cosig.rs` against an independent
// Rust serializer (Rust standard library, no third-party crate).
//
// The vectors lock the bytes that `buildCosigSignedMessage(body, ts)`
// must produce. The construction is two newline-terminated header
// lines (`cosignature/v1`, `time <decimal>`) followed by the whole
// note body including its terminating newline; no separator between
// the timestamp line and the body.
//
// C2SP commit pinned for this vector corpus:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).

export interface CosigMessageRecord {
	/** Human-readable description of the case. */
	desc: string;
	/**
	 * POSIX-seconds timestamp on the cosignature, the second line of
	 * the signed message after the `time ` prefix.
	 */
	timestamp: number;
	/**
	 * Canonical checkpoint body bytes, the suffix of the signed
	 * message. Stored as the raw UTF-8 string for direct readability;
	 * the test encodes via `utf8ToBytes` before passing to
	 * `buildCosigSignedMessage`. Trailing 0x0A is present per
	 * c2sp.org/tlog-checkpoint §Note text.
	 */
	body: string;
	/**
	 * Expected signed-message bytes the cosigner signs. Stored as the
	 * raw UTF-8 string; the test encodes via `utf8ToBytes` before
	 * byte-comparing against `buildCosigSignedMessage(body, ts)`.
	 */
	expectedMessage: string;
}

export const COSIG_MESSAGE_RECORDS: readonly CosigMessageRecord[] = [
	{
		desc: 'GATE: c2sp.org/tlog-cosignature §"Ed25519 signed message" worked example',
		timestamp: 1679315147,
		// c2sp.org/tlog-cosignature §"Ed25519 signed message" worked
		// example. Body matches `test/vectors/merkle_checkpoint.ts`
		// gate body exactly; duplicated inline so the Rust verifier
		// reads the literal bytes without resolving a TS module-level
		// identifier.
		body:
			'example.com/behind-the-sofa\n'
			+ '20852163\n'
			+ 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n',
		expectedMessage:
			'cosignature/v1\n'
			+ 'time 1679315147\n'
			+ 'example.com/behind-the-sofa\n'
			+ '20852163\n'
			+ 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n',
	},
	{
		desc: 'timestamp 0: epoch-zero cosignature',
		timestamp: 0,
		body:
			'example.com/log42\n'
			+ '1\n'
			+ 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n',
		expectedMessage:
			'cosignature/v1\n'
			+ 'time 0\n'
			+ 'example.com/log42\n'
			+ '1\n'
			+ 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n',
	},
	{
		desc: 'timestamp 1: smallest non-zero cosignature timestamp',
		timestamp: 1,
		body:
			'example.com/log42\n'
			+ '0\n'
			+ 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n',
		expectedMessage:
			'cosignature/v1\n'
			+ 'time 1\n'
			+ 'example.com/log42\n'
			+ '0\n'
			+ 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n',
	},
	{
		desc: 'large timestamp near Number.MAX_SAFE_INTEGER',
		timestamp: Number.MAX_SAFE_INTEGER,
		body:
			'sigsum.example.org/v1\n'
			+ '9007199254740991\n'
			+ 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n',
		expectedMessage:
			'cosignature/v1\n'
			+ 'time 9007199254740991\n'
			+ 'sigsum.example.org/v1\n'
			+ '9007199254740991\n'
			+ 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n',
	},
];
