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
// test/vectors/merkle_checkpoint.ts
//
// KAT corpus for the c2sp.org/tlog-checkpoint (Transparency Log
// Checkpoints) §Note text canonical body codec. The first record
// (`gate`) is the spec worked example from c2sp.org/tlog-checkpoint
// §Note text, byte-for-byte. The remaining records are self-generated
// and cross-verified by `scripts/verify-vectors/src/merkle_checkpoint.rs`
// against an independent Rust serializer (UTF-8 concat with RustCrypto
// `base64`).
//
// C2SP commit pinned for this vector corpus:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).

export interface CheckpointRecord {
	/** Human-readable description of the case. */
	desc: string;
	/** Log identity, the first line of the body. */
	origin: string;
	/** Tree size, the second line of the body. */
	treeSize: number;
	/** Root hash bytes encoded as base64 with RFC 4648 §4 padding. */
	rootHashB64: string;
	/**
	 * Expected canonical body bytes. Stored as the raw UTF-8 string for
	 * direct readability; the test encodes via `utf8ToBytes` before
	 * byte-comparing against `serializeCheckpointBody`. Trailing 0x0A is
	 * present per c2sp.org/tlog-checkpoint §Note text.
	 */
	expectedBody: string;
}

// Per c2sp.org/tlog-checkpoint §Note text. The example body in the
// spec is the gate value; any deviation in serializer output is a
// spec violation, not a vector bug.
const GATE_BODY =
	'example.com/behind-the-sofa\n'
	+ '20852163\n'
	+ 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n';

export const CHECKPOINT_RECORDS: readonly CheckpointRecord[] = [
	{
		desc: 'GATE: c2sp.org/tlog-checkpoint §Note text worked example',
		origin: 'example.com/behind-the-sofa',
		treeSize: 20852163,
		rootHashB64: 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=',
		expectedBody: GATE_BODY,
	},
	{
		desc: 'tree size 0: empty tree, root hash is all-zero (placeholder, hasher-agnostic)',
		origin: 'example.com/log42',
		treeSize: 0,
		rootHashB64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
		expectedBody:
			'example.com/log42\n'
			+ '0\n'
			+ 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n',
	},
	{
		desc: 'tree size 1: single-leaf tree, 32-byte all-ones root hash',
		origin: 'example.com/log42',
		treeSize: 1,
		rootHashB64: '//////////////////////////////////////////8=',
		expectedBody:
			'example.com/log42\n'
			+ '1\n'
			+ '//////////////////////////////////////////8=\n',
	},
	{
		desc: 'tree size = Number.MAX_SAFE_INTEGER, hex-pattern root hash',
		origin: 'sigsum.example.org/v1',
		treeSize: Number.MAX_SAFE_INTEGER,
		rootHashB64: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
		expectedBody:
			'sigsum.example.org/v1\n'
			+ '9007199254740991\n'
			+ 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n',
	},
];
