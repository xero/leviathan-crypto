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
// test/vectors/cosigned_message.ts
//
// KAT corpus for the c2sp.org/tlog-cosignature (Transparency Log
// Cosignatures) §"ML-DSA-44 signed message" `cosigned_message`
// TLS-Presentation struct. Locks the bytes
// `buildCosignedMessage(input)` must produce.
//
// Layout per RFC 8446 §3.3 / §3.4 (big-endian integers,
// length-prefixed variable-length vectors):
//
//     uint8 label[12] = "subtree/v1\n\0"
//     opaque cosigner_name<1..2^8-1>
//     uint64 timestamp
//     opaque log_origin<1..2^8-1>
//     uint64 start
//     uint64 end
//     uint8 hash[32]
//
// The first record (`gate`) is the log-self-cosignature case over the
// c2sp.org/tlog-cosignature §"Ed25519 signed message" worked-example
// body: cosigner_name == log_origin == "example.com/behind-the-sofa",
// start == 0, end == 20852163, timestamp == 1679315147 (the same
// timestamp the §"Ed25519 signed message" example pairs with).
// Reusing the spec body keeps wire bytes coherent across the
// Ed25519 and ML-DSA-44 examples.
//
// The remaining records cover the additional spec branches:
//   - Witness case: cosigner_name != log_origin, timestamp != 0.
//   - No-statement case: timestamp == 0, start == 0 (cosigner makes
//     no observation-time claim per §"ML-DSA-44 signed message").
//   - Subtree case: non-zero start, timestamp == 0 (spec MUST per
//     §"ML-DSA-44 signed message" "If start is not zero, timestamp
//     MUST be zero"). Phase 7 does not emit this case but the codec
//     supports it.
//
// The Rust verifier oracle `scripts/verify-vectors/src/merkle_cosig.rs`
// regenerates the same bytes from each record's structured inputs.
//
// C2SP commit pinned for this vector corpus:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).

export interface CosignedMessageRecord {
	/** Human-readable description of the case. */
	desc: string;
	cosignerName: string;
	timestamp: number;
	logOrigin: string;
	start: number;
	end: number;
	/** 32-byte hash, ASCII hex (lowercase, no separators). */
	hashHex: string;
	/** Expected struct bytes, ASCII hex. */
	expectedHex: string;
}

export const COSIGNED_MESSAGE_RECORDS: readonly CosignedMessageRecord[] = [
	{
		desc: 'GATE: log self-cosignature on c2sp.org/tlog-cosignature §"ML-DSA-44 signed message" worked-example body',
		cosignerName: 'example.com/behind-the-sofa',
		timestamp: 1679315147,
		logOrigin: 'example.com/behind-the-sofa',
		start: 0,
		end: 20852163,
		hashHex: '0ac5186a91863e8e1d90c808014aa89bf5da8e3ee1d9f07630f0378f68f1ab62',
		expectedHex:
			'737562747265652f76310a00'
			+ '1b6578616d706c652e636f6d2f626568696e642d7468652d736f6661'
			+ '00000000641850cb'
			+ '1b6578616d706c652e636f6d2f626568696e642d7468652d736f6661'
			+ '0000000000000000'
			+ '00000000013e2dc3'
			+ '0ac5186a91863e8e1d90c808014aa89bf5da8e3ee1d9f07630f0378f68f1ab62',
	},
	{
		desc: 'witness cosignature: distinct cosigner_name and log_origin, non-zero timestamp',
		cosignerName: 'witness.example.com/w1',
		timestamp: 1700000000,
		logOrigin: 'example.com/log42',
		start: 0,
		end: 1,
		hashHex: '1111111111111111111111111111111111111111111111111111111111111111',
		expectedHex:
			'737562747265652f76310a00'
			+ '167769746e6573732e6578616d706c652e636f6d2f7731'
			+ '000000006553f100'
			+ '116578616d706c652e636f6d2f6c6f673432'
			+ '0000000000000000'
			+ '0000000000000001'
			+ '1111111111111111111111111111111111111111111111111111111111111111',
	},
	{
		desc: 'no-statement: timestamp 0 + start 0 (cosigner makes no observation-time claim)',
		cosignerName: 'witness.example.org/w2',
		timestamp: 0,
		logOrigin: 'example.com/log42',
		start: 0,
		end: 5,
		hashHex: '2222222222222222222222222222222222222222222222222222222222222222',
		expectedHex:
			'737562747265652f76310a00'
			+ '167769746e6573732e6578616d706c652e6f72672f7732'
			+ '0000000000000000'
			+ '116578616d706c652e636f6d2f6c6f673432'
			+ '0000000000000000'
			+ '0000000000000005'
			+ '2222222222222222222222222222222222222222222222222222222222222222',
	},
	{
		desc: 'subtree case: non-zero start, timestamp MUST be zero per §"ML-DSA-44 signed message"',
		cosignerName: 'mirror.example.net/m1',
		timestamp: 0,
		logOrigin: 'example.com/log42',
		start: 16,
		end: 32,
		hashHex: '3333333333333333333333333333333333333333333333333333333333333333',
		expectedHex:
			'737562747265652f76310a00'
			+ '156d6972726f722e6578616d706c652e6e65742f6d31'
			+ '0000000000000000'
			+ '116578616d706c652e636f6d2f6c6f673432'
			+ '0000000000000010'
			+ '0000000000000020'
			+ '3333333333333333333333333333333333333333333333333333333333333333',
	},
];
