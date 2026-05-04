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
// Seal XChaCha20 v3 KAT vectors — single-chunk STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// XChaCha20 v3 wire format: 20-byte header + 32-byte key commitment in the
// preamble (52 bytes total). HKDF info string is 'xchacha20-sealstream-v3'
// concatenated with the 20-byte header, binding formatEnum, framed flag,
// nonce, and chunkSize into the derived material. Generated with fixed
// nonce seams, then independently verified against the underlying
// primitives (HKDF-SHA-256, HChaCha20, ChaCha20-Poly1305).
// Vectors serve as regression trip-wires for Seal wire format stability.
// Audit status: SELF-VERIFIED

export interface SealXChachaV3Vector {
	description: string;
	key: string;          // hex, 32 bytes
	nonce: string;        // hex, 16 bytes
	plaintext: string;    // hex
	preamble: string;     // hex, 52 bytes (20 header + 32 commitment)
	blob: string;         // hex, full output = preamble || ciphertext
}

export const xc1: SealXChachaV3Vector = {
	description: 'XC1: xchacha20 v3, 0x01 key, 0xaa nonce, 100-byte 0xcd plaintext',
	key: '0101010101010101010101010101010101010101010101010101010101010101',
	nonce: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
	plaintext:
		'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
		'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
		'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
		'cdcdcdcd',
	preamble:
		'03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000400f7e6aeaa08d2cf483e3ff37f' +
		'18db9a7f52f9cf59ff871729c8d6f0ebb730a9e2',
	blob:
		'03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000400f7e6aeaa08d2cf483e3ff37f' +
		'18db9a7f52f9cf59ff871729c8d6f0ebb730a9e2de538b9bc04f5dd3a203a1f5' +
		'33a96239c8234806f79ff3a80203f755d51c96d4ea4c57b8c90a73d2ded3540d' +
		'0171d2b4b064edfeec9b679c315db718b87171f90e4cd7bc78f4892218436e82' +
		'a982a4be0955af34de5db2fcb458817eaa703710ee40108c69413ca67ef77b11' +
		'e553afad3ce7c577',
};

export const xc_empty: SealXChachaV3Vector = {
	description: 'XC_EMPTY: xchacha20 v3, 0x02 key, 0xbb nonce, empty plaintext',
	key: '0202020202020202020202020202020202020202020202020202020202020202',
	nonce: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
	plaintext: '',
	preamble:
		'03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000400e206c0814c7d259f1cc01e5c' +
		'13821cfafe34e7b3a721b11ef39b75c1ddbdcd78',
	blob:
		'03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000400e206c0814c7d259f1cc01e5c' +
		'13821cfafe34e7b3a721b11ef39b75c1ddbdcd78b7e56d5fb51d2380635ca18b' +
		'0b503dee',
};
