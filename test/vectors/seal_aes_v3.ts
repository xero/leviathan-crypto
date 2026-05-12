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
// Seal AES-GCM-SIV v3 KAT vectors, single-chunk STREAM construction.
//
// SELF-GENERATED, no external authority for these wire formats.
// AES-GCM-SIV v3 wire format: 20-byte header + 32-byte key commitment in
// the preamble (52 bytes total). HKDF info string is
// 'aes-gcm-siv-sealstream-v3' concatenated with the 20-byte header,
// binding formatEnum, framed flag, nonce, and chunkSize into the derived
// material. Generated with fixed nonce seams, then independently verified
// against the underlying primitives (HKDF-SHA-256 and the raw AES-GCM-SIV
// WASM ops in src/ts/aes/ops.ts).
// Vectors serve as regression trip-wires for Seal wire format stability.
// Audit status: SELF-VERIFIED

export interface SealAesV3Vector {
	description: string;
	key: string;          // hex, 32 bytes
	nonce: string;        // hex, 16 bytes
	plaintext: string;    // hex
	preamble: string;     // hex, 52 bytes (20 header + 32 commitment)
	blob: string;         // hex, full output = preamble || ciphertext
}

export const ac1: SealAesV3Vector = {
	description: 'AC1: aes-gcm-siv v3, 0x05 key, 0xee nonce, 100-byte 0x12 plaintext',
	key: '0505050505050505050505050505050505050505050505050505050505050505',
	nonce: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
	plaintext:
		'1212121212121212121212121212121212121212121212121212121212121212' +
		'1212121212121212121212121212121212121212121212121212121212121212' +
		'1212121212121212121212121212121212121212121212121212121212121212' +
		'12121212',
	preamble:
		'04eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0004000575e685510a1047d9acec08' +
		'b2d1e9f3e785e2bf5e2a70c49eacb5ca00c43d0e',
	blob:
		'04eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0004000575e685510a1047d9acec08' +
		'b2d1e9f3e785e2bf5e2a70c49eacb5ca00c43d0edfcf9a4fda806357488a01f7' +
		'f8ebcf91e1e89be2fe4776077b104a8e6febf61f0fedc1bc9e81eca6b40c7364' +
		'9701e4d055528bd4fca33af92aaa64d22e46abd2724da64c01553e9d9f59b19e' +
		'039aa8f68f563dfa8d89c8b26b8fde122655a507e2b0d30c2b86aa1b40a6d74a' +
		'8d8516c59a32d9a3',
};

export const ac_empty: SealAesV3Vector = {
	description: 'AC_EMPTY: aes-gcm-siv v3, 0x06 key, 0x99 nonce, empty plaintext',
	key: '0606060606060606060606060606060606060606060606060606060606060606',
	nonce: '99999999999999999999999999999999',
	plaintext: '',
	preamble:
		'0499999999999999999999999999999999000400ec71c25aaba3adae03a7d335' +
		'15a44a258f6b63213e990f36ebad72ee58e2f197',
	blob:
		'0499999999999999999999999999999999000400ec71c25aaba3adae03a7d335' +
		'15a44a258f6b63213e990f36ebad72ee58e2f1971cc75775a71f68a1446a32bc' +
		'f4f5e547',
};
