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
// Seal Serpent v2 KAT vectors, single-chunk STREAM construction.
//
// SELF-GENERATED, no external authority for these wire formats.
// Serpent v3 wire format: 20-byte header preamble. HMAC-SHA-256 chunk
// authentication is collision-resistant under SHA-256, which is
// key-committing, no separate commitment is needed in the preamble.
// Generated with fixed nonce seams, then independently verified against
// the underlying primitives (HKDF-SHA-256, SerpentCbc, HMAC-SHA-256).
// Vectors serve as regression trip-wires for Seal wire format stability.
// Audit status: SELF-VERIFIED

export interface SealSerpentV3Vector {
	description: string;
	key: string;          // hex, 32 bytes
	nonce: string;        // hex, 16 bytes
	plaintext: string;    // hex
	preamble: string;     // hex, 20 bytes
	blob: string;         // hex, full output = preamble || ciphertext
}

export const sc1: SealSerpentV3Vector = {
	description: 'SC1: serpent v3, 0x03 key, 0xcc nonce, 100-byte 0xef plaintext',
	key: '0303030303030303030303030303030303030303030303030303030303030303',
	nonce: 'cccccccccccccccccccccccccccccccc',
	plaintext:
		'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef' +
		'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef' +
		'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef' +
		'efefefef',
	preamble: '02cccccccccccccccccccccccccccccccc000400',
	blob:
		'02cccccccccccccccccccccccccccccccc000400e9d72ac4702bde527bd114a5' +
		'd6e5834609658c752ae428c445e6bff118725de0690a8d962d0f6c26ab476b05' +
		'135faca25b60d092736860cdd4467f44fee96b26e4235b441854c851775cc7c2' +
		'72e6921221ead5677048055c6937a471e4fe4cddfeccdb4160292ced6c1b96f3' +
		'39c25369bf62e7715873ebc2c7f64b508054b3b1142eb2f8fecd7731da907ce8' +
		'8d31b828',
};

export const sc_empty: SealSerpentV3Vector = {
	description: 'SC_EMPTY: serpent v3, 0x04 key, 0xdd nonce, empty plaintext',
	key: '0404040404040404040404040404040404040404040404040404040404040404',
	nonce: 'dddddddddddddddddddddddddddddddd',
	plaintext: '',
	preamble: '02dddddddddddddddddddddddddddddddd000400',
	blob:
		'02dddddddddddddddddddddddddddddddd00040022b1c17266f62c2e1ffda917' +
		'd865561ce6097d6632cbbff386f48f5bc82d260eae7122dd9784a8194e5d5f4a' +
		'abc3a6cd',
};
