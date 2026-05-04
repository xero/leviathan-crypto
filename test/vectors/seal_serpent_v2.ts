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
// Seal Serpent v2 KAT vectors — single-chunk STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// Serpent v2 wire format: 20-byte header preamble. HMAC-SHA-256 chunk
// authentication is collision-resistant under SHA-256, which is
// key-committing — no separate commitment is needed in the preamble.
// Generated with fixed nonce seams, then independently verified against
// the underlying primitives (HKDF-SHA-256, SerpentCbc, HMAC-SHA-256).
// Vectors serve as regression trip-wires for Seal wire format stability.
// Audit status: SELF-VERIFIED

export interface SealSerpentV2Vector {
	description: string;
	key: string;          // hex, 32 bytes
	nonce: string;        // hex, 16 bytes
	plaintext: string;    // hex
	preamble: string;     // hex, 20 bytes
	blob: string;         // hex, full output = preamble || ciphertext
}

export const sc1: SealSerpentV2Vector = {
	description: 'SC1: serpent v2, 0x03 key, 0xcc nonce, 100-byte 0xef plaintext',
	key: '0303030303030303030303030303030303030303030303030303030303030303',
	nonce: 'cccccccccccccccccccccccccccccccc',
	plaintext:
		'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef' +
		'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef' +
		'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef' +
		'efefefef',
	preamble: '02cccccccccccccccccccccccccccccccc000400',
	blob:
		'02cccccccccccccccccccccccccccccccc000400b7eacee372c0e05bac76d340' +
		'a0fa79577158328eb6f909f849541de426686bbda6b1ab8eeaa00017064ed74c' +
		'bcb7c70aa9943dc667c7a060547fc805881b1a2c8e1b10ce70d31f588f880200' +
		'168d13872252a9e30d1872e27ea621034d61ba50f61e74557190ed9347995f0a' +
		'5731e9e0822351bf3cc2f1c5b826bfb6fb6a35dae23e2189cda3d47cf9cb40c5' +
		'a2f5a2f0',
};

export const sc_empty: SealSerpentV2Vector = {
	description: 'SC_EMPTY: serpent v2, 0x04 key, 0xdd nonce, empty plaintext',
	key: '0404040404040404040404040404040404040404040404040404040404040404',
	nonce: 'dddddddddddddddddddddddddddddddd',
	plaintext: '',
	preamble: '02dddddddddddddddddddddddddddddddd000400',
	blob:
		'02dddddddddddddddddddddddddddddddd0004007cc89fd0461f7e2636873fdc' +
		'c3715bd04660ace21966d10008e1ecd1b9635e65f77569c501833b88c00186a6' +
		'fe6b913e',
};
