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
// Seal v2 KAT vectors — single-chunk STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// Generated with fixed nonce seams, then independently verified
// against the underlying primitives (HKDF-SHA-256, HChaCha20,
// ChaCha20-Poly1305, SerpentCbc, HMAC-SHA-256).
// Vectors serve as regression trip-wires for Seal wire format stability.
// Audit status: SELF-VERIFIED

export interface SealV2Vector {
	description: string;
	cipher: 'xchacha20' | 'serpent';
	key: string;         // hex
	nonce: string;       // hex, 16 bytes
	plaintext: string;   // hex
	preamble: string;    // hex, always 20 bytes for symmetric
	blob: string;        // hex, full output = preamble || ciphertext
}

export const xc1: SealV2Vector = {
	description: 'XC1: xchacha20, 0x01 key, 0xaa nonce, 100-byte 0xcd plaintext',
	cipher: 'xchacha20',
	key: '0101010101010101010101010101010101010101010101010101010101010101',
	nonce: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
	plaintext:
		'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
		'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
		'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
		'cdcdcdcd',
	preamble: '01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000400',
	blob:
		'01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000400f1bb75999695c450a541ce55' +
		'8fab1fdeffbcae49a55ef2d7243f419f17f9787c6a4652f0f8584fdd27d7018e' +
		'2eff08290c0dd45a3638309d4b140324ee2d67198bbbbf0db469919cb088fdd4' +
		'3258bdc9bcddd8e594aff93295ccabed09f2b9183b47d5a9cbf2c06a73bc75f8' +
		'c8e61709dd765f2d',
};

export const xc_empty: SealV2Vector = {
	description: 'XC_EMPTY: xchacha20, 0x02 key, 0xbb nonce, empty plaintext',
	cipher: 'xchacha20',
	key: '0202020202020202020202020202020202020202020202020202020202020202',
	nonce: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
	plaintext: '',
	preamble: '01bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000400',
	blob:
		'01bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00040078a13a924a9524de425f4052' +
		'0bc1704f',
};

export const sc1: SealV2Vector = {
	description: 'SC1: serpent, 0x03 key, 0xcc nonce, 100-byte 0xef plaintext',
	cipher: 'serpent',
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

export const sc_empty: SealV2Vector = {
	description: 'SC_EMPTY: serpent, 0x04 key, 0xdd nonce, empty plaintext',
	cipher: 'serpent',
	key: '0404040404040404040404040404040404040404040404040404040404040404',
	nonce: 'dddddddddddddddddddddddddddddddd',
	plaintext: '',
	preamble: '02dddddddddddddddddddddddddddddddd000400',
	blob:
		'02dddddddddddddddddddddddddddddddd0004007cc89fd0461f7e2636873fdc' +
		'c3715bd04660ace21966d10008e1ecd1b9635e65f77569c501833b88c00186a6' +
		'fe6b913e',
};
