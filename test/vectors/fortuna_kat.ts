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
// test/vectors/fortuna_kat.ts
//
// Fortuna pluggable-primitive KAT vectors.
//
// SELF-GENERATED — no external authority for these wire formats. Generated with
// a deterministic entropy seed and msPerReseed: 0, then independently verified
// against the underlying primitives. Vectors serve as regression trip-wires for
// Fortuna's pluggable-primitive output stability.
// Audit status: SELF-VERIFIED

export interface FortunaVector {
	description: string;
	generator: 'serpent' | 'chacha20';
	hash: 'sha2' | 'sha3';
	entropySeed: string;        // hex, 64 bytes of repeated byte pattern
	genKeyAfterCreate: string;  // hex, length matches generator.keySize
	firstGet32: string;         // hex, 32 bytes from get(32) after create
}

export const serpent_sha2: FortunaVector = {
	description: 'Serpent + SHA-256',
	generator: 'serpent',
	hash: 'sha2',
	entropySeed: '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101',
	genKeyAfterCreate: '92062855ee9c299bcf85e5fb5e1b9c7c828567756fff64b81b845efd46e2a9ba',
	firstGet32: 'a830695a25abc4523fa43aa2c0d6681dbb56bcca9ceec4f264017c9a1891c1c0',
};

export const serpent_sha3: FortunaVector = {
	description: 'Serpent + SHA3-256',
	generator: 'serpent',
	hash: 'sha3',
	entropySeed: '02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202',
	genKeyAfterCreate: '211aa22e9c1eae8219397742a56058ba82f3651db9cf3c210c9a5c1bc6db133f',
	firstGet32: '70576e8f709e062f3d965074cfadd8092fd3345d036eaf2aabc2986dc89247ea',
};

export const chacha20_sha2: FortunaVector = {
	description: 'ChaCha20 + SHA-256',
	generator: 'chacha20',
	hash: 'sha2',
	entropySeed: '03030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303',
	genKeyAfterCreate: 'b3a2d8b44963d79d90c40808c5f2766a0d0efc65dd77ae7eb6d4d2b64cf55f9e',
	firstGet32: '0e0d6af7703d0a172c159501e39c83f1d647a8017b32bb4059ad64292ca00388',
};

export const chacha20_sha3: FortunaVector = {
	description: 'ChaCha20 + SHA3-256',
	generator: 'chacha20',
	hash: 'sha3',
	entropySeed: '04040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404',
	genKeyAfterCreate: '2d46c3c12b37a0372f31c4f19b9d6fbe6101ab1d3c0660aa600e1329f4ce54db',
	firstGet32: '5dbe8838baaf83cd87a58dd65f8ea322bba6a0f602d202550633025172f47d33',
};
