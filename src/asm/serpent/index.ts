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
// src/asm/serpent/index.ts
//
// Serpent-256 WASM module — public exports.
// Spec: Serpent AES submission, Anderson/Biham/Knudsen 1998.

// ── Buffer layout (buffers.ts) ──────────────────────────────────────────────

export {
	getModuleId,
	getKeyOffset,
	getBlockPtOffset,
	getBlockCtOffset,
	getNonceOffset,
	getCounterOffset,
	getSubkeyOffset,
	getChunkPtOffset,
	getChunkCtOffset,
	getWorkOffset,
	getCbcIvOffset,
	getSimdWorkOffset,
	getChunkSize,
	getMemoryPages,
} from './buffers';

// ── Key schedule + buffer wipe (serpent.ts) ─────────────────────────────────

export { loadKey, wipeBuffers } from './serpent';

// ── Block cipher (serpent_unrolled.ts) ──────────────────────────────────────
// Public exports use the fully-unrolled scalar implementation.

export {
	encryptBlock_unrolled as encryptBlock,
	decryptBlock_unrolled as decryptBlock,
} from './serpent_unrolled';

// ── CTR mode (ctr.ts) ───────────────────────────────────────────────────────

export { resetCounter, encryptChunk, decryptChunk, setCounter } from './ctr';

// ── CBC mode (cbc.ts) ───────────────────────────────────────────────────────

export { cbcEncryptChunk, cbcDecryptChunk } from './cbc';

// ── SIMD block cipher (serpent_simd.ts) ─────────────────────────────────────
// 4-block-parallel encrypt/decrypt over v128 lanes.

export { encryptBlock_simd_4x, decryptBlock_simd_4x } from './serpent_simd';

// ── SIMD CTR mode (ctr_simd.ts) ─────────────────────────────────────────────

export { encryptChunk_simd, decryptChunk_simd } from './ctr_simd';

// ── SIMD CBC decrypt (cbc_simd.ts) ──────────────────────────────────────────
// CBC encrypt stays scalar — sequential dependency is not parallelizable.

export { cbcDecryptChunk_simd } from './cbc_simd';
