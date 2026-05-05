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
// src/asm/aes/index.ts
//
// AES WASM module — public exports.
// Supports AES-128/192/256 encrypt + decrypt; raw block cipher only.

// ── Buffer layout (buffers.ts) ──────────────────────────────────────────────

export {
	getModuleId,
	getKeyOffset,
	getBlockPtOffset,
	getBlockCtOffset,
	getBlockPt8xOffset,
	getBlockCt8xOffset,
	getRoundKeysOffset,
	getBitslicedStateOffset,
	getCanrightScratchOffset,
	getKeyScheduleScratchOffset,
	getInvRoundKeysOffset,
	getChunkPtOffset,
	getChunkCtOffset,
	getChunkSize,
	getNrOffset,
	getMemoryPages,
} from './buffers'

// ── AES encrypt + decrypt (aes.ts) ─────────────────────────────────────────

export {
	loadKey,
	encryptBlock,
	encryptBlock_8x,
	decryptBlock,
	decryptBlock_8x,
	// Debug-only exports used by gate tests.
	transposeRoundTrip,
	sboxRoundTrip,
	singleRound,
} from './aes'

// ── Buffer wipe (wipe.ts) ───────────────────────────────────────────────────

export { wipeBuffers } from './wipe'
