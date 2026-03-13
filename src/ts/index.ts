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
// Root barrel — re-exports everything
import { init as _initSerpent } from './serpent/index.js';
import { init as _initChacha } from './chacha20/index.js';
import { init as _initSha2 } from './sha2/index.js';
import { init as _initSha3 } from './sha3/index.js';
import type { Module, Mode, InitOpts } from './init.js';

const _dispatchers: Record<string, (mode: Mode, opts?: InitOpts) => Promise<void>> = {
	serpent: (mode, opts) => _initSerpent(mode, opts),
	chacha20: (mode, opts) => _initChacha(mode, opts),
	sha2: (mode, opts) => _initSha2(mode, opts),
	sha3: (mode, opts) => _initSha3(mode, opts),
};

export async function init(
	modules: Module | Module[],
	mode: Mode = 'embedded',
	opts?: InitOpts,
): Promise<void> {
	const list = Array.isArray(modules) ? modules : [modules];
	await Promise.all(list.map(mod => _dispatchers[mod](mode, opts)));
}

export { type Module, type Mode, type InitOpts, isInitialized, _resetForTesting } from './init.js';
export { SerpentSeal, Serpent, SerpentCtr, SerpentCbc, SerpentStream, SerpentStreamPool, _serpentReady } from './serpent/index.js';
export type { StreamPoolOpts } from './serpent/index.js';
export { ChaCha20, Poly1305, ChaCha20Poly1305, XChaCha20Poly1305, _chachaReady } from './chacha20/index.js';
export { XChaCha20Poly1305Pool } from './chacha20/pool.js';
export type { PoolOpts } from './chacha20/pool.js';
export { SHA256, SHA512, SHA384, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384, HKDF_SHA256, HKDF_SHA512, _sha2Ready } from './sha2/index.js';
export { SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, _sha3Ready } from './sha3/index.js';
export { Fortuna } from './fortuna.js';
export type { Hash, KeyedHash, Blockcipher, Streamcipher, AEAD } from './types.js';
export {
	hexToBytes, bytesToHex, utf8ToBytes, bytesToUtf8,
	base64ToBytes, bytesToBase64,
	constantTimeEqual, wipe, xor, concat,
	randomBytes,
} from './utils.js';
