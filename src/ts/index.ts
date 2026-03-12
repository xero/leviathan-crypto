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
import { init as _initArgon } from './argon2id.js';
import type { Module, Mode, InitOpts } from './init.js';

const _dispatchers: Record<string, (mode: Mode, opts?: InitOpts) => Promise<void>> = {
	serpent: (mode, opts) => _initSerpent(mode, opts),
	chacha20: (mode, opts) => _initChacha(mode, opts),
	sha2: (mode, opts) => _initSha2(mode, opts),
	sha3: (mode, opts) => _initSha3(mode, opts),
};

export async function init(
	modules: (Module | 'argon2id') | (Module | 'argon2id')[],
	mode: Mode = 'embedded',
	opts?: InitOpts,
): Promise<void> {
	const list = Array.isArray(modules) ? modules : [modules];
	await Promise.all(list.map(mod => {
		if (mod === 'argon2id') {
			if (mode === 'streaming')
				throw new Error('leviathan-crypto: argon2id does not support streaming mode');
			return _initArgon(mode as 'embedded' | 'manual');
		}
		return _dispatchers[mod](mode, opts);
	}));
}

export { type Module, type Mode, type InitOpts, _resetForTesting } from './init.js';
export { SerpentSeal, Serpent, SerpentCtr, SerpentCbc, _serpentReady } from './serpent/index.js';
export { ChaCha20, Poly1305, ChaCha20Poly1305, XChaCha20Poly1305, _chachaReady } from './chacha20/index.js';
export { XChaCha20Poly1305Pool } from './chacha20/pool.js';
export type { PoolOpts } from './chacha20/pool.js';
export { SHA256, SHA512, SHA384, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384, _sha2Ready } from './sha2/index.js';
export { SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, _sha3Ready } from './sha3/index.js';
export { Fortuna } from './fortuna.js';
export {
	Argon2id,
	isArgon2idInitialized,
	ARGON2ID_INTERACTIVE,
	ARGON2ID_SENSITIVE,
	ARGON2ID_DERIVE,
} from './argon2id.js';
export type { Argon2idParams, Argon2idResult, ArgonOpts } from './argon2id.js';
export type { Hash, KeyedHash, Blockcipher, Streamcipher, AEAD } from './types.js';
export {
	hexToBytes, bytesToHex, utf8ToBytes, bytesToUtf8,
	base64ToBytes, bytesToBase64,
	constantTimeEqual, wipe, xor, concat,
	randomBytes,
} from './utils.js';
