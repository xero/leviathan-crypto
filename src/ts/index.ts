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
import { serpentInit } from './serpent/index.js';
import { chacha20Init } from './chacha20/index.js';
import { sha2Init } from './sha2/index.js';
import { sha3Init } from './sha3/index.js';
import { keccakInit } from './keccak/index.js';
import { kyberInit } from './kyber/index.js';
import type { Module } from './init.js';
import type { WasmSource } from './wasm-source.js';
import { hasSIMD } from './utils.js';

const _dispatchers: Record<Module, (source: WasmSource) => Promise<void>> = {
	serpent: serpentInit,
	chacha20: chacha20Init,
	sha2: sha2Init,
	sha3: sha3Init,
	keccak: keccakInit,
	kyber: kyberInit,
};

/**
 * Load one or more WASM modules. Each key is a module name; the value is the
 * WasmSource to load it from (embedded blob, URL, ArrayBuffer, etc.).
 *
 * ```ts
 * import { init } from 'leviathan-crypto';
 * import { serpentWasm } from 'leviathan-crypto/serpent/embedded';
 * import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded';
 * await init({ serpent: serpentWasm, sha2: sha2Wasm });
 * ```
 */
export async function init(
	sources: Partial<Record<Module, WasmSource>>,
): Promise<void> {
	const entries = Object.entries(sources) as [string, WasmSource][];
	// SIMD preflight — serpent, chacha20, and kyber modules contain SIMD instructions
	if (('serpent' in sources || 'chacha20' in sources || 'kyber' in sources) && !hasSIMD())
		throw new Error(
			'leviathan-crypto: serpent, chacha20, and kyber require WebAssembly SIMD — '
			+ 'this runtime does not support it',
		);
	for (const [mod, src] of entries) {
		if (!Object.hasOwn(_dispatchers, mod))
			throw new Error(`leviathan-crypto: unknown module "${mod}" — expected one of: ${Object.keys(_dispatchers).join(', ')}`);
		if (src == null)
			throw new TypeError(`leviathan-crypto: source for "${mod}" is null or undefined`);
	}
	await Promise.all(
		(entries as [Module, WasmSource][]).map(([mod, src]) => _dispatchers[mod](src)),
	);
}

export type { Module, WasmSource };
export { isInitialized, _resetForTesting } from './init.js';
export { AuthenticationError } from './errors.js';
export { serpentInit, Serpent, SerpentCtr, SerpentCbc, SerpentCipher, _serpentReady } from './serpent/index.js';
export { chacha20Init, ChaCha20, Poly1305, ChaCha20Poly1305, XChaCha20Poly1305, XChaCha20Cipher, _chachaReady } from './chacha20/index.js';
export { sha2Init, SHA256, SHA512, SHA384, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384, HKDF_SHA256, HKDF_SHA512, _sha2Ready } from './sha2/index.js';
export { sha3Init, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, _sha3Ready } from './sha3/index.js';
export { keccakInit } from './keccak/index.js';
export { kyberInit, MlKem512, MlKem768, MlKem1024, MlKemBase, KyberSuite, _kyberReady } from './kyber/index.js';
export type { KyberKeyPair, KyberEncapsulation, KyberParams } from './kyber/index.js';
export { SealStream, OpenStream, Seal, SealStreamPool, FLAG_FRAMED, TAG_DATA, TAG_FINAL, HEADER_SIZE, CHUNK_MIN, CHUNK_MAX } from './stream/index.js';
export type { CipherSuite, DerivedKeys, SealStreamOpts, PoolOpts } from './stream/index.js';
export { Fortuna } from './fortuna.js';
export type { Hash, KeyedHash, Blockcipher, Streamcipher, AEAD } from './types.js';
export {
	hexToBytes, bytesToHex, utf8ToBytes, bytesToUtf8,
	base64ToBytes, bytesToBase64,
	constantTimeEqual, CT_MAX_BYTES, wipe, xor, concat,
	randomBytes, hasSIMD,
} from './utils.js';
