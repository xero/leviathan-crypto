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
// Root barrel, re-exports everything
import { serpentInit } from './serpent/index.js';
import { chacha20Init } from './chacha20/index.js';
import { sha2Init } from './sha2/index.js';
import { sha3Init } from './sha3/index.js';
import { keccakInit } from './keccak/index.js';
import { kyberInit } from './kyber/index.js';
import { aesInit } from './aes/index.js';
import { mldsaInit } from './mldsa/index.js';
import { slhdsaInit } from './slhdsa/index.js';
import { blake3Init } from './blake3/index.js';
import { ecdsaP256Init } from './ecdsa/index.js';
import { initModule } from './init.js';
import type { Module } from './init.js';
import type { WasmSource } from './wasm-source.js';
import { hasSIMD } from './utils.js';

// curve25519 is the underlying module shared by ed25519 + x25519. Users
// initialise it via the per-primitive aliases (`init({ ed25519: ... })`
// or `init({ x25519: ... })`); the alias keys resolve here. The 'curve25519'
// key is accepted as well for symmetry with the Module type union, but the
// public docs route consumers to the per-primitive surface.
const _dispatchers: Record<Module, (source: WasmSource) => Promise<void>> = {
	serpent: serpentInit,
	chacha20: chacha20Init,
	sha2: sha2Init,
	sha3: sha3Init,
	keccak: keccakInit,
	kyber: kyberInit,
	aes: aesInit,
	mldsa: mldsaInit,
	slhdsa: slhdsaInit,
	blake3: blake3Init,
	curve25519: (source: WasmSource) => initModule('curve25519', source),
	p256: ecdsaP256Init,
};

/**
 * Top-level init() input. Accepts the canonical module keys plus the
 * `ed25519` and `x25519` aliases; both aliases resolve to the underlying
 * `curve25519` WASM module and are de-duped if given identical sources.
 */
export type InitInput = Partial<Record<Module | 'ed25519' | 'x25519', WasmSource>>;

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
 *
 * `ed25519` and `x25519` are aliases for the underlying `curve25519`
 * module. `init({ ed25519: src })` and `init({ x25519: src })` both work,
 * and `init({ ed25519: src, x25519: src })` is accepted (single underlying
 * init). Two different sources for the same underlying module is rejected.
 */
export async function init(sources: InitInput): Promise<void> {
	const entries = Object.entries(sources) as [string, WasmSource][];
	const resolved = new Map<Module, WasmSource>();
	for (const [key, src] of entries) {
		if (src == null)
			throw new TypeError(`leviathan-crypto: source for "${key}" is null or undefined`);
		const target: Module = (key === 'ed25519' || key === 'x25519') ? 'curve25519' : key as Module;
		if (!Object.hasOwn(_dispatchers, target))
			throw new Error(
				`leviathan-crypto: unknown module "${key}", expected one of: `
				+ `${Object.keys(_dispatchers).join(', ')}, ed25519, x25519`,
			);
		const prior = resolved.get(target);
		if (prior !== undefined) {
			if (prior !== src)
				throw new Error(
					'leviathan-crypto: init() called with different sources for "ed25519" and "x25519" '
					+ '(both alias to curve25519, sources must be identical)',
				);
			continue;
		}
		resolved.set(target, src);
	}
	// SIMD preflight: serpent, chacha20, kyber, aes, mldsa, and blake3 contain SIMD instructions.
	// curve25519 ships scalar (simd:false in scripts/lib/modules.ts), and is excluded here.
	if (
		(resolved.has('serpent') || resolved.has('chacha20') || resolved.has('kyber')
			|| resolved.has('aes') || resolved.has('mldsa') || resolved.has('blake3'))
		&& !hasSIMD()
	)
		throw new Error(
			'leviathan-crypto: serpent, chacha20, kyber, aes, mldsa, and blake3 require WebAssembly SIMD, '
			+ 'this runtime does not support it',
		);
	await Promise.all(
		Array.from(resolved.entries()).map(([mod, src]) => _dispatchers[mod](src)),
	);
}

export type { Module, WasmSource };
export { isInitialized } from './init.js';
export { AuthenticationError, SigningError, KeyAgreementError } from './errors.js';
export { serpentInit, Serpent, SerpentCtr, SerpentCbc, SerpentCipher, SerpentGenerator } from './serpent/index.js';
export { chacha20Init, ChaCha20, Poly1305, ChaCha20Poly1305, XChaCha20Poly1305, XChaCha20Cipher, ChaCha20Generator } from './chacha20/index.js';
export { sha2Init, SHA256, SHA224, SHA384, SHA512, SHA512_224, SHA512_256, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384, HKDF_SHA256, HKDF_SHA512, SHA256Hash } from './sha2/index.js';
export { sha3Init, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA3_256Stream, SHA3_512Stream, SHAKE128, SHAKE256, SHAKE128Stream, SHAKE256Stream, SHA3_256Hash, CSHAKE128, CSHAKE256, KMAC128, KMAC256, KMACXOF128, KMACXOF256 } from './sha3/index.js';
export { keccakInit } from './keccak/index.js';
export { kyberInit, MlKem512, MlKem768, MlKem1024, MlKemBase, KyberSuite } from './kyber/index.js';
export { aesInit, AES, AESCbc, AESCtr, AESGCM, AESGCMSIV, AESGenerator, AESGCMSIVCipher } from './aes/index.js';
export { mldsaInit, MlDsa44, MlDsa65, MlDsa87, MlDsaBase, MLDSA44, MLDSA65, MLDSA87 } from './mldsa/index.js';
export {
	slhdsaInit, SlhDsaBase,
	SlhDsa128f, SlhDsa192f, SlhDsa256f,
	SLHDSA128F, SLHDSA192F, SLHDSA256F,
} from './slhdsa/index.js';
export {
	blake3Init,
	BLAKE3, BLAKE3KeyedHash, BLAKE3DeriveKey,
	BLAKE3Stream, BLAKE3KeyedHashStream, BLAKE3DeriveKeyStream,
	BLAKE3OutputReader,
	BLAKE3Hash,
} from './blake3/index.js';
export { ecdsaP256Init, EcdsaP256 } from './ecdsa/index.js';
export type { EcdsaP256KeyPair } from './ecdsa/index.js';
export { ecdsaSignatureToDer, ecdsaSignatureFromDer } from './ecdsa/der.js';
export { ed25519Init, Ed25519 } from './ed25519/index.js';
export type { Ed25519KeyPair } from './ed25519/index.js';
export { x25519Init, X25519 } from './x25519/index.js';
export type { X25519KeyPair } from './x25519/index.js';
export type { KyberKeyPair, KyberEncapsulation, KyberParams } from './kyber/index.js';
export type { MlDsaKeyPair, MlDsaParams, PreHashAlgorithm } from './mldsa/index.js';
export type { SlhDsaKeyPair, SlhDsaParams } from './slhdsa/index.js';
export { SealStream, OpenStream, Seal, SealStreamPool, FLAG_FRAMED, TAG_DATA, TAG_FINAL, HEADER_SIZE, CHUNK_MIN, CHUNK_MAX } from './stream/index.js';
export type { CipherSuite, DerivedKeys, SealStreamOpts, PoolOpts } from './stream/index.js';
export { Sign, SignStream, VerifyStream } from './sign/index.js';
export type {
	SignatureSuite,
	StreamableSignatureSuite,
	PrehashAlgorithm,
} from './sign/index.js';
export {
	Ed25519Suite, Ed25519PreHashSuite,
	EcdsaP256Suite,
	MlDsa44Suite, MlDsa65Suite, MlDsa87Suite,
	MlDsa44PreHashSuite, MlDsa65PreHashSuite, MlDsa87PreHashSuite,
	SlhDsa128fSuite, SlhDsa192fSuite, SlhDsa256fSuite,
	SlhDsa128fPreHashSuite, SlhDsa192fPreHashSuite, SlhDsa256fPreHashSuite,
	MlDsa44SlhDsa128fSuite, MlDsa65SlhDsa192fSuite, MlDsa87SlhDsa256fSuite,
} from './sign/index.js';
export { Fortuna } from './fortuna.js';
export type { Hash, KeyedHash, Blockcipher, Streamcipher, AEAD, Generator, HashFn } from './types.js';
export {
	KDFChain,
	ratchetInit,
	kemRatchetEncap,
	kemRatchetDecap,
	ratchetReady,
	SkippedKeyStore,
	RatchetKeypair,
} from './ratchet/index.js';
export type {
	RatchetInitResult,
	KemEncapResult,
	KemDecapResult,
	MlKemLike,
	RatchetMessageHeader,
	ResolveHandle,
	SkippedKeyStoreOpts,
} from './ratchet/index.js';
export {
	hexToBytes, bytesToHex, utf8ToBytes, bytesToUtf8,
	base64ToBytes, bytesToBase64,
	constantTimeEqual, CT_MAX_BYTES, wipe, xor, concat,
	randomBytes, hasSIMD,
} from './utils.js';
