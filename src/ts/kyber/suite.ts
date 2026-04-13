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
// src/ts/kyber/suite.ts
//
// KyberSuite — wraps a MlKemBase + inner CipherSuite into a unified CipherSuite.
// Provides hybrid KEM + symmetric AEAD for use with SealStream / OpenStream / Seal.

import type { CipherSuite, DerivedKeys } from '../stream/types.js';
import type { KyberKeyPair, KyberEncapsulation } from './types.js';
import type { KyberParams } from './params.js';
import { concat } from '../utils.js';
import { HKDF_SHA256 } from '../sha2/index.js';

// KEM selector per parameter set (bits 4-5 of formatEnum)
const KEM_NIBBLE: Record<number, number> = {
	2: 0x10,   // ML-KEM-512  (k=2)
	3: 0x20,   // ML-KEM-768  (k=3)
	4: 0x30,   // ML-KEM-1024 (k=4)
};

const KEM_LABEL: Record<number, string> = {
	2: 'mlkem512',
	3: 'mlkem768',
	4: 'mlkem1024',
};

// Structural interface for the KEM object — avoids circular imports with index.ts
export interface MlKemLike {
	readonly params: KyberParams;
	encapsulate(ek: Uint8Array): KyberEncapsulation;
	decapsulate(dk: Uint8Array, c: Uint8Array): Uint8Array;
	keygen(): KyberKeyPair;
}

export function KyberSuite(
	kem: MlKemLike,
	inner: CipherSuite,
): CipherSuite & { keygen(): KyberKeyPair } {
	const p = kem.params;
	const kemNibble = KEM_NIBBLE[p.k];
	if (!kemNibble) throw new Error(`unsupported ML-KEM k=${p.k}`);

	const kemLabel = KEM_LABEL[p.k];
	const infoBytes = new TextEncoder().encode(inner.hkdfInfo);

	return {
		formatEnum: kemNibble | inner.formatEnum,
		formatName: `${kemLabel}+${inner.formatName}`,
		hkdfInfo: inner.hkdfInfo,
		keySize: p.ekBytes,
		decKeySize: p.dkBytes,
		kemCtSize: p.ctBytes,
		tagSize: inner.tagSize,
		padded: inner.padded,
		wasmChunkSize: inner.wasmChunkSize,
		wasmModules: [...inner.wasmModules, 'kyber', 'sha3'],

		deriveKeys(key: Uint8Array, nonce: Uint8Array, kemCt?: Uint8Array): DerivedKeys {
			let sharedSecret: Uint8Array;
			let outKemCt: Uint8Array | undefined;
			let ctForInfo: Uint8Array;

			if (kemCt === undefined) {
				// encrypt path: key = ek — encapsulate to produce shared secret + ct
				const result = kem.encapsulate(key);
				sharedSecret = result.sharedSecret;
				outKemCt = result.ciphertext;
				ctForInfo = outKemCt;
			} else {
				// decrypt path: key = dk — decapsulate to recover shared secret
				sharedSecret = kem.decapsulate(key, kemCt);
				ctForInfo = kemCt;
			}

			// Bind kemCt into HKDF info for defense in depth (KEM ciphertext binding)
			const info = concat(infoBytes, ctForInfo);
			const hkdf = new HKDF_SHA256();
			const derived = hkdf.derive(sharedSecret, nonce, info, inner.keySize);
			hkdf.dispose();
			sharedSecret.fill(0);

			// Delegate actual per-cipher key derivation to the inner suite
			const innerKeys = inner.deriveKeys(derived, nonce);
			derived.fill(0);

			return outKemCt
				? { bytes: innerKeys.bytes, kemCiphertext: outKemCt }
				: innerKeys;
		},

		sealChunk: inner.sealChunk.bind(inner),
		openChunk: inner.openChunk.bind(inner),
		wipeKeys: inner.wipeKeys.bind(inner),
		createPoolWorker: inner.createPoolWorker.bind(inner),

		keygen(): KyberKeyPair {
			return kem.keygen();
		},
	};
}
